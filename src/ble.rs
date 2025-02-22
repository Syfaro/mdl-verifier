use std::time::Duration;

use btleplug::{
    api::{Central as _, CentralEvent, Manager as _, Peripheral as _, ScanFilter},
    platform::{Adapter, Manager},
};
use eyre::OptionExt;
use isomdl::{
    definitions::{
        DeviceEngagement,
        device_request::{DataElements, Namespaces},
        helpers::{NonEmptyMap, Tag24},
        session::Handover,
        x509::trust_anchor::{PemTrustAnchor, TrustAnchorRegistry, TrustPurpose},
    },
    presentation::{authentication::ResponseAuthenticationOutcome, reader::SessionManager},
};
use tokio_stream::StreamExt;
use tracing::{debug, error, trace, warn};
use uuid::{Uuid, uuid};

const STATE_ID: Uuid = uuid!("00000001-A123-48CE-896B-4C76973373E6");
const CLIENT2SERVER_ID: Uuid = uuid!("00000002-A123-48CE-896B-4C76973373E6");
const SERVER2CLIENT_ID: Uuid = uuid!("00000003-A123-48CE-896B-4C76973373E6");

/// Maximum length of data to read from a peripheral before aborting.
const MAX_PAYLOAD_SIZE: usize = 512 * 1000;

pub async fn attempt_connections<S>(
    certificates: Vec<String>,
    mut stream: S,
) -> eyre::Result<tokio::sync::mpsc::Receiver<super::VerifierEvent>>
where
    S: futures::Stream<Item = eyre::Result<(Uuid, Tag24<DeviceEngagement>, Handover)>>
        + Unpin
        + Send
        + Sync
        + 'static,
{
    let manager = Manager::new().await?;
    let mut adapters = manager.adapters().await?;
    let central = adapters.pop().ok_or_eyre("missing ble adapter")?;

    let (tx, rx) = tokio::sync::mpsc::channel(1);

    let certs: Vec<_> = certificates
        .into_iter()
        .map(|cert| PemTrustAnchor {
            purpose: TrustPurpose::Iaca,
            certificate_pem: cert,
        })
        .collect();

    let trust_anchors = TrustAnchorRegistry::from_pem_certificates(certs)
        .map_err(|err| eyre::eyre!(Box::new(err)))?;

    tokio::spawn(async move {
        let requested_elements = Namespaces::new(
            "org.iso.18013.5.1".into(),
            DataElements::new("age_over_21".to_string(), false),
        );

        while let Ok(Some((service_uuid, device_engagement, handover))) = stream.try_next().await {
            match tokio::time::timeout(
                Duration::from_secs(30),
                attempt_exchange(
                    &central,
                    requested_elements.clone(),
                    trust_anchors.clone(),
                    service_uuid,
                    device_engagement,
                    handover,
                ),
            )
            .await
            {
                Ok(Ok(outcome)) => tx
                    .send(crate::VerifierEvent::Verified(outcome))
                    .await
                    .unwrap(),
                Ok(Err(err)) => error!("error getting authentication outcome: {err}"),
                Err(_) => warn!("timed out while waiting for doc"),
            }
        }
    });

    Ok(rx)
}

async fn attempt_exchange(
    central: &Adapter,
    requested_elements: NonEmptyMap<String, NonEmptyMap<String, bool>>,
    trust_anchors: TrustAnchorRegistry,
    service_uuid: Uuid,
    device_engagement: Tag24<DeviceEngagement>,
    handover: Handover,
) -> eyre::Result<ResponseAuthenticationOutcome> {
    trace!("got device_engagement: {device_engagement:?}");

    let (mut reader_sm, session_request, _ble_ident) =
        SessionManager::establish_session_with_handover(
            device_engagement,
            requested_elements,
            trust_anchors,
            handover,
        )
        .map_err(|err| eyre::eyre!(Box::new(err)))?;

    let mut events = central.events().await?;

    central
        .start_scan(ScanFilter {
            services: vec![service_uuid],
        })
        .await?;
    debug!(service_uuid = %service_uuid, "starting scan for service");

    let peripheral_id = loop {
        match events.next().await {
            Some(CentralEvent::DeviceDiscovered(id)) => {
                debug!(%id, "got peripheral, stopping scan");
                break id;
            }
            Some(event) => {
                trace!("got other ble event: {event:?}");
            }
            None => {
                eyre::bail!("end of events without discovering device");
            }
        }
    };

    central.stop_scan().await?;

    let peripheral = central.peripheral(&peripheral_id).await?;
    peripheral.connect().await?;
    peripheral.discover_services().await?;
    trace!("discovered services");

    let characteristics: Vec<_> = peripheral
        .characteristics()
        .into_iter()
        .filter(|c| c.service_uuid == service_uuid)
        .collect();

    let Some(state) = characteristics.iter().find(|c| c.uuid == STATE_ID) else {
        eyre::bail!("missing state characteristic");
    };

    let Some(client2server) = characteristics.iter().find(|c| c.uuid == CLIENT2SERVER_ID) else {
        eyre::bail!("missing c2s characteristic");
    };

    let Some(server2client) = characteristics.iter().find(|c| c.uuid == SERVER2CLIENT_ID) else {
        eyre::bail!("missing s2c characteristic");
    };

    peripheral.subscribe(state).await?;
    peripheral.subscribe(server2client).await?;
    trace!("subscribed to characteristics");

    peripheral
        .write(state, &[0x01], btleplug::api::WriteType::WithoutResponse)
        .await?;
    trace!("wrote start");

    // TODO: figure out the real MTU, but for now our requests are small
    // enough this isn't a huge performance issue.
    let mtu = 20;

    // We can fit up to the usable MTU minus one byte, because we need that
    // byte to indicate if more messages are needed to fit all of the data.
    let mut it = session_request.chunks(mtu - 1).peekable();
    // Buffer for holding the message data.
    let mut buf = Vec::with_capacity(mtu);

    while let Some(chunk) = it.next() {
        buf.clear();

        // Until data fits, prepend 1 to data to signal incomplete message.
        if it.peek().is_some() {
            trace!("writing incomplete packet");
            buf.push(1);
        } else {
            trace!("writing last packet");
            buf.push(0);
        }

        buf.extend_from_slice(chunk);

        peripheral
            .write(
                client2server,
                &buf,
                btleplug::api::WriteType::WithoutResponse,
            )
            .await?;

        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    let mut notifs = peripheral.notifications().await?;
    trace!("starting peripheral notifications");

    let mut response: Vec<u8> = Vec::new();

    while let Some(data) = notifs.next().await {
        if response.len() + data.value.len() > MAX_PAYLOAD_SIZE {
            eyre::bail!("response payload is too large");
        }

        let Some(first) = data.value.first().copied() else {
            eyre::bail!("value notification did not have any bytes");
        };

        if data.value.len() > 1 {
            trace!(
                first,
                "extending response with {} bytes",
                data.value.len() - 1
            );
            response.extend(&data.value[1..]);
        }

        if first == 0 {
            trace!("data transfer done!");
            break;
        }
    }

    drop(notifs);
    trace!("ended peripheral notifications");

    peripheral
        .write(state, &[0x02], btleplug::api::WriteType::WithoutResponse)
        .await?;
    trace!("wrote end");

    peripheral.disconnect().await?;
    trace!("disconnected from peripheral");

    let validated = reader_sm.handle_response(&response);
    debug!("{validated:?}");

    Ok(validated)
}
