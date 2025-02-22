use std::time::Duration;

use btleplug::{
    api::{Central as _, CentralEvent, Manager as _, Peripheral as _, ScanFilter},
    platform::{Adapter, Manager},
};
use isomdl::{
    definitions::{
        DeviceEngagement,
        helpers::{NonEmptyMap, Tag24},
        session::Handover,
        x509::trust_anchor::TrustAnchorRegistry,
    },
    presentation::{authentication::ResponseAuthenticationOutcome, reader::SessionManager},
};
use thiserror::Error;
use tokio::sync::mpsc::{Receiver, channel};
use tokio_stream::StreamExt;
use tracing::{debug, error, trace, warn};
use uuid::{Uuid, uuid};

const STATE_ID: Uuid = uuid!("00000001-A123-48CE-896B-4C76973373E6");
const CLIENT2SERVER_ID: Uuid = uuid!("00000002-A123-48CE-896B-4C76973373E6");
const SERVER2CLIENT_ID: Uuid = uuid!("00000003-A123-48CE-896B-4C76973373E6");

/// Maximum length of data to read from a peripheral before aborting.
const MAX_PAYLOAD_SIZE: usize = 512 * 1000;

#[derive(Error, Debug)]
pub enum BleError {
    #[error(transparent)]
    BtleplugError(#[from] btleplug::Error),
    #[error("no ble adapter found")]
    NoAdapter,
    #[error("peripheral with service {0} was not found")]
    MissingPeripheral(Uuid),
    #[error("peripheral was missing characteristic {0}")]
    MissingCharacteristic(Uuid),
    #[error("received data exceeded maximum allowable size")]
    DataTooLarge,
    #[error("received data was empty")]
    DataEmpty,
}

macro_rules! find_characteristic {
    ($characteristics:expr, $characteristic:expr) => {
        match $characteristics.iter().find(|c| c.uuid == $characteristic) {
            Some(ch) => ch,
            None => return Err(BleError::MissingCharacteristic($characteristic).into()),
        }
    };
}

pub async fn attempt_connections<S>(
    trust_anchors: TrustAnchorRegistry,
    requested_elements: NonEmptyMap<String, NonEmptyMap<String, bool>>,
    mut stream: S,
) -> Result<Receiver<super::VerifierEvent>, BleError>
where
    S: futures::Stream<Item = super::StreamConnectionInfo> + Unpin + Send + Sync + 'static,
{
    let manager = Manager::new().await?;
    let mut adapters = manager.adapters().await?;
    let central = adapters.pop().ok_or(BleError::NoAdapter)?;

    let (tx, rx) = channel(1);

    tokio::spawn(async move {
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
                    .send(crate::VerifierEvent::AuthenticationOutcome(outcome))
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
) -> Result<ResponseAuthenticationOutcome, super::Error> {
    trace!("got device_engagement: {device_engagement:?}");

    let (mut reader_sm, session_request, _ble_ident) =
        SessionManager::establish_session_with_handover(
            device_engagement,
            requested_elements,
            trust_anchors,
            handover,
        )
        .map_err(Box::<dyn std::error::Error + Send + Sync + 'static>::from)
        .map_err(super::VerifyError::EstablishSession)?;

    let mut events = central.events().await.map_err(BleError::BtleplugError)?;

    central
        .start_scan(ScanFilter {
            services: vec![service_uuid],
        })
        .await
        .map_err(BleError::BtleplugError)?;
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
                return Err(BleError::MissingPeripheral(service_uuid).into());
            }
        }
    };

    central.stop_scan().await.map_err(BleError::BtleplugError)?;

    let peripheral = central
        .peripheral(&peripheral_id)
        .await
        .map_err(BleError::BtleplugError)?;
    peripheral
        .connect()
        .await
        .map_err(BleError::BtleplugError)?;
    peripheral
        .discover_services()
        .await
        .map_err(BleError::BtleplugError)?;
    trace!("discovered services");

    let characteristics: Vec<_> = peripheral
        .characteristics()
        .into_iter()
        .filter(|c| c.service_uuid == service_uuid)
        .collect();

    let state = find_characteristic!(characteristics, STATE_ID);
    let client2server = find_characteristic!(characteristics, CLIENT2SERVER_ID);
    let server2client = find_characteristic!(characteristics, SERVER2CLIENT_ID);

    peripheral
        .subscribe(state)
        .await
        .map_err(BleError::BtleplugError)?;
    peripheral
        .subscribe(server2client)
        .await
        .map_err(BleError::BtleplugError)?;
    trace!("subscribed to characteristics");

    peripheral
        .write(state, &[0x01], btleplug::api::WriteType::WithoutResponse)
        .await
        .map_err(BleError::BtleplugError)?;
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
            .await
            .map_err(BleError::BtleplugError)?;

        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    let mut notifs = peripheral
        .notifications()
        .await
        .map_err(BleError::BtleplugError)?;
    trace!("starting peripheral notifications");

    let mut response: Vec<u8> = Vec::new();

    while let Some(data) = notifs.next().await {
        if response.len() + data.value.len() > MAX_PAYLOAD_SIZE {
            return Err(BleError::DataTooLarge.into());
        }

        let Some(first) = data.value.first().copied() else {
            return Err(BleError::DataEmpty.into());
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
        .await
        .map_err(BleError::BtleplugError)?;
    trace!("wrote end");

    peripheral
        .disconnect()
        .await
        .map_err(BleError::BtleplugError)?;
    trace!("disconnected from peripheral");

    let validated = reader_sm.handle_response(&response);
    debug!("{validated:?}");

    Ok(validated)
}
