use std::time::Duration;

use btleplug::{
    api::{Central as _, CentralEvent, Peripheral as _, ScanFilter},
    platform::Adapter,
};
use futures::StreamExt;
use isomdl::{
    definitions::{
        DeviceEngagement,
        helpers::{NonEmptyMap, Tag24},
        session::Handover,
        x509::trust_anchor::TrustAnchorRegistry,
    },
    presentation::{authentication::ResponseAuthenticationOutcome, reader::SessionManager},
};
use tracing::{debug, trace};
use uuid::{Uuid, uuid};

use crate::{
    Error,
    ble::{BleError, MAX_PAYLOAD_SIZE, find_characteristic},
};

const STATE_ID: Uuid = uuid!("00000001-A123-48CE-896B-4C76973373E6");
const CLIENT2SERVER_ID: Uuid = uuid!("00000002-A123-48CE-896B-4C76973373E6");
const SERVER2CLIENT_ID: Uuid = uuid!("00000003-A123-48CE-896B-4C76973373E6");

pub async fn attempt_exchange(
    central: &Adapter,
    requested_elements: NonEmptyMap<String, NonEmptyMap<String, bool>>,
    trust_anchors: TrustAnchorRegistry,
    service_uuid: Uuid,
    device_engagement: Tag24<DeviceEngagement>,
    handover: Handover,
) -> Result<ResponseAuthenticationOutcome, Error> {
    let (mut reader_sm, session_request, _ble_ident) =
        SessionManager::establish_session_with_handover(
            device_engagement,
            requested_elements,
            trust_anchors,
            handover,
        )
        .map_err(Box::<dyn std::error::Error + Send + Sync + 'static>::from)
        .map_err(crate::VerifyError::EstablishSession)?;

    let mut events = central.events().await.map_err(BleError::Btleplug)?;

    central
        .start_scan(ScanFilter {
            services: vec![service_uuid],
        })
        .await
        .map_err(BleError::Btleplug)?;
    trace!(service_uuid = %service_uuid, "starting scan for service");

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

    central.stop_scan().await.map_err(BleError::Btleplug)?;

    let peripheral = central
        .peripheral(&peripheral_id)
        .await
        .map_err(BleError::Btleplug)?;
    peripheral.connect().await.map_err(BleError::Btleplug)?;
    peripheral
        .discover_services()
        .await
        .map_err(BleError::Btleplug)?;
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
        .map_err(BleError::Btleplug)?;
    peripheral
        .subscribe(server2client)
        .await
        .map_err(BleError::Btleplug)?;
    trace!("subscribed to characteristics");

    peripheral
        .write(state, &[0x01], btleplug::api::WriteType::WithoutResponse)
        .await
        .map_err(BleError::Btleplug)?;
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
            .map_err(BleError::Btleplug)?;

        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    let mut notifs = peripheral
        .notifications()
        .await
        .map_err(BleError::Btleplug)?;
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
        .map_err(BleError::Btleplug)?;
    trace!("wrote end");

    peripheral.disconnect().await.map_err(BleError::Btleplug)?;
    debug!("disconnected from peripheral");

    let validated = reader_sm.handle_response(&response);
    trace!("{validated:?}");

    Ok(validated)
}
