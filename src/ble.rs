use std::time::Duration;

use btleplug::{api::Manager as _, platform::Manager};
use futures::future::Either;
use isomdl::definitions::{helpers::NonEmptyMap, x509::trust_anchor::TrustAnchorRegistry};
use thiserror::Error;
use tokio::sync::mpsc::{Receiver, channel};
use tokio_stream::StreamExt;
use tokio_util::sync::CancellationToken;
use tracing::{error, warn};
use uuid::Uuid;

mod central;
mod peripheral;

/// Maximum length of data to read from a peripheral before aborting.
const MAX_PAYLOAD_SIZE: usize = 512 * 1000;

#[derive(Error, Debug)]
pub enum BleError {
    #[error(transparent)]
    Btleplug(#[from] btleplug::Error),
    #[error(transparent)]
    BlePeripheral(#[from] ble_peripheral_rust::error::Error),
    #[error("unexpected ble peripheral status")]
    BlePeripheralResponse(ble_peripheral_rust::gatt::peripheral_event::RequestResponse),
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
            None => return Err(crate::ble::BleError::MissingCharacteristic($characteristic).into()),
        }
    };
}

pub(crate) use find_characteristic;

pub async fn attempt_connections<S>(
    trust_anchors: TrustAnchorRegistry,
    requested_elements: NonEmptyMap<String, NonEmptyMap<String, bool>>,
    timeout: u64,
    mut stream: S,
) -> Result<Receiver<super::VerifierEvent>, BleError>
where
    S: futures::Stream<Item = Result<super::StreamConnectionInfo, super::BoxedError>>
        + Unpin
        + Send
        + Sync
        + 'static,
{
    let manager = Manager::new().await?;
    let mut adapters = manager.adapters().await?;
    let central = adapters.pop().ok_or(BleError::NoAdapter)?;

    let mut central_manager = central::CentralManager::new().await?;

    let (tx, rx) = channel(1);

    tokio::spawn(async move {
        while let Ok(Some(conn_info)) = stream.try_next().await {
            let res = match conn_info.ble_service_mode {
                crate::BLEServiceMode::PeripheralServer => tokio::time::timeout(
                    Duration::from_secs(timeout),
                    peripheral::attempt_exchange(
                        &central,
                        requested_elements.clone(),
                        trust_anchors.clone(),
                        conn_info.ble_service_uuid,
                        conn_info.device_engagement_bytes,
                        conn_info.handover_type.into(),
                    ),
                )
                .await
                .map_err(|_| crate::Error::Timeout),
                crate::BLEServiceMode::CentralClient => {
                    let token = CancellationToken::new();

                    let timeout_fut = tokio::time::sleep(Duration::from_secs(timeout));
                    tokio::pin!(timeout_fut);

                    let exchange_fut = central_manager.attempt_exchange(
                        requested_elements.clone(),
                        trust_anchors.clone(),
                        conn_info.ble_service_uuid,
                        conn_info.device_engagement_bytes,
                        conn_info.handover_type.into(),
                        token.clone(),
                    );
                    tokio::pin!(exchange_fut);

                    match futures::future::select(timeout_fut, exchange_fut).await {
                        Either::Left((_, fut)) => {
                            warn!("exchange timed out");
                            token.cancel();
                            Ok(fut.await)
                        }
                        Either::Right((res, _)) => Ok(res),
                    }
                }
            };

            match res {
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
