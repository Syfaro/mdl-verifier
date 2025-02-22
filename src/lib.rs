use std::pin::Pin;

use futures::Stream;
use isomdl::{
    definitions::{
        BleOptions, DeviceEngagement,
        helpers::{ByteStr, Tag24},
        session::Handover,
    },
    presentation::authentication::ResponseAuthenticationOutcome,
};
use tokio_stream::{StreamExt, StreamMap};
use uuid::Uuid;

mod ble;
mod mdl;
mod nfc;

pub struct Config {
    pub certificate_pem_data: Vec<String>,
    pub nfc_connstring: Option<String>,
}

#[derive(Debug)]
pub enum VerifierEvent {
    Error(eyre::Report),
    Verified(ResponseAuthenticationOutcome),
}

type StreamConnectionInfo = eyre::Result<(Uuid, Tag24<DeviceEngagement>, Handover)>;
type PinnedStreamResult = Pin<Box<dyn Stream<Item = StreamConnectionInfo> + Send + Sync>>;

pub async fn start<S>(
    config: Config,
    scanner_stream: S,
) -> eyre::Result<tokio::sync::mpsc::Receiver<VerifierEvent>>
where
    S: Stream<Item = String> + Unpin + Send + Sync + 'static,
{
    let mut streams = StreamMap::new();

    streams.insert(
        "qr",
        Box::pin(scanner_stream.map(qr_to_needed)) as PinnedStreamResult,
    );

    if let Some(connstring) = config.nfc_connstring {
        let nfc_rx = nfc::start_nfc_thread(connstring)?;
        let nfc_stream = tokio_stream::wrappers::ReceiverStream::new(nfc_rx).map(nfc_to_needed);

        streams.insert("nfc", Box::pin(nfc_stream) as PinnedStreamResult);
    }

    let stream = streams.map(|(_, res)| res);

    let rx = ble::attempt_connections(config.certificate_pem_data, stream).await?;

    Ok(rx)
}

fn nfc_to_needed(
    connection: nfc::NegotiatedConnection,
) -> eyre::Result<(Uuid, Tag24<DeviceEngagement>, Handover)> {
    Ok((
        connection.service_uuid,
        Tag24::<DeviceEngagement>::from_bytes(connection.device_engagement)?,
        Handover::NFC(
            ByteStr::from(connection.handover_select),
            connection.handover_request.map(ByteStr::from),
        ),
    ))
}

fn qr_to_needed(engagement: String) -> eyre::Result<(Uuid, Tag24<DeviceEngagement>, Handover)> {
    let device_engagement = Tag24::<DeviceEngagement>::from_qr_code_uri(&engagement)
        .map_err(|err| eyre::eyre!(Box::new(err)))?;

    let Some(server_mode) = device_engagement
        .clone()
        .into_inner()
        .device_retrieval_methods
        .and_then(|methods| {
            methods.iter().find_map(|method| match method {
                isomdl::definitions::DeviceRetrievalMethod::BLE(BleOptions {
                    peripheral_server_mode: Some(server_mode),
                    ..
                }) => Some(server_mode.clone()),
                _ => None,
            })
        })
    else {
        eyre::bail!("could not find BLE peripheral server mode");
    };

    Ok((server_mode.uuid, device_engagement, Handover::QR))
}
