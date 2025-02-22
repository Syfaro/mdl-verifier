use std::pin::Pin;

use futures::Stream;
use isomdl::{
    definitions::{
        BleOptions, DeviceEngagement,
        device_request::{DataElements, Namespaces},
        helpers::{ByteStr, Tag24, tag24},
        session::Handover,
        x509::trust_anchor::{PemTrustAnchor, TrustAnchorRegistry, TrustPurpose},
    },
    presentation::authentication::ResponseAuthenticationOutcome,
};
use thiserror::Error;
use tokio::sync::mpsc::Receiver;
use tokio_stream::{StreamExt, StreamMap};
use uuid::Uuid;

mod ble;
mod mdl;
mod nfc;

pub struct Config {
    pub certificate_pem_data: Vec<String>,
    pub nfc_connstring: Option<String>,
}

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    BleError(#[from] ble::BleError),
    #[error(transparent)]
    NfcError(#[from] nfc::NfcError),
    #[error(transparent)]
    VerifyError(#[from] VerifyError),
}

#[derive(Error, Debug)]
pub enum VerifyError {
    #[error("failed to build trust anchors")]
    TrustAnchor(Box<dyn std::error::Error + Send + Sync>),
    #[error(transparent)]
    DeviceEngagement(tag24::Error),
    #[error("failed to parse qr code engagement")]
    DeviceEngagementQr(Box<dyn std::error::Error + Send + Sync>),
    #[error("missing required connection mode: {0}")]
    MissingMode(&'static str),
    #[error("failed to establish session")]
    EstablishSession(Box<dyn std::error::Error + Send + Sync>),
}

#[derive(Debug)]
pub enum VerifierEvent {
    Error(Error),
    AuthenticationOutcome(ResponseAuthenticationOutcome),
}

type StreamConnectionInfo = Result<(Uuid, Tag24<DeviceEngagement>, Handover), Error>;
type PinnedStreamResult = Pin<Box<dyn Stream<Item = StreamConnectionInfo> + Send + Sync>>;

pub async fn start<S>(config: Config, scanner_stream: S) -> Result<Receiver<VerifierEvent>, Error>
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

    let certs: Vec<_> = config
        .certificate_pem_data
        .into_iter()
        .map(|cert| PemTrustAnchor {
            purpose: TrustPurpose::Iaca,
            certificate_pem: cert,
        })
        .collect();

    let trust_anchors = TrustAnchorRegistry::from_pem_certificates(certs).map_err(|err| {
        VerifyError::TrustAnchor(Box::<dyn std::error::Error + Send + Sync + 'static>::from(
            err,
        ))
    })?;

    let requested_elements = Namespaces::new(
        "org.iso.18013.5.1".into(),
        DataElements::new("age_over_21".to_string(), false),
    );

    let rx = ble::attempt_connections(trust_anchors, requested_elements, stream).await?;

    Ok(rx)
}

fn nfc_to_needed(connection: nfc::NegotiatedConnection) -> StreamConnectionInfo {
    Ok((
        connection.service_uuid,
        Tag24::<DeviceEngagement>::from_bytes(connection.device_engagement)
            .map_err(VerifyError::DeviceEngagement)?,
        Handover::NFC(
            ByteStr::from(connection.handover_select),
            connection.handover_request.map(ByteStr::from),
        ),
    ))
}

fn qr_to_needed(engagement: String) -> StreamConnectionInfo {
    let device_engagement =
        Tag24::<DeviceEngagement>::from_qr_code_uri(&engagement).map_err(|err| {
            VerifyError::DeviceEngagementQr(
                Box::<dyn std::error::Error + Send + Sync + 'static>::from(err),
            )
        })?;

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
        return Err(VerifyError::MissingMode("ble peripheral server").into());
    };

    Ok((server_mode.uuid, device_engagement, Handover::QR))
}
