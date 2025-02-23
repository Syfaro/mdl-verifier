use std::{collections::HashMap, pin::Pin};

use futures::Stream;
use isomdl::{
    definitions::{
        BleOptions, DeviceEngagement,
        helpers::{NonEmptyMap, Tag24, tag24},
        x509::trust_anchor::{PemTrustAnchor, TrustAnchorRegistry, TrustPurpose},
    },
    presentation::authentication::ResponseAuthenticationOutcome,
};
use thiserror::Error;
use tokio::sync::mpsc::Receiver;
use tokio_stream::{StreamExt, StreamMap, wrappers::ReceiverStream};
use uuid::Uuid;

mod ble;
mod mdl;
mod nfc;

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    BleError(#[from] ble::BleError),
    #[error(transparent)]
    NfcError(#[from] nfc::NfcError),
    #[error(transparent)]
    VerifyError(#[from] VerifyError),
    #[error("invalid config: {0}")]
    InvalidConfig(&'static str),
    #[error("unexpected error: {0}")]
    Unexpected(Box<dyn std::error::Error + Send + Sync>),
    #[error("cancelled")]
    Timeout,
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
    AuthenticationOutcome(ResponseAuthenticationOutcome),
    Error(Error),
}

#[derive(Clone, Debug)]
pub struct StreamConnectionInfo {
    pub ble_service_mode: BLEServiceMode,
    pub ble_service_uuid: Uuid,
    pub device_engagement_bytes: Tag24<DeviceEngagement>,
    pub handover_type: HandoverType,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BLEServiceMode {
    PeripheralServer,
    CentralClient,
}

impl From<nfc::ndef::handover::BLERole> for BLEServiceMode {
    fn from(value: nfc::ndef::handover::BLERole) -> Self {
        use nfc::ndef::handover::BLERole::{
            Central, CentralPeripheral, Peripheral, PeripheralCentral,
        };

        match value {
            Peripheral | PeripheralCentral => Self::PeripheralServer,
            Central | CentralPeripheral => Self::CentralClient,
        }
    }
}

#[derive(Clone, Debug)]
pub enum HandoverType {
    Qr,
    Nfc {
        handover_select_bytes: Vec<u8>,
        handover_request_bytes: Option<Vec<u8>>,
    },
}

impl From<HandoverType> for isomdl::definitions::session::Handover {
    fn from(value: HandoverType) -> Self {
        match value {
            HandoverType::Qr => isomdl::definitions::session::Handover::QR,
            HandoverType::Nfc {
                handover_select_bytes,
                handover_request_bytes,
            } => isomdl::definitions::session::Handover::NFC(
                isomdl::definitions::helpers::ByteStr::from(handover_select_bytes),
                handover_request_bytes.map(isomdl::definitions::helpers::ByteStr::from),
            ),
        }
    }
}

type BoxedError = Box<dyn std::error::Error + Send + Sync + 'static>;
pub type PinnedConnectionInfoStream =
    Pin<Box<dyn Stream<Item = Result<StreamConnectionInfo, BoxedError>> + Send + Sync>>;

pub struct MdlVerifier {
    trust_anchors: TrustAnchorRegistry,
    requested_elements: NonEmptyMap<String, NonEmptyMap<String, bool>>,
    streams: StreamMap<String, PinnedConnectionInfoStream>,
}

impl MdlVerifier {
    pub fn new(
        certificate_pem_data: Vec<String>,
        requested_elements: HashMap<String, HashMap<String, bool>>,
    ) -> Result<Self, Error> {
        let requested_elements = Self::non_empty_requested_elements(requested_elements)
            .ok_or(Error::InvalidConfig("must have requested elements"))?;

        let certs: Vec<_> = certificate_pem_data
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

        Ok(Self {
            trust_anchors,
            requested_elements,
            streams: Default::default(),
        })
    }

    pub fn add_qr_stream<S>(&mut self, stream: S) -> &mut Self
    where
        S: Stream<Item = String> + Unpin + Send + Sync + 'static,
    {
        self.add_stream(
            "qr",
            Box::pin(stream.map(qr_to_needed)) as PinnedConnectionInfoStream,
        );

        self
    }

    pub fn add_nfc_stream(&mut self, connstring: String) -> Result<&mut Self, Error> {
        let nfc_rx = nfc::start_nfc_thread(connstring)?;
        let nfc_stream = ReceiverStream::new(nfc_rx).map(nfc_to_needed);

        self.add_stream("nfc", Box::pin(nfc_stream) as PinnedConnectionInfoStream);

        Ok(self)
    }

    pub fn add_stream<S>(&mut self, name: impl ToString, stream: S) -> &mut Self
    where
        S: Into<PinnedConnectionInfoStream>,
    {
        self.streams.insert(name.to_string(), stream.into());
        self
    }

    pub async fn start(self) -> Result<Receiver<VerifierEvent>, Error> {
        if self.streams.is_empty() {
            return Err(Error::InvalidConfig(
                "at least one stream must be specified",
            ));
        }

        let stream = self.streams.map(|(_name, res)| res);

        ble::attempt_connections(self.trust_anchors, self.requested_elements, stream)
            .await
            .map_err(Into::into)
    }

    fn non_empty_requested_elements(
        requested_elements: HashMap<String, HashMap<String, bool>>,
    ) -> Option<NonEmptyMap<String, NonEmptyMap<String, bool>>> {
        NonEmptyMap::maybe_new(
            requested_elements
                .into_iter()
                .filter_map(|(namespace, elements)| {
                    NonEmptyMap::maybe_new(elements.into_iter().collect())
                        .map(|map| (namespace, map))
                })
                .collect(),
        )
    }
}

fn nfc_to_needed(
    connection: nfc::NegotiatedConnection,
) -> Result<StreamConnectionInfo, BoxedError> {
    let device_engagement_bytes =
        Tag24::<DeviceEngagement>::from_bytes(connection.device_engagement)
            .map_err(VerifyError::DeviceEngagement)?;

    Ok(StreamConnectionInfo {
        ble_service_mode: connection.le_role.into(),
        ble_service_uuid: connection.service_uuid,
        device_engagement_bytes,
        handover_type: HandoverType::Nfc {
            handover_select_bytes: connection.handover_select,
            handover_request_bytes: connection.handover_request,
        },
    })
}

fn qr_to_needed(engagement: String) -> Result<StreamConnectionInfo, BoxedError> {
    let device_engagement_bytes = Tag24::<DeviceEngagement>::from_qr_code_uri(&engagement)
        .map_err(|err| {
            VerifyError::DeviceEngagementQr(
                Box::<dyn std::error::Error + Send + Sync + 'static>::from(err),
            )
        })?;

    let Some((ble_service_mode, ble_service_uuid)) = device_engagement_bytes
        .clone()
        .into_inner()
        .device_retrieval_methods
        .into_iter()
        .flat_map(|methods| methods.into_inner())
        .filter_map(|method| match method {
            isomdl::definitions::DeviceRetrievalMethod::BLE(ble) => Some(ble),
            _ => None,
        })
        .find_map(|ble| match ble {
            BleOptions {
                peripheral_server_mode: Some(peripheral_server_mode),
                ..
            } => Some((
                BLEServiceMode::PeripheralServer,
                peripheral_server_mode.uuid,
            )),
            BleOptions {
                central_client_mode: Some(central_client_mode),
                ..
            } => Some((BLEServiceMode::CentralClient, central_client_mode.uuid)),
            _ => None,
        })
    else {
        return Err(VerifyError::MissingMode("ble").into());
    };

    Ok(StreamConnectionInfo {
        ble_service_mode,
        ble_service_uuid,
        device_engagement_bytes,
        handover_type: HandoverType::Qr,
    })
}
