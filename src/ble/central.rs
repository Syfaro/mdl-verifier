use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
    time::Duration,
};

use ble_peripheral_rust::{
    Peripheral, PeripheralImpl,
    gatt::{
        characteristic::Characteristic,
        peripheral_event::{
            PeripheralEvent, ReadRequestResponse, RequestResponse, WriteRequestResponse,
        },
        properties::{AttributePermission, CharacteristicProperty},
        service::Service,
    },
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
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use tracing::{error, trace, warn};
use uuid::{Uuid, uuid};

use crate::{Error, ble::BleError};

const STATE_ID: Uuid = uuid!("00000005-A123-48CE-896B-4C76973373E6");
const CLIENT2SERVER_ID: Uuid = uuid!("00000006-A123-48CE-896B-4C76973373E6");
const SERVER2CLIENT_ID: Uuid = uuid!("00000007-A123-48CE-896B-4C76973373E6");
const IDENT_ID: Uuid = uuid!("00000008-A123-48CE-896B-4C76973373E6");

type PendingServices = Arc<Mutex<HashMap<Uuid, PendingService>>>;

struct PendingService {
    ready_to_send: Option<oneshot::Sender<()>>,
    received_data: Option<oneshot::Sender<Vec<u8>>>,
    buf: Vec<u8>,
}

impl PendingService {
    fn new() -> (
        PendingService,
        oneshot::Receiver<()>,
        oneshot::Receiver<Vec<u8>>,
    ) {
        let (ready_to_send, ready_rx) = oneshot::channel();
        let (received_data, data_rx) = oneshot::channel();

        (
            PendingService {
                ready_to_send: Some(ready_to_send),
                received_data: Some(received_data),
                buf: Vec::new(),
            },
            ready_rx,
            data_rx,
        )
    }
}

pub struct CentralManager {
    peripheral: Peripheral,
    advertised_services: HashSet<Uuid>,

    pending_services: PendingServices,
}

impl CentralManager {
    pub async fn new() -> Result<Self, BleError> {
        let pending_services = PendingServices::default();

        let (event_tx, event_rx) = mpsc::channel::<PeripheralEvent>(1);

        let mut peripheral = Peripheral::new(event_tx)
            .await
            .map_err(BleError::BlePeripheral)?;

        while !peripheral
            .is_powered()
            .await
            .map_err(BleError::BlePeripheral)?
        {}

        tokio::spawn(Self::start_background_task(
            event_rx,
            Arc::clone(&pending_services),
        ));

        Ok(Self {
            peripheral,
            pending_services,
            advertised_services: Default::default(),
        })
    }

    pub async fn attempt_exchange(
        &mut self,
        requested_elements: NonEmptyMap<String, NonEmptyMap<String, bool>>,
        trust_anchors: TrustAnchorRegistry,
        service_uuid: Uuid,
        device_engagement: Tag24<DeviceEngagement>,
        handover: Handover,
        token: CancellationToken,
    ) -> Result<ResponseAuthenticationOutcome, Error> {
        let (mut reader_sm, session_request, ble_ident) =
            SessionManager::establish_session_with_handover(
                device_engagement,
                requested_elements,
                trust_anchors,
                handover,
            )
            .map_err(Box::<dyn std::error::Error + Send + Sync + 'static>::from)
            .map_err(crate::VerifyError::EstablishSession)?;

        let service = Self::create_service(service_uuid, ble_ident.to_vec());

        let (pending_service, ready_rx, data_rx) = PendingService::new();
        self.pending_services
            .lock()
            .unwrap()
            .insert(service_uuid, pending_service);

        self.peripheral
            .add_service(&service)
            .await
            .map_err(BleError::BlePeripheral)?;

        self.advertised_services.insert(service_uuid);
        self.advertise_services().await?;

        let res = token
            .run_until_cancelled(self.exchange_data(session_request, ready_rx, data_rx))
            .await;

        self.pending_services.lock().unwrap().remove(&service_uuid);

        // TODO: doesn't look like there's a way to remove services right now
        self.advertised_services.remove(&service_uuid);
        self.advertise_services().await?;

        match res {
            Some(Ok(data)) => Ok(reader_sm.handle_response(&data)),
            Some(Err(err)) => Err(err),
            None => Err(Error::Timeout),
        }
    }

    async fn exchange_data(
        &mut self,
        session_request: Vec<u8>,
        ready_rx: oneshot::Receiver<()>,
        data_rx: oneshot::Receiver<Vec<u8>>,
    ) -> Result<Vec<u8>, Error> {
        ready_rx.await.map_err(|_| Error::Timeout)?;

        let mtu = 20;
        let mut chunks = session_request.chunks(mtu - 1).peekable();
        while let Some(chunk) = chunks.next() {
            let mut data = Vec::with_capacity(mtu);
            data.push(if chunks.peek().is_some() { 0x01 } else { 0x00 });
            data.extend_from_slice(chunk);

            self.peripheral
                .update_characteristic(SERVER2CLIENT_ID, data)
                .await
                .map_err(BleError::BlePeripheral)?;

            tokio::time::sleep(Duration::from_millis(5)).await;
        }

        data_rx.await.map_err(|_| Error::Timeout)
    }

    fn create_service(uuid: Uuid, ble_ident: Vec<u8>) -> Service {
        Service {
            uuid,
            primary: true,
            characteristics: vec![
                Characteristic {
                    uuid: STATE_ID,
                    properties: vec![
                        CharacteristicProperty::Notify,
                        CharacteristicProperty::WriteWithoutResponse,
                    ],
                    permissions: vec![
                        AttributePermission::Readable,
                        AttributePermission::Writeable,
                    ],
                    ..Default::default()
                },
                Characteristic {
                    uuid: CLIENT2SERVER_ID,
                    properties: vec![CharacteristicProperty::WriteWithoutResponse],
                    permissions: vec![AttributePermission::Writeable],
                    ..Default::default()
                },
                Characteristic {
                    uuid: SERVER2CLIENT_ID,
                    properties: vec![CharacteristicProperty::Notify],
                    permissions: vec![AttributePermission::Readable],
                    ..Default::default()
                },
                Characteristic {
                    uuid: IDENT_ID,
                    properties: vec![CharacteristicProperty::Read],
                    permissions: vec![AttributePermission::Readable],
                    value: Some(ble_ident),
                    ..Default::default()
                },
            ],
        }
    }

    async fn advertise_services(&mut self) -> Result<(), Error> {
        trace!(
            len = self.advertised_services.len(),
            "updating advertised services"
        );

        if self.advertised_services.is_empty() {
            self.peripheral.stop_advertising().await
        } else {
            self.peripheral
                .start_advertising(
                    "mdoc reader",
                    &self.advertised_services.iter().copied().collect::<Vec<_>>(),
                )
                .await
        }
        .map_err(BleError::BlePeripheral)
        .map_err(Error::BleError)
    }

    async fn start_background_task(
        mut event_rx: mpsc::Receiver<PeripheralEvent>,
        pending_services: PendingServices,
    ) -> Result<(), Error> {
        while let Some(event) = event_rx.recv().await {
            match event {
                PeripheralEvent::ReadRequest {
                    request, responder, ..
                } => {
                    warn!(%request.service, %request.characteristic, "got unexpected read request");
                    responder
                        .send(ReadRequestResponse {
                            value: vec![],
                            response: RequestResponse::RequestNotSupported,
                        })
                        .map_err(|err| BleError::BlePeripheralResponse(err.response))?
                }
                PeripheralEvent::WriteRequest {
                    request,
                    value,
                    offset,
                    responder,
                } => {
                    trace!(
                        %request.service,
                        %request.characteristic,
                        offset,
                        "got write request: {}",
                        hex::encode(&value)
                    );
                    match request.characteristic {
                        STATE_ID => {
                            if value != [0x01] {
                                warn!("got unexpected status code: {}", hex::encode(value));
                                continue;
                            }

                            let ready_sender =
                                match pending_services.lock().unwrap().get_mut(&request.service) {
                                    Some(PendingService { ready_to_send, .. }) => {
                                        ready_to_send.take()
                                    }
                                    _ => {
                                        warn!("got unexpected service state: {}", request.service);
                                        continue;
                                    }
                                };

                            match ready_sender.map(|sender| sender.send(())) {
                                Some(Ok(_)) => trace!("sent that service was ready for data"),
                                Some(Err(_)) => error!("could not send that service was ready"),
                                None => warn!("service sent ready multiple times"),
                            }
                        }
                        CLIENT2SERVER_ID => {
                            {
                                let mut pending_services = pending_services.lock().unwrap();
                                let pending_service = match pending_services
                                    .get_mut(&request.service)
                                {
                                    Some(pending_service) => pending_service,
                                    None => {
                                        warn!("got data for unknown service: {}", request.service);
                                        continue;
                                    }
                                };
                                pending_service.buf.extend_from_slice(&value[1..]);
                            }

                            if !value.is_empty() && value[0] != 0x00 {
                                trace!("more data expected");
                                continue;
                            }

                            let Some(pending_service) =
                                pending_services.lock().unwrap().remove(&request.service)
                            else {
                                warn!(
                                    "attempting to send data for unknown service: {}",
                                    request.service
                                );
                                continue;
                            };

                            match pending_service
                                .received_data
                                .map(|tx| tx.send(pending_service.buf))
                            {
                                Some(Ok(_)) => trace!("sent final data"),
                                Some(Err(_)) => error!("could not send final data"),
                                None => warn!("already sent final data for service"),
                            }
                        }
                        other => {
                            warn!("device tried to write other characteristic: {other}");
                        }
                    }

                    responder
                        .send(WriteRequestResponse {
                            response: RequestResponse::Success,
                        })
                        .map_err(|err| BleError::BlePeripheralResponse(err.response))?;
                }
                other => trace!("got other peripheral event: {other:?}"),
            }
        }

        Ok(())
    }
}
