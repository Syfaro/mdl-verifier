use std::{collections::HashMap, time::Duration};

use nfc1::{
    Context, Device, Modulation, Target,
    target_info::{Iso14443a, TargetInfo},
};
use tracing::{debug, info, instrument, trace};

mod ndef;

use ndef::{IntoNdefRecord, KnownNdefRecord};

const T4T_CLASS: u8 = 0x00;

const T4T_INS_SELECT: u8 = 0xA4;
const T4T_INS_READ: u8 = 0xB0;
const T4T_INS_UPDATE: u8 = 0xD6;

const T4T_COMPLETED: u8 = 0x90;

const NDEF_APP_SELECT: u8 = 0x04;
const NDEF_FILE_SELECT: u8 = 0x00;

const NDEF_CC_FILE: u16 = 0xE103;
const NDEF_AID: [u8; 7] = [0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01];

static MODULATION: Modulation = Modulation {
    modulation_type: nfc1::ModulationType::Iso14443a,
    baud_rate: nfc1::BaudRate::Baud106,
};

pub struct NfcReader<'a> {
    device: Device<'a>,
}

impl<'a> NfcReader<'a> {
    #[instrument(skip(context))]
    pub fn new(context: &'a mut Context, connstring: &str) -> eyre::Result<NfcReader<'a>> {
        let mut device = context.open_with_connstring(connstring)?;
        device.initiator_init()?;
        info!(name = device.name(), "opened nfc device");

        Ok(Self { device })
    }

    pub fn poll_14a(&mut self) -> eyre::Result<Option<Iso14443a>> {
        let mut targets = self.device.initiator_list_passive_targets(&MODULATION, 1)?;
        eyre::ensure!(targets.len() <= 1, "at most one target should be returned");

        if let Some(Target {
            target_info: TargetInfo::Iso14443a(info),
            ..
        }) = targets.pop()
        {
            if info.uid_len > 0 {
                return Ok(Some(info));
            } else {
                trace!("uid_len was 0, no tag detected");
            }
        }

        Ok(None)
    }

    #[instrument(skip_all, fields(uid))]
    pub fn get_18013_5_device_engagement(&mut self, info: Iso14443a) -> eyre::Result<()> {
        let uid = info.uid[..info.uid_len].to_vec();
        tracing::Span::current().record("uid", hex::encode(&uid));
        debug!("got device uid");

        self.select_app(&NDEF_AID)?;
        self.select_file(NDEF_CC_FILE)?;

        let cc_data = self.read_file(0, 15)?;
        eyre::ensure!(
            cc_data.len() == 15,
            "cc file read should have returned 15 bytes"
        );

        let ndef_file_id = Self::get_ndef_file_id_from_cc(&cc_data)?;
        let ndef_file_data = self.read_file_ndef(ndef_file_id)?;
        trace!("got ndef file data: {}", hex::encode(&ndef_file_data));

        self.process_ndef_data(ndef_file_data)?;

        todo!()
    }

    fn process_ndef_data(&mut self, ndef_file_data: Vec<u8>) -> eyre::Result<()> {
        let records = ndef::RawNdefRecord::decode_many(&mut ndef_file_data.into_iter())?
            .into_iter()
            .map(ndef::KnownNdefRecord::parse)
            .collect::<Result<Vec<_>, _>>()?;

        let records_by_id: HashMap<_, _> = records
            .iter()
            .cloned()
            .filter_map(|(id, record)| id.map(|id| (id, record)))
            .collect();

        for (_, record) in records {
            match record {
                KnownNdefRecord::TnepServiceParameter(param) => {
                    trace!("got tnep service param: {param:?}");

                    let wait_time = Duration::from_secs_f32(param.wait_time_seconds());
                    trace!(?wait_time);

                    std::thread::sleep(wait_time);

                    let service_select = ndef::tnep::ServiceSelect {
                        service_name: param.service_name,
                    }
                    .ndef_record();
                    self.update_file_ndef(service_select)?;
                    let ndef_file_data = self.read_current_file_ndef()?;
                    trace!("got tnep response data: {}", hex::encode(&ndef_file_data));
                    let (_, known_record) = ndef::KnownNdefRecord::parse(
                        ndef::RawNdefRecord::decode_single(&mut ndef_file_data.into_iter())?,
                    )?;
                    eyre::ensure!(
                        matches!(
                            known_record,
                            ndef::KnownNdefRecord::TnepStatus(ndef::tnep::Status::Success)
                        ),
                        "tnep service select must be successful"
                    );

                    let service_address = uuid::Uuid::new_v4();
                    let messages = vec![
                        ndef::handover::HandoverRequest {
                            version: param.version,
                            collision_resolution: rand::random(),
                            alternative_carriers: vec![ndef::handover::AlternativeCarrier {
                                carrier_power_state: ndef::handover::CarrierPowerState::Active,
                                carrier_data_reference: b"0".to_vec(),
                                auxiliary_data_references: vec![b"mdocreader".to_vec()],
                            }],
                        }
                        .ndef_record(),
                        ndef::handover::BLECarrierConfiguration::new(
                            ndef::handover::BLERole::Peripheral,
                            service_address,
                        )
                        .carrier_configuration()
                        .ndef_record(),
                        ndef::encode_record(
                            true,
                            true,
                            ndef::TypeNameFormat::External,
                            b"iso.org:18013:readerengagement",
                            Some(b"mdocreader"),
                            &crate::mdl::ReaderEngagement::default().encode()?,
                        ),
                    ];
                    let message_data = ndef::merge_messages(messages);
                    self.update_file_ndef(message_data)?;

                    let ndef_file_data = self.read_current_file_ndef()?;
                    trace!("got ndef file data: {}", hex::encode(&ndef_file_data));
                    self.process_ndef_data(ndef_file_data)?;
                }
                KnownNdefRecord::HandoverSelect(select) => {
                    debug!("got handover select: {select:?}");

                    for alt_carrier in select.alternative_carriers {
                        if let Some(record) = records_by_id.get(&alt_carrier.carrier_data_reference)
                        {
                            debug!("select referenced carrier: {record:?}");
                        }

                        for aux_ref in alt_carrier.auxiliary_data_references {
                            if let Some(record) = records_by_id.get(&aux_ref) {
                                debug!("carrier referenced aux data: {record:?}");
                            }
                        }
                    }
                }
                other => {
                    trace!("got other ndef record: {other:?}");
                }
            }
        }

        Ok(())
    }

    #[instrument(skip_all)]
    fn select_app(&mut self, aid: &[u8]) -> eyre::Result<()> {
        let mut select_app_req = vec![
            T4T_CLASS,
            T4T_INS_SELECT,
            NDEF_APP_SELECT,
            0x00,
            aid.len() as u8,
        ];
        select_app_req.extend_from_slice(aid);
        select_app_req.push(0x00);
        trace!("built request: {}", hex::encode(&select_app_req));

        let select_app_resp =
            self.device
                .initiator_transceive_bytes(&select_app_req, 2, nfc1::Timeout::Default)?;
        trace!(
            "got response from select: {}",
            hex::encode(&select_app_resp)
        );

        Self::check_status("select app", &select_app_resp)?;

        Ok(())
    }

    #[instrument(skip_all, fields(file_id = hex::encode(file_id.to_be_bytes())))]
    fn select_file(&mut self, file_id: u16) -> eyre::Result<()> {
        let mut select_file_req = vec![T4T_CLASS, T4T_INS_SELECT, NDEF_FILE_SELECT, 0x0C, 0x02];
        select_file_req.extend_from_slice(&file_id.to_be_bytes());
        trace!("built request: {}", hex::encode(&select_file_req));

        let select_file_resp =
            self.device
                .initiator_transceive_bytes(&select_file_req, 2, nfc1::Timeout::Default)?;
        trace!(
            "got response from select: {}",
            hex::encode(&select_file_resp)
        );

        Self::check_status("select file", &select_file_resp)?;

        Ok(())
    }

    #[instrument(skip(self, offset), fields(offset = hex::encode(offset.to_be_bytes())))]
    fn read_file(&mut self, offset: u16, length: u8) -> eyre::Result<Vec<u8>> {
        let mut read_file_req = vec![T4T_CLASS, T4T_INS_READ];
        read_file_req.extend_from_slice(&offset.to_be_bytes());
        read_file_req.push(length);
        trace!("built request: {}", hex::encode(&read_file_req));

        let mut read_file_resp =
            self.device
                .initiator_transceive_bytes(&read_file_req, 256, nfc1::Timeout::Default)?;
        trace!("got response from read: {}", hex::encode(&read_file_resp));

        Self::check_status("read file", &read_file_resp)?;

        // Last two bytes are status, not part of the data.
        read_file_resp.truncate(read_file_resp.len() - 2);
        Ok(read_file_resp)
    }

    #[instrument(skip_all, fields(ndef_file_id))]
    fn read_file_ndef(&mut self, ndef_file_id: u16) -> eyre::Result<Vec<u8>> {
        tracing::Span::current().record("tlv_data", hex::encode(ndef_file_id.to_be_bytes()));
        self.select_file(ndef_file_id)?;

        self.read_current_file_ndef()
    }

    fn read_current_file_ndef(&mut self) -> eyre::Result<Vec<u8>> {
        let ndef_file_len_data = self.read_file(0, 2)?;
        eyre::ensure!(
            ndef_file_len_data.len() == 2,
            "ndef file read should have returned 2 bytes"
        );
        let ndef_file_len_bytes: [u8; 2] = ndef_file_len_data.try_into().unwrap();
        let ndef_file_len = u16::from_be_bytes(ndef_file_len_bytes);
        trace!(len = ndef_file_len, "got ndef file len");

        let mut ndef_file_data: Vec<u8> = Vec::with_capacity(ndef_file_len.into());
        let mut offset = 2;

        while ndef_file_data.len() < ndef_file_len.into() {
            let remaining = usize::from(ndef_file_len) - ndef_file_data.len();
            let chunk_size = u8::try_from(remaining).unwrap_or(u8::MAX);
            trace!(remaining, chunk_size, offset, "performing ndef read");

            let ndef_chunk = self.read_file(offset, chunk_size)?;
            ndef_file_data.extend_from_slice(&ndef_chunk);

            offset += chunk_size as u16;
        }
        eyre::ensure!(
            ndef_file_data.len() == ndef_file_len.into(),
            "ndef file should be reported length"
        );

        Ok(ndef_file_data)
    }

    #[instrument(skip_all)]
    fn update_file_ndef(&mut self, ndef_file_data: Vec<u8>) -> eyre::Result<()> {
        trace!(
            "updating file with ndef data: {}",
            hex::encode(&ndef_file_data)
        );

        self.update_file(0x00, &0u16.to_be_bytes())?;

        let mut offset = 2;
        for chunk in ndef_file_data.chunks(0xFF) {
            self.update_file(offset, chunk)?;
            offset += u16::try_from(chunk.len()).unwrap();
        }

        let ndef_file_data_len = u16::try_from(ndef_file_data.len()).unwrap();
        self.update_file(0x00, &ndef_file_data_len.to_be_bytes())?;

        Ok(())
    }

    #[instrument(skip_all)]
    fn update_file(&mut self, offset: u16, data: &[u8]) -> eyre::Result<()> {
        eyre::ensure!(
            (0x0000..=0x7FFF).contains(&offset),
            "offset range is 0000h-7FFFh"
        );
        eyre::ensure!(
            (0x01..=0xFF).contains(&data.len()),
            "data length range is 01h-FFh"
        );

        let mut update_file_req = vec![T4T_CLASS, T4T_INS_UPDATE];
        update_file_req.extend_from_slice(&offset.to_be_bytes());
        update_file_req.push(u8::try_from(data.len()).unwrap());
        update_file_req.extend_from_slice(data);
        trace!("built request: {}", hex::encode(&update_file_req));

        let update_file_resp =
            self.device
                .initiator_transceive_bytes(&update_file_req, 2, nfc1::Timeout::Default)?;
        trace!("got update response: {}", hex::encode(&update_file_resp));
        Self::check_status("update file", &update_file_resp)?;

        Ok(())
    }

    #[track_caller]
    fn check_status(action: &'static str, data: &[u8]) -> eyre::Result<()> {
        let status_bytes = &data[data.len() - 2..];
        if status_bytes != [T4T_COMPLETED, 0x00] {
            eyre::bail!(
                "unexpected response from {action}: {}",
                hex::encode(status_bytes)
            );
        }
        Ok(())
    }

    #[instrument(skip_all, fields(tlv_data))]
    fn get_ndef_file_id_from_cc(cc_data: &[u8]) -> eyre::Result<u16> {
        let ndef_file_control_tlv = &cc_data[7..15];
        tracing::Span::current().record("tlv_data", hex::encode(ndef_file_control_tlv));
        trace!("got ndef file control tlv");
        eyre::ensure!(
            ndef_file_control_tlv[..2] == [0x04, 0x06],
            "unknown tlv header"
        );

        // 2 bytes should always fit into a u16
        let ndef_file_id_bytes: [u8; 2] = ndef_file_control_tlv[2..4].try_into().unwrap();
        let ndef_file_id = u16::from_be_bytes(ndef_file_id_bytes);
        trace!(
            "got ndef file id: {}",
            hex::encode(ndef_file_id.to_be_bytes())
        );

        Ok(ndef_file_id)
    }
}
