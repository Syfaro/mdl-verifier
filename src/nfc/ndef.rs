use tracing::{error, instrument, trace};

use crate::nfc::{NfcError, ensure_length, get_byte, get_bytes};

pub mod handover;
pub mod tnep;

pub trait IntoNdefRecord {
    fn ndef_record(self) -> Vec<u8>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypeNameFormat {
    Empty,
    WellKnown,
    MediaType,
    AbsoluteUri,
    External,
    Unknown,
    Unchanged,
    Reserved,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum KnownNdefRecord {
    TnepServiceParameter(tnep::ServiceParameter),
    TnepStatus(tnep::Status),
    HandoverSelect(handover::HandoverSelect),
    BluetoothCarrierConfiguration(handover::BLECarrierConfiguration),
    DeviceEngagement(Vec<u8>),
    Unknown(RawNdefRecord),
}

pub type IdAndKnownRecord = (Option<Vec<u8>>, KnownNdefRecord);

impl KnownNdefRecord {
    pub fn parse(record: RawNdefRecord) -> Result<IdAndKnownRecord, NfcError> {
        let id = record.id_data.clone();

        let known_record = match (record.type_name_format, record.type_data.as_slice()) {
            (TypeNameFormat::WellKnown, b"Tp") => {
                tnep::ServiceParameter::decode(&record.payload_data)
                    .map(KnownNdefRecord::TnepServiceParameter)
            }
            (TypeNameFormat::WellKnown, b"Te") => {
                tnep::Status::decode(&record.payload_data).map(KnownNdefRecord::TnepStatus)
            }
            (TypeNameFormat::WellKnown, b"Hs") => {
                handover::HandoverSelect::decode(&record.payload_data)
                    .map(KnownNdefRecord::HandoverSelect)
            }
            (TypeNameFormat::MediaType, type_data)
                if type_data == handover::BLECarrierConfiguration::RECORD_TYPE_NAME.as_bytes() =>
            {
                handover::BLECarrierConfiguration::decode(&record.payload_data)
                    .map(KnownNdefRecord::BluetoothCarrierConfiguration)
            }
            (TypeNameFormat::External, b"iso.org:18013:deviceengagement")
                if record.id_data.as_deref() == Some(b"mdoc") =>
            {
                Ok(KnownNdefRecord::DeviceEngagement(record.payload_data))
            }
            _ => Ok(KnownNdefRecord::Unknown(record)),
        }?;

        Ok((id, known_record))
    }
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct RawNdefRecord {
    pub message_begin: bool,
    pub message_end: bool,
    pub chunk_flag: bool,
    pub short_record: bool,
    pub id_length_present: bool,
    pub type_name_format: TypeNameFormat,
    pub type_length: u8,
    pub id_length: Option<u8>,
    pub payload_length: u32,
    pub type_data: Vec<u8>,
    pub id_data: Option<Vec<u8>>,
    pub payload_data: Vec<u8>,
}

impl RawNdefRecord {
    #[instrument(skip_all)]
    pub fn decode_many<Iter>(data: &mut Iter) -> Result<Vec<Self>, NfcError>
    where
        Iter: Iterator<Item = u8>,
    {
        let mut data = data.into_iter().peekable();

        let mut records = Vec::new();
        while data.peek().is_some() {
            let record = Self::decode_single(&mut data)?;
            records.push(record);
        }

        Ok(records)
    }

    #[instrument(skip_all)]
    pub fn decode_single<Iter>(data: &mut Iter) -> Result<Self, NfcError>
    where
        Iter: Iterator<Item = u8>,
    {
        let header = get_byte!(data, "header");
        let message_begin = Self::u8_to_bool(header & 0b10000000);
        let message_end = Self::u8_to_bool(header & 0b01000000);
        let chunk_flag = Self::u8_to_bool(header & 0b00100000);
        let short_record = Self::u8_to_bool(header & 0b00010000);
        let id_length_present = Self::u8_to_bool(header & 0b00001000);
        let type_name_format = header & 0b00000111;
        trace!(
            message_begin,
            message_end,
            chunk_flag,
            short_record,
            id_length_present,
            type_name_format,
            "got ndef header byte"
        );

        let type_name_format = match type_name_format {
            0x00 => TypeNameFormat::Empty,
            0x01 => TypeNameFormat::WellKnown,
            0x02 => TypeNameFormat::MediaType,
            0x03 => TypeNameFormat::AbsoluteUri,
            0x04 => TypeNameFormat::External,
            0x05 => TypeNameFormat::Unknown,
            0x06 => TypeNameFormat::Unchanged,
            0x07 => TypeNameFormat::Reserved,
            _ => unreachable!("type_name_format is only 3 bits"),
        };

        let type_length = get_byte!(data, "type_length");
        let payload_length: u32 = if short_record {
            get_byte!(data, "payload_length").into()
        } else {
            u32::from_be_bytes(get_bytes!(data, 4, "payload_length"))
        };
        let id_length = if id_length_present {
            Some(get_byte!(data, "id_length"))
        } else {
            None
        };
        trace!(type_length, payload_length, id_length, "got more ndef data");

        let type_data: Vec<u8> = data.by_ref().take(type_length.into()).collect();
        trace!(
            "got type data: {}, {}",
            hex::encode(&type_data),
            String::from_utf8_lossy(&type_data)
        );
        ensure_length!(type_data.len(), usize::from(type_length));

        let id_data: Option<Vec<u8>> = if let Some(id_length) = id_length {
            let id_data: Vec<u8> = data.by_ref().take(id_length.into()).collect();
            trace!(
                "got id data: {}, {}",
                hex::encode(&id_data),
                String::from_utf8_lossy(&id_data)
            );
            ensure_length!(id_data.len(), usize::from(id_length));
            Some(id_data)
        } else {
            None
        };

        let payload_data: Vec<u8> = data
            .by_ref()
            .take(payload_length.try_into().unwrap())
            .collect();
        trace!(
            "got payload_data: {}, {}",
            hex::encode(&payload_data),
            String::from_utf8_lossy(&payload_data)
        );
        ensure_length!(payload_data.len(), usize::try_from(payload_length).unwrap());

        Ok(Self {
            message_begin,
            message_end,
            chunk_flag,
            short_record,
            id_length_present,
            type_name_format,
            type_length,
            id_length,
            payload_length,
            type_data,
            id_data,
            payload_data,
        })
    }

    fn u8_to_bool(bit: u8) -> bool {
        bit > 0
    }
}

pub fn encode_record(
    begin: bool,
    end: bool,
    type_name_format: TypeNameFormat,
    type_data: &[u8],
    id_data: Option<&[u8]>,
    payload_data: &[u8],
) -> Vec<u8> {
    let mut record = Vec::new();

    let mut hdr = 0x00;
    if begin {
        hdr |= 0b10000000
    };
    if end {
        hdr |= 0b01000000
    };
    if type_data.len() < u8::MAX.into() {
        hdr |= 0b00010000
    }
    if id_data.is_some() {
        hdr |= 0b00001000
    }
    hdr |= match type_name_format {
        TypeNameFormat::Empty => 0x00,
        TypeNameFormat::WellKnown => 0x01,
        TypeNameFormat::MediaType => 0x02,
        TypeNameFormat::AbsoluteUri => 0x03,
        TypeNameFormat::External => 0x04,
        TypeNameFormat::Unknown => 0x05,
        TypeNameFormat::Unchanged => 0x06,
        TypeNameFormat::Reserved => 0x07,
    };

    record.push(hdr);
    record.push(u8::try_from(type_data.len()).unwrap());
    if payload_data.len() < u8::MAX.into() {
        record.push(u8::try_from(payload_data.len()).unwrap());
    } else {
        record.extend_from_slice(&u32::try_from(payload_data.len()).unwrap().to_be_bytes());
    }
    if let Some(id_data) = id_data {
        record.push(u8::try_from(id_data.len()).unwrap());
    }

    record.extend_from_slice(type_data);
    if let Some(id_data) = id_data {
        record.extend_from_slice(id_data);
    }
    record.extend_from_slice(payload_data);

    trace!(
        begin,
        end,
        ?type_name_format,
        type_data = hex::encode(type_data),
        id_data = ?id_data.map(hex::encode),
        payload_data = hex::encode(payload_data),
        "encoded ndef data: {}",
        hex::encode(&record)
    );

    record
}

#[instrument(skip_all)]
pub fn merge_messages(records: Vec<Vec<u8>>) -> Vec<u8> {
    trace!(len = records.len(), "merging ndef records");
    let mut records = records.into_iter().peekable();

    let mut data = Vec::new();
    let mut first = true;
    while let Some(mut record) = records.next() {
        let Some(hdr) = record.get_mut(0) else {
            error!("empty ndef record");
            continue;
        };

        let is_last_record = records.peek().is_none();

        *hdr &= 0b00111111;
        if first {
            *hdr |= 0b10000000
        }
        if is_last_record {
            *hdr |= 0b01000000
        }

        let hdr = *hdr;

        trace!(
            first,
            is_last_record,
            "updated ndef record header: {hdr:08b}, {}",
            hex::encode(&record)
        );

        data.extend_from_slice(&record);
        first = false;
    }

    data
}
