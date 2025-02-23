use crate::nfc::{
    NfcError, ensure_length, get_byte, get_bytes,
    ndef::{IntoNdefRecord, TypeNameFormat, encode_record},
};

#[derive(Clone, Debug)]
pub struct ServiceParameter {
    pub version: u8,
    pub service_name: String,
    pub tnep_communication_mode: u8,
    pub minimum_waiting_time: u8,
    pub maximum_waiting_time_extensions: u8,
    pub maximum_message_size: u16,
}

impl ServiceParameter {
    pub fn decode(data: &[u8]) -> Result<Self, NfcError> {
        let mut data = data.iter().copied();

        let version = get_byte!(data, "version");

        let service_name_len = get_byte!(data, "service_name_len");
        let service_name: Vec<u8> = data.by_ref().take(service_name_len.into()).collect();
        ensure_length!(service_name.len(), usize::from(service_name_len));
        let service_name = String::from_utf8_lossy(&service_name).to_string();

        let tnep_communication_mode = get_byte!(data, "tnep_communication_mode");
        let minimum_waiting_time = get_byte!(data, "minimum_waiting_time");
        let maximum_waiting_time_extensions = get_byte!(data, "maximum_waiting_time_extensions");

        let maximum_message_size =
            u16::from_be_bytes(get_bytes!(data, 2, "maximum_message_size_bytes"));

        Ok(ServiceParameter {
            version,
            service_name,
            tnep_communication_mode,
            minimum_waiting_time,
            maximum_waiting_time_extensions,
            maximum_message_size,
        })
    }

    pub fn wait_time_seconds(&self) -> f32 {
        (2.0_f32).powf((self.minimum_waiting_time / 4 - 1).into()) / 1000.0
    }
}

#[derive(Clone, Debug)]
pub struct ServiceSelect {
    pub service_name: String,
}

impl IntoNdefRecord for ServiceSelect {
    fn ndef_record(mut self) -> Vec<u8> {
        let name_len = u8::try_from(self.service_name.len()).unwrap();
        self.service_name.insert(0, name_len as char);

        encode_record(
            true,
            true,
            TypeNameFormat::WellKnown,
            b"Ts",
            None,
            self.service_name.as_bytes(),
        )
    }
}

#[derive(Clone, Debug)]
pub enum Status {
    Success,
    Unknown(u8),
}

impl Status {
    pub fn from_repr(repr: u8) -> Result<Self, NfcError> {
        match repr {
            0x00 => Ok(Self::Success),
            other => Err(NfcError::UnexpectedBytes {
                expected: vec![0x00],
                got: vec![other],
            }),
        }
    }

    pub fn decode(data: &[u8]) -> Result<Self, NfcError> {
        ensure_length!(data.len(), 1);
        Self::from_repr(data[0])
    }
}

impl std::fmt::Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Success => write!(f, "tnep success"),
            Self::Unknown(val) => write!(f, "tnep unknown: {val:02x}"),
        }
    }
}
