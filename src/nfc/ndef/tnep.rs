use eyre::OptionExt;

use super::{IntoNdefRecord, TypeNameFormat, encode_record};

#[allow(dead_code)]
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
    pub fn decode(data: &[u8]) -> eyre::Result<Self> {
        let mut data = data.iter().copied();

        let version = data.next().ok_or_eyre("missing version byte")?;

        let service_name_len = data.next().ok_or_eyre("missing service_name_len byte")?;
        let service_name: Vec<u8> = data.by_ref().take(service_name_len.into()).collect();
        eyre::ensure!(
            service_name.len() == service_name_len.into(),
            "not enough bytes to fill service_name"
        );
        let service_name = String::from_utf8(service_name)?;

        let tnep_communication_mode = data
            .next()
            .ok_or_eyre("missing tnep_communication_mode byte")?;
        let minimum_waiting_time = data
            .next()
            .ok_or_eyre("missing minimum_waiting_time byte")?;
        let maximum_waiting_time_extensions = data
            .next()
            .ok_or_eyre("missing maximum_waiting_time_extensions byte")?;

        let maximum_message_size_bytes: [u8; 2] = data
            .take(2)
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| eyre::eyre!("not enough bytes to fill maximum_message_size_bytes"))?;
        let maximum_message_size = u16::from_be_bytes(maximum_message_size_bytes);

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

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub enum Status {
    Success,
    Unknown,
}

impl Status {
    pub fn from_repr(repr: u8) -> eyre::Result<Self> {
        match repr {
            0x00 => Ok(Self::Success),
            other => eyre::bail!("unknown status code: {other:02x}"),
        }
    }

    pub fn decode(data: &[u8]) -> eyre::Result<Self> {
        eyre::ensure!(data.len() == 1, "status should only have one byte");
        Self::from_repr(data[0])
    }
}
