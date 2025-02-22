use eyre::OptionExt;
use strum::FromRepr;
use tracing::trace;
use uuid::Uuid;

use super::{IntoNdefRecord, RawNdefRecord, TypeNameFormat, encode_record, merge_messages};

#[derive(Debug)]
pub struct HandoverRequest {
    pub version: u8,
    pub collision_resolution: u16,
    pub alternative_carriers: Vec<AlternativeCarrier>,
}

impl IntoNdefRecord for HandoverRequest {
    fn ndef_record(self) -> Vec<u8> {
        let mut records = vec![
            CollisionResolution {
                value: self.collision_resolution,
            }
            .ndef_record(),
        ];

        for alt_carrier in self.alternative_carriers {
            records.push(alt_carrier.ndef_record());
        }

        let mut data = vec![self.version];
        data.extend_from_slice(&merge_messages(records));

        encode_record(true, true, TypeNameFormat::WellKnown, b"Hr", None, &data)
    }
}

#[derive(Debug)]
pub struct CollisionResolution {
    value: u16,
}

impl IntoNdefRecord for CollisionResolution {
    fn ndef_record(self) -> Vec<u8> {
        encode_record(
            true,
            true,
            TypeNameFormat::WellKnown,
            b"cr",
            None,
            &self.value.to_be_bytes(),
        )
    }
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct HandoverSelect {
    pub version: u8,
    pub alternative_carriers: Vec<AlternativeCarrier>,
}

impl HandoverSelect {
    pub fn decode(data: &[u8]) -> eyre::Result<Self> {
        let mut data = data.iter().copied();
        let version = data.next().ok_or_eyre("missing version byte")?;

        let record = RawNdefRecord::decode_single(&mut data)?;

        let mut data = record.payload_data.into_iter();

        let mut alternative_carriers = Vec::new();

        let carrier_power_state_byte =
            data.next().ok_or_eyre("missing carrier_power_state byte")?;
        let carrier_power_state =
            CarrierPowerState::from_repr(carrier_power_state_byte & 0b0000011)
                .ok_or_eyre("carrier_power_state byte must be known")?;
        trace!(?carrier_power_state);

        let carrier_data_ref_len = data.next().ok_or_eyre("missing carrier_ref_len byte")?;
        trace!(carrier_data_ref_len);
        let carrier_data_reference: Vec<_> =
            data.by_ref().take(carrier_data_ref_len as usize).collect();
        eyre::ensure!(
            carrier_data_reference.len() == usize::from(carrier_data_ref_len),
            "not enough bytes to fill carrier_data_ref"
        );
        trace!(carrier_data_reference = hex::encode(&carrier_data_reference));

        let aux_data_ref_count = data.next().ok_or_eyre("missing aux_data_ref_count byte")?;
        trace!(aux_data_ref_count);
        let mut auxiliary_data_references: Vec<_> = Vec::with_capacity(aux_data_ref_count.into());

        for _ in 0..aux_data_ref_count {
            let aux_data_ref_len = data.next().ok_or_eyre("missing aux_data_ref_len byte")?;
            trace!(aux_data_ref_len);
            let aux_data_ref: Vec<_> = data.by_ref().take(aux_data_ref_len.into()).collect();
            eyre::ensure!(
                aux_data_ref.len() == usize::from(aux_data_ref_len),
                "not enough bytes to fill aux_data_ref"
            );
            trace!(aux_data_ref = hex::encode(&aux_data_ref));
            auxiliary_data_references.push(aux_data_ref);
        }

        alternative_carriers.push(AlternativeCarrier {
            carrier_power_state,
            carrier_data_reference,
            auxiliary_data_references,
        });

        Ok(HandoverSelect {
            version,
            alternative_carriers,
        })
    }
}

#[derive(Clone, Debug)]
pub struct AlternativeCarrier {
    pub carrier_power_state: CarrierPowerState,
    pub carrier_data_reference: Vec<u8>,
    pub auxiliary_data_references: Vec<Vec<u8>>,
}

impl IntoNdefRecord for AlternativeCarrier {
    fn ndef_record(self) -> Vec<u8> {
        let mut data = vec![
            self.carrier_power_state as u8,
            u8::try_from(self.carrier_data_reference.len()).unwrap(),
        ];
        data.extend_from_slice(&self.carrier_data_reference);

        data.push(u8::try_from(self.auxiliary_data_references.len()).unwrap());
        for aux_ref in self.auxiliary_data_references {
            data.push(u8::try_from(aux_ref.len()).unwrap());
            data.extend_from_slice(&aux_ref);
        }

        encode_record(true, true, TypeNameFormat::WellKnown, b"ac", None, &data)
    }
}

#[derive(FromRepr, Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum CarrierPowerState {
    Inactive = 0x00,
    Active = 0x01,
    Activating = 0x02,
    Unknown = 0x03,
}

#[allow(dead_code)]
#[derive(FromRepr, Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum BLERole {
    Peripheral = 0x00,
    Central = 0x01,
    PeripheralCentral = 0x02,
    CentralPeripheral = 0x03,
}

#[derive(Clone, Debug)]
pub struct CarrierConfiguration {
    pub type_name: Vec<u8>,
    pub id_data: Vec<u8>,
    pub payload: Vec<u8>,
}

impl IntoNdefRecord for CarrierConfiguration {
    fn ndef_record(self) -> Vec<u8> {
        encode_record(
            true,
            true,
            TypeNameFormat::MediaType,
            &self.type_name,
            Some(&self.id_data),
            &self.payload,
        )
    }
}

#[derive(Clone, Debug)]
pub struct BLECarrierConfiguration {
    data: Vec<(u8, Vec<u8>)>,
}

impl BLECarrierConfiguration {
    pub const RECORD_TYPE_NAME: &str = "application/vnd.bluetooth.le.oob";

    pub fn new(le_role: BLERole, service_address: Uuid) -> Self {
        Self {
            data: vec![
                (0x1C, vec![le_role as u8]),
                (
                    0x07,
                    service_address.as_bytes().iter().copied().rev().collect(),
                ),
            ],
        }
    }

    pub fn decode(data: &[u8]) -> eyre::Result<Self> {
        let mut data = data.iter().copied();

        let mut data_type_blocks = Vec::new();

        while let Some(data_length) = data.next() {
            let data_type = data.next().ok_or_eyre("missing data_type byte")?;
            // data length includes the length of the type byte
            let block_data: Vec<_> = data.by_ref().take(data_length as usize - 1).collect();
            trace!(
                data_length = hex::encode(data_length.to_be_bytes()),
                data_type = hex::encode(data_type.to_be_bytes()),
                block_data = hex::encode(&block_data)
            );
            eyre::ensure!(
                block_data.len() == data_length as usize - 1,
                "missing bytes from block_dtaa"
            );
            data_type_blocks.push((data_type, block_data));
        }

        Ok(Self {
            data: data_type_blocks,
        })
    }

    pub fn carrier_configuration(self) -> CarrierConfiguration {
        CarrierConfiguration {
            type_name: Self::RECORD_TYPE_NAME.as_bytes().to_vec(),
            id_data: b"0".to_vec(),
            payload: self.encode(),
        }
    }

    pub fn encode(self) -> Vec<u8> {
        let mut buf = Vec::new();

        for (data_type, data_value) in self.data {
            buf.push(u8::try_from(data_value.len() + 1).unwrap());
            buf.push(data_type);
            buf.extend_from_slice(&data_value);
        }

        buf
    }

    #[allow(dead_code)]
    pub fn get_by_type(&self, wanted_type: u8) -> Option<&[u8]> {
        self.data.iter().find_map(|(data_type, data_value)| {
            (*data_type == wanted_type).then_some(data_value.as_slice())
        })
    }

    #[allow(dead_code)]
    pub fn le_role(&self) -> Option<BLERole> {
        self.get_by_type(0x1C)
            .and_then(|data| data.first())
            .copied()
            .and_then(BLERole::from_repr)
    }

    #[allow(dead_code)]
    pub fn service_uuid(&self) -> Option<Uuid> {
        self.get_by_type(0x07)
            .and_then(|data| Uuid::from_slice(&data.iter().copied().rev().collect::<Vec<_>>()).ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alternative_carrier_ndef_record() {
        let alt_carrier = AlternativeCarrier {
            carrier_power_state: CarrierPowerState::Active,
            carrier_data_reference: b"test".to_vec(),
            auxiliary_data_references: vec![],
        }
        .ndef_record();
        assert_eq!(alt_carrier, hex_literal::hex!("d10207616301047465737400"));

        let alt_carrier = AlternativeCarrier {
            carrier_power_state: CarrierPowerState::Active,
            carrier_data_reference: b"test".to_vec(),
            auxiliary_data_references: vec![b"ref".to_vec()],
        }
        .ndef_record();
        assert_eq!(
            alt_carrier,
            hex_literal::hex!("d1020b61630104746573740103726566")
        );
    }

    #[test]
    fn test_handover_request_ndef_record() {
        let handover_request = HandoverRequest {
            version: 0x15,
            collision_resolution: u16::MAX,
            alternative_carriers: vec![],
        }
        .ndef_record();
        println!("{}", hex::encode(&handover_request));
        assert_eq!(
            handover_request,
            hex_literal::hex!("d10208487215d102026372ffff")
        );

        let handover_request = HandoverRequest {
            version: 0x15,
            collision_resolution: u16::MAX,
            alternative_carriers: vec![AlternativeCarrier {
                carrier_power_state: CarrierPowerState::Active,
                carrier_data_reference: b"test".to_vec(),
                auxiliary_data_references: vec![],
            }],
        }
        .ndef_record();
        assert_eq!(
            handover_request,
            hex_literal::hex!("d102144872159102026372ffff510207616301047465737400")
        );

        let handover_request = HandoverRequest {
            version: 0x15,
            collision_resolution: u16::MAX,
            alternative_carriers: vec![AlternativeCarrier {
                carrier_power_state: CarrierPowerState::Active,
                carrier_data_reference: b"ref".to_vec(),
                auxiliary_data_references: vec![b"aux".to_vec()],
            }],
        }
        .ndef_record();
        assert_eq!(
            handover_request,
            hex_literal::hex!("d102174872159102026372ffff51020a616301037265660103617578")
        );
    }

    #[test]
    fn test_ble_carrier_configuration_decode() {
        let config = BLECarrierConfiguration::decode(&hex_literal::hex!(
            "021c001107011945ca1e8dfc889e434ea5a511b834"
        ))
        .unwrap();
        assert_eq!(
            config.data,
            vec![
                (0x1C, vec![0x00]),
                (
                    0x07,
                    hex_literal::hex!("011945ca1e8dfc889e434ea5a511b834").to_vec()
                )
            ]
        )
    }

    #[test]
    fn test_ble_carrier_configuration_encode() {
        let data = BLECarrierConfiguration {
            data: vec![
                (0x1C, vec![0x00]),
                (
                    0x07,
                    hex_literal::hex!("011945ca1e8dfc889e434ea5a511b834").to_vec(),
                ),
            ],
        };
        assert_eq!(
            data.encode(),
            hex_literal::hex!("021c001107011945ca1e8dfc889e434ea5a511b834")
        );
    }

    #[test]
    fn test_ble_carrier_configuration_helpers() {
        let config = BLECarrierConfiguration {
            data: vec![
                (0x1C, vec![0x00]),
                (
                    0x07,
                    hex_literal::hex!("011945ca1e8dfc889e434ea5a511b834").to_vec(),
                ),
            ],
        };

        assert_eq!(config.le_role(), Some(BLERole::Peripheral));
        assert_eq!(
            config.service_uuid(),
            Some(uuid::uuid!("ca451901-8d1e-88fc-9e43-4ea5a511b834"))
        );
    }
}
