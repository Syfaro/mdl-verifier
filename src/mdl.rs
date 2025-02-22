use ciborium::cbor;

pub struct ReaderEngagement {
    pub version: String,
}

impl Default for ReaderEngagement {
    fn default() -> Self {
        Self {
            version: "1.0".to_string(),
        }
    }
}

impl ReaderEngagement {
    pub fn encode(self) -> Result<Vec<u8>, ciborium::value::Error> {
        let val = ciborium::cbor!({
            0 => self.version,
        })?;

        let mut data = Vec::new();
        ciborium::into_writer(&val, &mut data).unwrap();
        Ok(data)
    }
}
