use std::time::Duration;

use eyre::OptionExt;
use tracing::{error, trace};

mod mdl;
mod nfc;

fn main() -> eyre::Result<()> {
    tracing_subscriber::fmt::fmt().pretty().init();

    let connstring = std::env::args()
        .nth(1)
        .ok_or_eyre("missing nfc connstring")?;

    let mut context = nfc1::Context::new()?;
    let mut nfc_reader = nfc::NfcReader::new(&mut context, &connstring)?;

    loop {
        let info = match nfc_reader.poll_14a() {
            Ok(Some(info)) => info,
            Ok(None) => {
                trace!("no tag found");
                std::thread::sleep(Duration::from_secs(1));
                continue;
            }
            Err(err) => {
                error!("error polling nfc reader: {err}");
                break;
            }
        };

        nfc_reader.get_18013_5_device_engagement(info)?;
    }

    Ok(())
}
