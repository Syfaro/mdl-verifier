use std::{ffi::OsStr, path::PathBuf, time::Duration};

use clap::Parser;
use futures::Stream;
use tokio::{
    io::AsyncReadExt,
    select,
    sync::mpsc::{Sender, channel},
    time::interval,
};
use tokio_serial::{SerialPortBuilderExt, SerialStream};
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, level_filters::LevelFilter};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
struct Config {
    #[clap(short = 'l', long, env = "RUST_LOG")]
    rust_log: Option<String>,

    #[clap(short = 'c', long, env)]
    certificates_path: PathBuf,
    #[clap(short = 't', long, env, default_value = "120")]
    timeout: u64,

    #[clap(short = 'n', long, env)]
    nfc_connstring: Option<String>,

    #[clap(short = 's', long, env)]
    scanner_path: Option<String>,
    #[clap(short = 'b', long, env, default_value = "115200")]
    scanner_baud: u32,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = Config::parse();

    tracing_subscriber::fmt::fmt()
        .pretty()
        .with_env_filter(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .parse_lossy(config.rust_log.unwrap_or_default()),
        )
        .init();

    let certificates = load_certificates(config.certificates_path).await?;

    let elements = [(
        "org.iso.18013.5.1".to_string(),
        [("age_over_21".to_string(), false)].into_iter().collect(),
    )]
    .into_iter()
    .collect();

    let mut verifier = mdl_verifier::MdlVerifier::new(certificates, elements, config.timeout)?;

    if let Some(scanner_path) = config.scanner_path {
        let scanner_stream = create_scanner_stream(scanner_path, config.scanner_baud).await?;
        verifier.add_qr_stream(scanner_stream);
    }

    if let Some(nfc_connstring) = config.nfc_connstring {
        verifier.add_nfc_stream(nfc_connstring)?;
    }

    let token = CancellationToken::new();
    let mut events = verifier.start(token).await?;

    while let Some(event) = events.recv().await {
        info!("got event: {event:?}");
    }

    Ok(())
}

async fn load_certificates(path: PathBuf) -> anyhow::Result<Vec<String>> {
    let mut certificate_pem_data = Vec::new();

    let mut entries = tokio::fs::read_dir(path).await?;
    while let Ok(Some(file)) = entries.next_entry().await {
        if file.path().extension() != Some(OsStr::new("pem")) {
            continue;
        }

        debug!(path = %file.path().display(), "loading certificate");
        let mut file = tokio::fs::File::open(file.path()).await?;

        let mut data = String::new();
        file.read_to_string(&mut data).await?;
        certificate_pem_data.push(data);
    }

    Ok(certificate_pem_data)
}

async fn create_scanner_stream(
    path: String,
    baud: u32,
) -> anyhow::Result<impl Stream<Item = String>> {
    let port = tokio_serial::new(&path, baud).open_native_async()?;
    let (tx, rx) = channel(1);
    tokio::spawn(scanner_loop(port, tx));

    Ok(ReceiverStream::new(rx))
}

async fn scanner_loop(mut port: SerialStream, tx: Sender<String>) {
    let mut interval = interval(Duration::from_millis(50));
    let mut str_buf = String::new();
    let mut buf = [0u8; 4096];

    loop {
        select! {
            _ = interval.tick() => {
                if str_buf.is_empty() {
                    continue;
                }

                let final_value = std::mem::take(&mut str_buf);
                let final_value = final_value.trim_end_matches(['\r', '\n']).to_string();

                debug!("sending scanner value: {final_value}");
                tx.send(final_value).await.unwrap();
            }

            _ = tx.closed() => {
                break;
            }

            res = port.read(&mut buf) => {
                let size = res.unwrap();
                if size == 0 {
                    continue;
                }

                let s = String::from_utf8_lossy(&buf[0..size]);
                str_buf.push_str(&s);

                interval.reset();
            }
        }
    }
}
