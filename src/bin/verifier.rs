use std::{path::PathBuf, time::Duration};

use clap::Parser;
use futures::Stream;
use tokio::io::AsyncReadExt;
use tokio_serial::SerialPortBuilderExt;
use tracing::{debug, info};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
struct Config {
    #[clap(short = 'c', long)]
    certificates_path: PathBuf,

    #[clap(short = 'n', long)]
    nfc_connstring: Option<String>,

    #[clap(short = 's', long)]
    scanner_path: String,
    #[clap(short = 'b', long, default_value = "115200")]
    scanner_baud: u32,
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    if std::env::var_os("RUST_LOG").is_none() {
        unsafe { std::env::set_var("RUST_LOG", "info,btleplug=warn,mdl_verifier=debug") }
    }

    tracing_subscriber::fmt::fmt()
        .pretty()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let config = Config::parse();

    let scanner_stream = create_scanner_stream(config.scanner_path, config.scanner_baud).await?;

    let mut events = mdl_verifier::start(
        mdl_verifier::Config {
            certificate_pem_data: Vec::new(),
            nfc_connstring: config.nfc_connstring,
        },
        scanner_stream,
    )
    .await?;

    while let Some(event) = events.recv().await {
        info!("got event: {event:?}");
    }

    Ok(())
}

async fn create_scanner_stream(
    path: String,
    baud: u32,
) -> eyre::Result<impl Stream<Item = String>> {
    let (tx, rx) = tokio::sync::mpsc::channel(1);

    let mut port = tokio_serial::new(&path, baud).open_native_async()?;

    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_millis(50));
        let mut str_buf = String::new();
        let mut buf = [0u8; 4096];

        loop {
            tokio::select! {
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
    });

    Ok(tokio_stream::wrappers::ReceiverStream::new(rx))
}
