use std::{
    env,
    error::Error,
    fs, io,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

type DynError = Box<dyn Error + Send + Sync + 'static>;

const ALPN: &[u8] = b"hq-29";
const DEFAULT_BIND: &str = "0.0.0.0:4433";
const DEFAULT_PROBE_ADDR: &str = "127.0.0.1:4433";
const DEFAULT_MAX_CONNECTIONS: usize = 1024;
const MAX_STREAM_BYTES: usize = 64 * 1024;
const IDLE_TIMEOUT: Duration = Duration::from_secs(10);
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const PROBE_PAYLOAD: &[u8] = b"offbywon-quic-probe";

#[tokio::main]
async fn main() -> Result<(), DynError> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    match env::args().nth(1).as_deref() {
        None | Some("serve") => serve().await,
        Some("probe") => probe().await,
        Some("--help") | Some("-h") => {
            print_help();
            Ok(())
        }
        Some(command) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unknown command {command:?}; expected 'serve' or 'probe'"),
        )
        .into()),
    }
}

fn print_help() {
    println!(
        "OffByWon Quinn fuzzing target\n\n\
         Usage:\n  offbywon-quic-server serve\n  offbywon-quic-server probe\n\n\
         Environment:\n\
           OFFBYWON_QUIC_BIND             listen address (default {DEFAULT_BIND})\n\
           OFFBYWON_QUIC_PROBE_ADDR       probe destination (default {DEFAULT_PROBE_ADDR})\n\
           OFFBYWON_QUIC_STATE_DIR        certificate directory (default ./state)\n\
           OFFBYWON_QUIC_MAX_CONNECTIONS  connection cap (default {DEFAULT_MAX_CONNECTIONS})\n\
           OFFBYWON_QUIC_LOG_FAILURES     log failed handshakes when set to 1"
    );
}

async fn serve() -> Result<(), DynError> {
    let bind: SocketAddr = env_value("OFFBYWON_QUIC_BIND", DEFAULT_BIND).parse()?;
    let max_connections = env_value(
        "OFFBYWON_QUIC_MAX_CONNECTIONS",
        &DEFAULT_MAX_CONNECTIONS.to_string(),
    )
    .parse::<usize>()?;
    if max_connections == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "OFFBYWON_QUIC_MAX_CONNECTIONS must be greater than zero",
        )
        .into());
    }

    let log_failures = env::var("OFFBYWON_QUIC_LOG_FAILURES").as_deref() == Ok("1");
    let state_dir = state_dir();
    let (certificate, private_key) = load_or_create_identity(&state_dir)?;

    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certificate], private_key)?;
    server_crypto.alpn_protocols = vec![ALPN.to_vec()];

    let mut server_config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_crypto)?));
    let transport = Arc::get_mut(&mut server_config.transport)
        .expect("new server configuration unexpectedly shared");
    transport.max_idle_timeout(Some(IDLE_TIMEOUT.try_into()?));
    transport.max_concurrent_uni_streams(0_u8.into());

    let endpoint = quinn::Endpoint::server(server_config, bind)?;
    eprintln!(
        "OffByWon QUIC target listening on {} (ALPN {}, max connections {})",
        endpoint.local_addr()?,
        String::from_utf8_lossy(ALPN),
        max_connections
    );

    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            _ = &mut shutdown => {
                eprintln!("shutdown requested");
                break;
            }
            maybe_incoming = endpoint.accept() => {
                let Some(incoming) = maybe_incoming else {
                    break;
                };

                if endpoint.open_connections() >= max_connections {
                    incoming.refuse();
                    continue;
                }

                let remote = incoming.remote_address();
                tokio::spawn(async move {
                    match incoming.await {
                        Ok(connection) => {
                            eprintln!("connection established from {remote}");
                            if let Err(error) = handle_connection(connection).await {
                                eprintln!("connection {remote} ended: {error}");
                            }
                        }
                        Err(error) if log_failures => {
                            eprintln!("handshake from {remote} failed: {error}");
                        }
                        Err(_) => {}
                    }
                });
            }
        }
    }

    endpoint.close(0_u32.into(), b"server shutdown");
    endpoint.wait_idle().await;
    Ok(())
}

async fn handle_connection(connection: quinn::Connection) -> Result<(), DynError> {
    loop {
        let (mut send, mut receive) = match connection.accept_bi().await {
            Ok(streams) => streams,
            Err(quinn::ConnectionError::ApplicationClosed { .. }) => return Ok(()),
            Err(error) => return Err(error.into()),
        };

        tokio::spawn(async move {
            let result = async {
                let payload = receive.read_to_end(MAX_STREAM_BYTES).await?;
                send.write_all(&payload).await?;
                send.finish()?;
                Ok::<(), DynError>(())
            }
            .await;

            if let Err(error) = result {
                eprintln!("stream failed: {error}");
            }
        });
    }
}

async fn probe() -> Result<(), DynError> {
    let state_dir = state_dir();
    let cert_path = state_dir.join("cert.der");
    let certificate = CertificateDer::from(fs::read(&cert_path).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("failed to read {}: {error}", cert_path.display()),
        )
    })?);

    let mut roots = rustls::RootCertStore::empty();
    roots.add(certificate)?;
    let mut client_crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![ALPN.to_vec()];

    let client_config =
        quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_crypto)?));
    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse()?)?;
    endpoint.set_default_client_config(client_config);

    let remote: SocketAddr = env_value("OFFBYWON_QUIC_PROBE_ADDR", DEFAULT_PROBE_ADDR).parse()?;
    let connecting = endpoint.connect(remote, "localhost")?;
    let connection = tokio::time::timeout(PROBE_TIMEOUT, connecting)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "QUIC handshake timed out"))??;

    let (mut send, mut receive) = connection.open_bi().await?;
    send.write_all(PROBE_PAYLOAD).await?;
    send.finish()?;
    let response = tokio::time::timeout(PROBE_TIMEOUT, receive.read_to_end(MAX_STREAM_BYTES))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "QUIC echo timed out"))??;

    if response != PROBE_PAYLOAD {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected echo response: {} bytes", response.len()),
        )
        .into());
    }

    connection.close(0_u32.into(), b"probe complete");
    endpoint.wait_idle().await;
    println!(
        "probe passed: QUIC handshake, ALPN {}, and bidirectional echo via {remote}",
        String::from_utf8_lossy(ALPN)
    );
    Ok(())
}

fn state_dir() -> PathBuf {
    env::var_os("OFFBYWON_QUIC_STATE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("state"))
}

fn load_or_create_identity(
    state_dir: &Path,
) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>), DynError> {
    fs::create_dir_all(state_dir)?;
    secure_state_dir(state_dir)?;

    let cert_path = state_dir.join("cert.der");
    let key_path = state_dir.join("key.der");
    match (cert_path.exists(), key_path.exists()) {
        (true, true) => {
            let certificate = CertificateDer::from(fs::read(cert_path)?);
            let private_key = PrivateKeyDer::try_from(fs::read(key_path)?)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
            Ok((certificate, private_key))
        }
        (false, false) => {
            let rcgen::CertifiedKey { cert, key_pair } = rcgen::generate_simple_self_signed(vec![
                "localhost".to_owned(),
                "127.0.0.1".to_owned(),
            ])?;
            let certificate_bytes = cert.der().to_vec();
            let private_key_bytes = key_pair.serialize_der();
            fs::write(&cert_path, &certificate_bytes)?;
            fs::write(&key_path, &private_key_bytes)?;
            secure_private_key(&key_path)?;
            eprintln!("generated identity in {}", state_dir.display());
            Ok((
                CertificateDer::from(certificate_bytes),
                PrivatePkcs8KeyDer::from(private_key_bytes).into(),
            ))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "incomplete identity in {}: cert.der and key.der must both exist",
                state_dir.display()
            ),
        )
        .into()),
    }
}

#[cfg(unix)]
fn secure_state_dir(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn secure_state_dir(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn secure_private_key(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn secure_private_key(_path: &Path) -> io::Result<()> {
    Ok(())
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};

        let mut terminate = signal(SignalKind::terminate()).expect("install SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = terminate.recv() => {}
        }
    }

    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

fn env_value(name: &str, default: &str) -> String {
    env::var(name).unwrap_or_else(|_| default.to_owned())
}
