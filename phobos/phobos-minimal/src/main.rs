//! PHOBOS Minimal
//! TCP -> X.224 -> TLS -> CredSSP/NTLM -> FENIX -> EXIT
//! No RDP session, desktop, graphics, audio or virtual channels.

mod forensic_log;
mod honeypot_config;

use std::error::Error;
use std::fs::OpenOptions;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use ironrdp_acceptor::{Acceptor, BeginResult, DesktopSize};
use ironrdp_pdu::nego::SecurityProtocol;
use ironrdp_pdu::rdp::client_info::Credentials;
use ironrdp_tokio::TokioFramed;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tokio_rustls::rustls;
use tokio_rustls::rustls::pki_types::pem::PemObject as _;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::TlsAcceptor;
use x509_cert::der::Decode as _;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_CONNECTIONS: usize = 4;

fn load_tls(
    cert_path: &Path,
    key_path: &Path,
) -> Result<(TlsAcceptor, Vec<u8>)> {
    let certs = CertificateDer::pem_file_iter(cert_path)
        .context("cannot read TLS certificate")?
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("invalid TLS certificate")?;

    let key = PrivateKeyDer::from_pem_file(key_path)
        .context("cannot read TLS private key")?;

    let cert = certs.first().context("empty certificate chain")?;

    let parsed = x509_cert::Certificate::from_der(cert)
        .context("cannot parse X.509 certificate")?;

    let public_key = parsed
        .tbs_certificate()
        .subject_public_key_info()
        .subject_public_key
        .as_bytes()
        .context("invalid certificate public key")?
        .to_vec();

    let tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("invalid TLS certificate/key pair")?;

    Ok((
        TlsAcceptor::from(Arc::new(tls_config)),
        public_key,
    ))
}

fn check_forensic_log() -> Result<()> {
    let path = std::env::var("RDP_HONEYPOT_LOG")
        .unwrap_or_else(|_| {
            "/var/log/rdp-honeypot/events.jsonl".into()
        });

    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("PHOBOS: log unavailable: {path}"))?;

    file.sync_all()
        .context("PHOBOS: log synchronization failed")?;

    Ok(())
}

fn fenix_capture(
    peer: SocketAddr,
    error: &(dyn Error + 'static),
) {
    let mut current = Some(error);

    while let Some(err) = current {
        if let Some(auth_error) =
            err.downcast_ref::<
                ironrdp_acceptor::credssp::CredsspAuthError
            >()
        {
            if !auth_error
                .error
                .to_string()
                .contains("FENIX_IDENTITY_CAPTURED")
            {
                return;
            }

            let Some(attempt) = auth_error.auth_attempt.as_ref()
            else {
                eprintln!("FENIX: identity marker without identity");
                std::process::exit(1);
            };

            let result = forensic_log::log_auth_attempt(
                Some(peer),
                &attempt.username,
                &attempt.domain,
                "failure",
                "FENIX_IDENTITY_CAPTURED",
            );

            match result {
                Ok(()) => {
                    eprintln!("FENIX: identity captured and saved");
                    std::process::exit(0);
                }
                Err(error) => {
                    eprintln!("FENIX: forensic write failed: {error}");
                    std::process::exit(1);
                }
            }
        }

        current = err.source();
    }
}

async fn handle_connection(
    stream: TcpStream,
    peer: SocketAddr,
    tls: &TlsAcceptor,
    public_key: &[u8],
    identity: sspi::ntlm::NtlmServerIdentity,
) -> Result<()> {
    let mut acceptor = Acceptor::new(
        SecurityProtocol::HYBRID | SecurityProtocol::HYBRID_EX,
        DesktopSize {
            width: 1024,
            height: 768,
        },
        Vec::new(),
        Some(Credentials {
            username: String::new(),
            password: String::new(),
            domain: None,
        }),
    );

    acceptor.set_server_identity(identity);

    let framed = TokioFramed::new(stream);

    let result = ironrdp_acceptor::accept_begin(
        framed,
        &mut acceptor,
    )
    .await
    .context("RDP negotiation failed")?;

    let stream = match result {
        BeginResult::ShouldUpgrade(stream) => stream,

        BeginResult::Continue(_) => {
            bail!("PHOBOS requires TLS and CredSSP");
        }
    };

    let tls_stream = tls
        .accept(stream)
        .await
        .context("TLS handshake failed")?;

    let mut framed = TokioFramed::new(tls_stream);

    acceptor.mark_security_upgrade_as_done();

    // Only CredSSP. Never continue into RDP finalization.
    let result = ironrdp_acceptor::accept_credssp(
        &mut framed,
        &mut acceptor,
        &mut ironrdp_tokio::reqwest::ReqwestNetworkClient::new(),
        "rdp-client".to_owned().into(),
        public_key.to_vec(),
        None,
    )
    .await;

    if let Err(ref error) = result {
        fenix_capture(peer, error);
    }

    match result {
        Ok(()) => {
            // Even unexpected authentication success cannot create a session.
            eprintln!("PHOBOS: authentication completed, session denied");
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let local = tokio::task::LocalSet::new();

    local.run_until(async {
    let args: Vec<String> = std::env::args().collect();

    anyhow::ensure!(
        args.len() == 5,
        "Usage: phobos-minimal <bind> <cert.pem> <key.pem> <config>"
    );

    let bind_addr: SocketAddr = args[1]
        .parse()
        .context("invalid bind address")?;

    let (tls, public_key) = load_tls(
        Path::new(&args[2]),
        Path::new(&args[3]),
    )?;

    let config = honeypot_config::HoneypotConfig::load(
        Path::new(&args[4]),
    )?;

    check_forensic_log()?;

    let identity = config.ntlm_identity();

    let listener = TcpListener::bind(bind_addr)
        .await
        .context("cannot bind PHOBOS listener")?;

    println!("PHOBOS Minimal listening on {bind_addr}");

    let semaphore = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let public_key = Arc::new(public_key);

    println!("PHOBOS: maximum concurrent connections: {MAX_CONNECTIONS}");

    loop {
        let (stream, peer) = listener.accept().await?;

        // Do not queue unlimited pending connections.
        let permit = match semaphore.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                eprintln!("PHOBOS: connection limit reached, rejecting {peer}");
                drop(stream);
                continue;
            }
        };

        println!("PHOBOS connection: {peer}");

        let tls = tls.clone();
        let public_key = Arc::clone(&public_key);
        let identity = identity.clone();

        tokio::task::spawn_local(async move {
            // Permit is held until this connection finishes.
            let _permit = permit;

            let result = timeout(
                HANDSHAKE_TIMEOUT,
                handle_connection(
                    stream,
                    peer,
                    &tls,
                    public_key.as_slice(),
                    identity,
                ),
            )
            .await;

            match result {
                Ok(Ok(())) => {
                    eprintln!("PHOBOS: connection closed: {peer}");
                }
                Ok(Err(error)) => {
                    eprintln!("PHOBOS: handshake failed: {peer}: {error}");
                }
                Err(_) => {
                    eprintln!("PHOBOS: handshake timeout: {peer}");
                }
            }
        });
    }
    }).await
}
