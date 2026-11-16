//! PHOBOS - RDP authentication honeypot.
//! No desktop, input processing, audio, clipboard or RDP session.

#[path = "honeypot_config.rs"]
mod honeypot_config;

use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use ironrdp::server::{Credentials, RdpServer, TlsIdentityCtx};
use tokio::net::TcpListener;
use tokio::time::timeout;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();

    anyhow::ensure!(
        args.len() == 5,
        "Usage: phobos <bind-address> <certificate> <private-key> <config>"
    );

    let bind_addr: SocketAddr = args[1].parse()
        .context("invalid bind address")?;

    let identity = TlsIdentityCtx::init_from_paths(
        Path::new(&args[2]),
        Path::new(&args[3]),
    )?;

    let acceptor = identity.make_acceptor()?;

    let config = honeypot_config::HoneypotConfig::load(
        Path::new(&args[4]),
    )?;

    let mut server = RdpServer::builder()
        .with_addr(bind_addr)
        .with_hybrid(acceptor, identity.pub_key)
        .with_no_input()
        .with_no_display()
        .with_server_identity(config.ntlm_identity())
        .build();

    // No credential is ever authorized for an interactive session.
    server.set_credentials(Some(Credentials {
        username: String::new(),
        password: String::new(),
        domain: None,
    }));

    let listener = TcpListener::bind(bind_addr).await
        .context("failed to bind PHOBOS listener")?;

    println!("PHOBOS listening on {bind_addr}");

    loop {
        let (stream, peer) = listener.accept().await?;

        println!("PHOBOS connection: {peer}");

        // Handshake only. Never call run_connection_session().
        let result = timeout(
            Duration::from_secs(30),
            server.run_connection_handshake(stream),
        ).await;

        match result {
            Ok(Ok(pending)) => {
                // Unexpected success: close without creating a session.
                drop(pending);
                eprintln!("PHOBOS: session denied: {peer}");
            }
            Ok(Err(error)) => {
                eprintln!("PHOBOS: handshake ended: {peer}: {error}");
            }
            Err(_) => {
                eprintln!("PHOBOS: handshake timeout: {peer}");
            }
        }
    }
}
