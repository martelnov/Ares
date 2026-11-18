//! Local-only HADES protocol prototype.
//! NOT READY FOR HONEYPOT DEPLOYMENT: no network LOGIN7, forensics or IPC.
use hades::tds::packet::{read_prelogin, response_packet};
use hades::tds::prelogin::{response_payload, response_payload_with_encryption, Prelogin};
use hades::tls::{config_from_pem, negotiate_tds7_tls};
use rustls::ServerConfig;
use std::error::Error;
use std::io::Write;
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

fn handle(mut conn: TcpStream, tls: Option<Arc<ServerConfig>>) -> Result<(), Box<dyn Error>> {
    conn.set_read_timeout(Some(Duration::from_secs(5)))?;
    conn.set_write_timeout(Some(Duration::from_secs(5)))?;
    let request = read_prelogin(&mut conn)?;
    let prelogin = Prelogin::parse(&request)?;
    eprintln!(
        "PRELOGIN received peer={} version={:?} encryption={:?} mars={:?}",
        conn.peer_addr()?,
        prelogin.version,
        prelogin.encryption,
        prelogin.mars
    );
    let payload = if tls.is_some() {
        response_payload_with_encryption(&prelogin, 3)
    } else {
        response_payload(&prelogin)
    };
    conn.write_all(&response_packet(&payload)?)?;
    if let Some(config) = tls {
        // 0.2c milestone: finish TLS handshake, then close without reading
        // LOGIN7, printing credentials or claiming a successful login.
        let connection = negotiate_tds7_tls(conn, config)?;
        eprintln!("local TLS handshake completed; no credentials accepted");
        let _ = connection.sock.shutdown(Shutdown::Both);
    } else {
        let _ = conn.shutdown(Shutdown::Both);
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let bind = std::env::var("HADES_BIND").unwrap_or_else(|_| "127.0.0.1:11433".to_owned());
    let address: SocketAddr = bind.parse()?;
    if !address.ip().is_loopback() {
        return Err("prototype refuses non-loopback listener".into());
    }
    let tls = match (
        std::env::var("HADES_TLS_CERT"),
        std::env::var("HADES_TLS_KEY"),
    ) {
        (Ok(cert), Ok(key)) => Some(config_from_pem(Path::new(&cert), Path::new(&key))?),
        (Err(_), Err(_)) => None,
        _ => return Err("set both HADES_TLS_CERT and HADES_TLS_KEY or neither".into()),
    };
    let listener = TcpListener::bind(address)?;
    eprintln!("HADES PRELOGIN+optional-TLS local prototype on {bind}");
    eprintln!("WARNING: no authentication, credential capture, forensics or ARES IPC yet");
    for connection in listener.incoming() {
        match connection {
            Ok(conn) => {
                if let Err(err) = handle(conn, tls.clone()) {
                    eprintln!("connection rejected: {err}");
                }
            }
            Err(err) => eprintln!("accept failed: {err}"),
        }
    }
    Ok(())
}
