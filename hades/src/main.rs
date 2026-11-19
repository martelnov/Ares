//! Local-only HADES protocol prototype.
//! NOT READY FOR HONEYPOT DEPLOYMENT: local-only authentication prototype; no IPC.
use hades::forensic::{open_evidence, persist_login};
use hades::tds::login7::Login7;
use hades::tds::packet::{read_login7, read_prelogin, response_packet};
use hades::tds::prelogin::{response_payload, response_payload_with_encryption, Prelogin};
use hades::tds::response::login_failed_response;
use hades::tls::{config_from_pem, negotiate_tds7_tls};
use rustls::ServerConfig;
use std::error::Error;
use std::fs::File;
use std::io::Write;
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use zeroize::Zeroizing;

fn handle(
    mut conn: TcpStream,
    tls: Option<Arc<ServerConfig>>,
    forensic: Option<&mut File>,
) -> Result<(), Box<dyn Error>> {
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
        let mut connection = negotiate_tds7_tls(conn, config)?;
        let bytes = Zeroizing::new(read_login7(&mut connection)?);
        let login = Login7::parse(&bytes)?;
        let peer = connection.sock.peer_addr()?;
        let file = forensic.ok_or("TLS enabled without a forensic evidence sink")?;
        // The evidence must reach stable storage before the server responds.
        let evidence_id = persist_login(file, peer, &login)?;
        eprintln!("LOGIN7 captured peer={peer} evidence_id={evidence_id}");
        connection.write_all(&login_failed_response()?)?;
        connection.flush()?;
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
    // Fail closed: accepting LOGIN7 requires TLS and a durable evidence sink.
    let log_path = std::env::var("HADES_FORENSIC_JSONL").ok();
    if tls.is_some() != log_path.is_some() {
        return Err("HADES_TLS_CERT/KEY and HADES_FORENSIC_JSONL must all be set, or none".into());
    }
    let mut forensic = match log_path {
        Some(path) => Some(open_evidence(Path::new(&path))?),
        None => None,
    };
    let listener = TcpListener::bind(address)?;
    eprintln!("HADES experimental local-only listener on {bind}");
    eprintln!("WARNING: not production-ready; no ARES IPC or concurrent sessions");
    for connection in listener.incoming() {
        match connection {
            Ok(conn) => {
                if let Err(err) = handle(conn, tls.clone(), forensic.as_mut()) {
                    eprintln!("connection rejected: {err}");
                }
            }
            Err(err) => eprintln!("accept failed: {err}"),
        }
    }
    Ok(())
}
