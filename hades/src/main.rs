//! Local-only, intentionally incomplete HADES PRELOGIN test listener.
//! NOT READY FOR HONEYPOT DEPLOYMENT: no TLS, LOGIN7, credentials, JSONL or IPC.
use hades::tds::packet::{read_prelogin, response_packet};
use hades::tds::prelogin::{response_payload, Prelogin};
use std::error::Error;
use std::io::Write;
use std::net::{Shutdown, TcpListener, TcpStream};
use std::time::Duration;

fn handle(mut conn: TcpStream) -> Result<(), Box<dyn Error>> {
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
    let payload = response_payload(&prelogin);
    conn.write_all(&response_packet(&payload)?)?;
    let _ = conn.shutdown(Shutdown::Both);
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let bind = std::env::var("HADES_BIND").unwrap_or_else(|_| "127.0.0.1:11433".to_owned());
    let listener = TcpListener::bind(&bind)?;
    eprintln!("HADES PRELOGIN-only prototype on {bind}");
    eprintln!("WARNING: no authentication, TLS, forensics or ARES IPC yet");
    for connection in listener.incoming() {
        match connection {
            Ok(conn) => {
                if let Err(err) = handle(conn) {
                    eprintln!("connection rejected: {err}");
                }
            }
            Err(err) => eprintln!("accept failed: {err}"),
        }
    }
    Ok(())
}
