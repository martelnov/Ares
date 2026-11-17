//! Optional IPC channel between PHOBOS and its parent ARES.
//!
//! ARES creates an AF_UNIX/SOCK_DGRAM socketpair and passes
//! one descriptor to PHOBOS through ARES_IPC_FD.
//!
//! Without that environment variable PHOBOS runs standalone.

use std::os::fd::{FromRawFd, RawFd};
use std::os::unix::net::UnixDatagram;
use std::sync::OnceLock;

use serde_json::{Value, json};

static IPC: OnceLock<Option<UnixDatagram>> = OnceLock::new();

const MAX_MESSAGE_SIZE: usize = 4096;

pub fn init() {
    IPC.get_or_init(|| {
        let value = std::env::var("ARES_IPC_FD").ok()?;

        let fd: RawFd = match value.parse() {
            Ok(fd) if fd >= 3 => fd,
            _ => {
                eprintln!("PHOBOS IPC: invalid descriptor");
                return None;
            }
        };

        // SAFETY:
        // ARES transfers ownership of this inherited descriptor
        // to PHOBOS. It must refer to a Unix datagram socket.
        let socket = unsafe {
            UnixDatagram::from_raw_fd(fd)
        };

        if let Err(error) = socket.set_nonblocking(true) {
            eprintln!("PHOBOS IPC: {error}");
            return None;
        }

        eprintln!("PHOBOS IPC: ARES channel available");

        Some(socket)
    });
}

pub fn emit(event: &str, payload: Value) {
    let Some(Some(socket)) = IPC.get() else {
        return;
    };

    let message = json!({
        "version": 1,
        "event": event,
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "pid": std::process::id(),
        "data": payload
    });

    let Ok(encoded) = serde_json::to_vec(&message) else {
        return;
    };

    if encoded.len() > MAX_MESSAGE_SIZE {
        eprintln!("PHOBOS IPC: message too large");
        return;
    }

    // One nonblocking datagram per event.
    // IPC failure must never block RDP processing.
    if let Err(error) = socket.send(&encoded) {
        if error.kind() != std::io::ErrorKind::WouldBlock {
            eprintln!("PHOBOS IPC: send failed: {error}");
        }
    }
}
