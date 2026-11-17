use std::env;
use std::error::Error;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixDatagram;
use std::process::Command;
use std::time::{Duration, Instant};

use serde_json::Value;

const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_MESSAGE: usize = 4096;

fn handle_event(data: &[u8], last_heartbeat: &mut Instant) {
    let event: Value = match serde_json::from_slice(data) {
        Ok(event) => event,
        Err(error) => {
            eprintln!("ARES: invalid IPC message: {error}");
            return;
        }
    };

    let kind = event["event"].as_str().unwrap_or("UNKNOWN");

    match kind {
        "READY" => {
            *last_heartbeat = Instant::now();
            println!("ARES: PHOBOS ready");
        }

        "HEARTBEAT" => {
            *last_heartbeat = Instant::now();
            println!("ARES: PHOBOS heartbeat");
        }

        "CONNECTION" => {
            println!(
                "ARES: connection {}:{} -> {}:{}",
                event["data"]["source_ip"],
                event["data"]["source_port"],
                event["data"]["destination_ip"],
                event["data"]["destination_port"]
            );
        }

        "CAPTURED" => {
            println!("ARES: identity captured and saved");
        }

        "DISCONNECT" => {
            println!("ARES: connection disconnected");
        }

        "ERROR" => {
            eprintln!("ARES: PHOBOS reported error: {event}");
        }

        _ => {
            eprintln!("ARES: unknown event: {kind}");
        }
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = env::args_os();
    let _program = args.next();

    let phobos_exe = args.next().ok_or(
        "Usage: ares <phobos-binary> <phobos-arguments...>"
    )?;

    // Local IPC channel. No TCP port is created.
    let (parent, child) = UnixDatagram::pair()?;

    parent.set_read_timeout(Some(Duration::from_secs(1)))?;

    // dup() creates a descriptor without FD_CLOEXEC.
    // The child receives ownership of its own inherited copy.
    let fd = unsafe { libc::dup(child.as_raw_fd()) };

    if fd < 0 {
        return Err(io::Error::last_os_error().into());
    }

    let inherited = unsafe { OwnedFd::from_raw_fd(fd) };

    let mut command = Command::new(phobos_exe);

    command
        .args(args)
        .env("ARES_IPC_FD", inherited.as_raw_fd().to_string());

    let mut phobos = command.spawn()?;

    drop(child);
    drop(inherited);

    println!("ARES: started");
    println!("ARES: PHOBOS PID {}", phobos.id());

    let mut last_heartbeat = Instant::now();
    let mut timeout_reported = false;
    let mut buffer = [0u8; MAX_MESSAGE];

    loop {
        match parent.recv(&mut buffer) {
            Ok(length) => {
                handle_event(&buffer[..length], &mut last_heartbeat);

                if last_heartbeat.elapsed() < HEARTBEAT_TIMEOUT {
                    timeout_reported = false;
                }
            }

            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                ) => {}

            Err(error) => {
                eprintln!("ARES: IPC error: {error}");
            }
        }

        if !timeout_reported
            && last_heartbeat.elapsed() > HEARTBEAT_TIMEOUT
        {
            eprintln!("ARES: PHOBOS heartbeat timeout");
            timeout_reported = true;
        }

        if let Some(status) = phobos.try_wait()? {
            // Collect IPC messages queued immediately before exit.
            parent.set_nonblocking(true)?;

            while let Ok(length) = parent.recv(&mut buffer) {
                handle_event(&buffer[..length], &mut last_heartbeat);
            }

            println!("ARES: PHOBOS exited: {status}");
            break;
        }
    }

    Ok(())
}
