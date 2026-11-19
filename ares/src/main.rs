use std::env;
use std::error::Error;
use std::ffi::OsString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixDatagram;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, ExitStatus};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value;

const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(20);
const IPC_POLL_INTERVAL: Duration = Duration::from_millis(500);
const NORMAL_RESTART_DELAY: Duration = Duration::from_millis(250);
const MAX_MESSAGE: usize = 4096;

static SHUTDOWN: AtomicBool = AtomicBool::new(false);

extern "C" fn signal_handler(_: libc::c_int) {
    SHUTDOWN.store(true, Ordering::Relaxed);
}

fn install_signals() -> io::Result<()> {
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = signal_handler as *const () as usize;
        libc::sigemptyset(&mut action.sa_mask);

        for signal in [libc::SIGINT, libc::SIGTERM] {
            if libc::sigaction(signal, &action, std::ptr::null_mut()) != 0 {
                return Err(io::Error::last_os_error());
            }
        }
    }

    Ok(())
}

struct PhobosState {
    last_heartbeat: Instant,
    captured: bool,
}

impl PhobosState {
    fn new() -> Self {
        Self {
            last_heartbeat: Instant::now(),
            captured: false,
        }
    }
}

fn handle_event(data: &[u8], state: &mut PhobosState) {
    let message: Value = match serde_json::from_slice(data) {
        Ok(message) => message,
        Err(error) => {
            eprintln!("ARES: invalid IPC message: {error}");
            return;
        }
    };

    let event = message["event"].as_str().unwrap_or("UNKNOWN");
    let payload = &message["data"];

    match event {
        "READY" => {
            state.last_heartbeat = Instant::now();
            println!("ARES: PHOBOS ready");
        }

        "HEARTBEAT" => {
            state.last_heartbeat = Instant::now();
            println!(
                "ARES: PHOBOS heartbeat, active connections: {}",
                payload["active_connections"]
            );
        }

        "CONNECTION" => {
            let source = payload["source_ip"].as_str().unwrap_or("?");
            let destination = payload["destination_ip"].as_str().unwrap_or("?");

            println!(
                "ARES: CONNECTION {}:{} -> {}:{} (id={})",
                source,
                payload["source_port"],
                destination,
                payload["destination_port"],
                payload["connection_id"]
            );
        }

        "DISCONNECT" => {
            println!(
                "ARES: DISCONNECT id={} reason={}",
                payload["connection_id"], payload["reason"]
            );
        }

        "CAPTURED" => {
            state.captured = true;

            println!(
                "ARES: CAPTURED id={} source={}",
                payload["connection_id"], payload["source_ip"]
            );
        }

        "ERROR" => {
            eprintln!("ARES: PHOBOS ERROR: {payload}");
        }

        _ => {
            eprintln!("ARES: unknown IPC event: {event}");
        }
    }
}

fn start_phobos(
    executable: &OsString,
    arguments: &[OsString],
) -> io::Result<(Child, UnixDatagram)> {
    let (parent, child) = UnixDatagram::pair()?;

    parent.set_read_timeout(Some(IPC_POLL_INTERVAL))?;

    // dup() creates an inheritable file descriptor.
    let fd = unsafe { libc::dup(child.as_raw_fd()) };

    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    let inherited = unsafe { OwnedFd::from_raw_fd(fd) };

    let mut command = Command::new(executable);

    // PHOBOS gets its own process group.
    // Terminal SIGINT must reach ARES, not PHOBOS directly.
    command.process_group(0);

    command
        .args(arguments)
        .env("ARES_IPC_FD", inherited.as_raw_fd().to_string());

    let process = command.spawn()?;

    drop(inherited);
    drop(child);

    println!("ARES: PHOBOS started, PID={}", process.id());

    Ok((process, parent))
}

fn terminate_phobos(process: &mut Child) -> io::Result<ExitStatus> {
    if let Some(status) = process.try_wait()? {
        return Ok(status);
    }

    let result = unsafe { libc::kill(process.id() as libc::pid_t, libc::SIGTERM) };

    if result != 0 {
        let error = io::Error::last_os_error();

        if error.raw_os_error() != Some(libc::ESRCH) {
            return Err(error);
        }
    }

    let deadline = Instant::now() + Duration::from_secs(3);

    while Instant::now() < deadline {
        if let Some(status) = process.try_wait()? {
            return Ok(status);
        }

        thread::sleep(Duration::from_millis(50));
    }

    process.kill()?;
    process.wait()
}

fn drain_ipc(socket: &UnixDatagram, state: &mut PhobosState) -> io::Result<()> {
    socket.set_nonblocking(true)?;

    let mut buffer = [0u8; MAX_MESSAGE];

    loop {
        match socket.recv(&mut buffer) {
            Ok(size) => handle_event(&buffer[..size], state),

            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                break;
            }

            Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                continue;
            }

            Err(error) => return Err(error),
        }
    }

    Ok(())
}

fn wait_before_restart(duration: Duration) {
    let deadline = Instant::now() + duration;

    while !SHUTDOWN.load(Ordering::Relaxed) && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(50));
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    install_signals()?;

    let mut args = env::args_os().skip(1);

    let executable = args
        .next()
        .ok_or("Usage: ares <phobos-binary> <phobos-arguments...>")?;

    let arguments: Vec<OsString> = args.collect();

    let mut failure_streak = 0u32;

    println!("ARES: supervisor started");

    while !SHUTDOWN.load(Ordering::Relaxed) {
        let started = Instant::now();

        let (mut phobos, socket) = match start_phobos(&executable, &arguments) {
            Ok(result) => result,

            Err(error) => {
                eprintln!("ARES: PHOBOS start failed: {error}");

                failure_streak = failure_streak.saturating_add(1);

                let seconds = (1u64 << failure_streak.saturating_sub(1).min(5)).min(30);

                wait_before_restart(Duration::from_secs(seconds));
                continue;
            }
        };

        let mut state = PhobosState::new();
        let mut watchdog_triggered = false;

        let exit_status = loop {
            if SHUTDOWN.load(Ordering::Relaxed) {
                println!("ARES: shutting down PHOBOS");
                let status = terminate_phobos(&mut phobos)?;
                println!("ARES: PHOBOS terminated: {status}");
                break status;
            }

            let mut buffer = [0u8; MAX_MESSAGE];

            match socket.recv(&mut buffer) {
                Ok(size) => {
                    handle_event(&buffer[..size], &mut state);
                }

                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock
                            | io::ErrorKind::TimedOut
                            | io::ErrorKind::Interrupted
                    ) => {}

                Err(error) => {
                    eprintln!("ARES: IPC receive error: {error}");
                }
            }

            if let Some(status) = phobos.try_wait()? {
                drain_ipc(&socket, &mut state)?;
                break status;
            }

            if state.last_heartbeat.elapsed() > HEARTBEAT_TIMEOUT {
                eprintln!("ARES: PHOBOS heartbeat timeout");

                watchdog_triggered = true;

                let status = terminate_phobos(&mut phobos)?;
                drain_ipc(&socket, &mut state)?;

                break status;
            }
        };

        println!("ARES: PHOBOS exited: {exit_status}");

        if SHUTDOWN.load(Ordering::Relaxed) {
            break;
        }

        let normal_capture = state.captured && exit_status.success() && !watchdog_triggered;

        if normal_capture {
            failure_streak = 0;

            println!("ARES: restarting PHOBOS after capture");

            wait_before_restart(NORMAL_RESTART_DELAY);
            continue;
        }

        // Long-running processes reset the failure counter.
        if started.elapsed() >= Duration::from_secs(60) {
            failure_streak = 0;
        }

        failure_streak = failure_streak.saturating_add(1);

        let seconds = (1u64 << failure_streak.saturating_sub(1).min(5)).min(30);

        eprintln!("ARES: unexpected PHOBOS exit, restart in {seconds}s");

        wait_before_restart(Duration::from_secs(seconds));
    }

    println!("ARES: stopped");

    Ok(())
}
