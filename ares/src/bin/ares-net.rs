//! Experimental ARES management-network discovery and monotonic address allocator.
//! Raw L2 packets allow a fresh clone to discover peers before it has an IPv4 address.
//! This binary intentionally never assigns an IP address to an OS interface.

use std::collections::HashSet;
use std::env;
use std::error::Error;
use std::ffi::CString;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};

#[path = "ares-net/arp.rs"]
mod arp;

const ETHERTYPE: u16 = 0x88b5; // IEEE local experimental EtherType, NOT an Internet protocol.
const PROTOCOL: &str = "olymp-ares-network";
const MAX_FRAME: usize = 1514;
const MAX_MESSAGE: usize = 1200;
const DISCOVERY_WAIT: Duration = Duration::from_secs(3);
const CLAIM_WAIT: Duration = Duration::from_secs(3);

#[derive(Debug, Deserialize)]
struct ConfigFile {
    network: NetworkConfig,
}

#[derive(Debug, Deserialize)]
struct NetworkConfig {
    management_vlan: u8,
    branch: toml::Value,
    branches_file: Option<PathBuf>,
    state_file: PathBuf,
    auth_key_file: PathBuf,
    ip_first: u8,
    ip_last: u8,
    #[serde(default)]
    allow_first_node: bool,
    #[serde(default = "default_sync_secs")]
    sync_seconds: u64,
}

fn default_sync_secs() -> u64 {
    60
}

impl NetworkConfig {
    fn validate(&self) -> io::Result<()> {
        if self.management_vlan == 0 || self.management_vlan == 255 {
            return Err(bad("management_vlan must be in 1..254"));
        }
        if self.ip_first < 2 || self.ip_last > 254 || self.ip_first > self.ip_last {
            return Err(bad("invalid IP allocation range (2..254)"));
        }
        if !(10..=3600).contains(&self.sync_seconds) {
            return Err(bad("sync_seconds must be between 10 and 3600"));
        }
        Ok(())
    }
}

fn bad(s: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, s.into())
}

fn load_config(path: &Path) -> Result<NetworkConfig, Box<dyn Error>> {
    let raw = fs::read_to_string(path)?;
    let config: ConfigFile = toml::from_str(&raw)?;
    config.network.validate()?;
    Ok(config.network)
}

fn branch_candidates(cfg: &NetworkConfig) -> io::Result<Vec<u8>> {
    if let Some(number) = cfg.branch.as_integer() {
        if (1..=254).contains(&number) {
            return Ok(vec![number as u8]);
        }
        return Err(bad("branch must be between 1 and 254"));
    }
    if cfg.branch.as_str() != Some("auto") {
        return Err(bad("branch must be an integer or 'auto'"));
    }
    let path = cfg
        .branches_file
        .as_deref()
        .ok_or_else(|| bad("branch='auto' requires branches_file"))?;
    let raw = fs::read_to_string(path)?;
    let mut found = Vec::new();
    for (idx, line) in raw.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('B') {
            continue;
        }
        let first = line
            .split_whitespace()
            .next()
            .ok_or_else(|| bad("missing branch"))?;
        let n: u8 = first
            .parse()
            .map_err(|_| bad(format!("invalid branch at line {}", idx + 1)))?;
        if n == 0 || n == 255 {
            return Err(bad("invalid branch in branches_file"));
        }
        if !found.contains(&n) {
            found.push(n);
        }
    }
    if found.is_empty() {
        return Err(bad("no branches in branches_file"));
    }
    Ok(found)
}

fn interfaces() -> io::Result<Vec<String>> {
    let mut result = Vec::new();
    for ent in fs::read_dir("/sys/class/net")? {
        let ent = ent?;
        let name = ent.file_name().to_string_lossy().into_owned();
        if name == "lo" {
            continue;
        }
        let path = ent.path();
        // Only Ethernet-compatible, administratively active interfaces.
        if fs::read_to_string(path.join("type"))?.trim() != "1" {
            continue;
        }
        let state = fs::read_to_string(path.join("operstate"))?;
        if state.trim() != "up" && state.trim() != "unknown" {
            continue;
        }
        result.push(name);
    }
    result.sort();
    Ok(result)
}

fn probe_gateway(interface: &str, gateway: Ipv4Addr) -> io::Result<bool> {
    Ok(arp::probe(interface, gateway)?.is_some())
}

fn find_management(cfg: &NetworkConfig) -> io::Result<(String, u8)> {
    let candidates = branch_candidates(cfg)?;
    let mut matches = Vec::new();
    for interface in interfaces()? {
        for &branch in &candidates {
            let gateway = Ipv4Addr::new(10, branch, cfg.management_vlan, 1);
            println!("ARES-NET: ARP probe interface={interface} gateway={gateway}");
            if probe_gateway(&interface, gateway)? {
                matches.push((interface.clone(), branch));
            }
        }
    }
    match matches.as_slice() {
        [(iface, branch)] => Ok(((*iface).clone(), *branch)),
        [] => Err(bad(
            "no unique management interface: router did not answer ARP",
        )),
        _ => Err(bad(format!("ambiguous management network: {matches:?}"))),
    }
}

fn parse_hex(input: &str) -> io::Result<Vec<u8>> {
    let s = input.trim();
    if !s.len().is_multiple_of(2) {
        return Err(bad("odd-length hex key"));
    }
    s.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let part = std::str::from_utf8(pair).map_err(|_| bad("non-ASCII key"))?;
            u8::from_str_radix(part, 16).map_err(|_| bad("invalid hex key"))
        })
        .collect()
}

fn hex(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len() * 2);
    for byte in input {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn load_key(path: &Path) -> io::Result<hmac::Key> {
    let mode = fs::metadata(path)?.permissions().mode();
    if mode & 0o077 != 0 {
        return Err(bad(
            "auth key must not be readable by group/others (chmod 600)",
        ));
    }
    let data = fs::read_to_string(path)?;
    let key = parse_hex(&data)?;
    if key.len() != 32 {
        return Err(bad("auth key must be exactly 32 bytes (64 hex chars)"));
    }
    Ok(hmac::Key::new(hmac::HMAC_SHA256, &key))
}

fn new_nonce() -> io::Result<u64> {
    let mut buf = [0u8; 8];
    SystemRandom::new()
        .fill(&mut buf)
        .map_err(|_| bad("random generator failed"))?;
    Ok(u64::from_ne_bytes(buf))
}

fn new_node_id() -> io::Result<String> {
    let mut buf = [0u8; 16];
    SystemRandom::new()
        .fill(&mut buf)
        .map_err(|_| bad("random generator failed"))?;
    Ok(hex(&buf))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct State {
    branch: u8,
    management_vlan: u8,
    node_id: String,
    assigned_x: u8,
    ip_max: u8,
}

fn read_state(path: &Path) -> io::Result<Option<State>> {
    match fs::read(path) {
        Ok(data) => serde_json::from_slice::<State>(&data)
            .map(Some)
            .map_err(|e| bad(format!("invalid state: {e}"))),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

fn save_state(path: &Path, state: &State) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    let temporary = parent.join(format!(".ares-net-{}.tmp", new_node_id()?));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    let result = (|| {
        serde_json::to_writer(&mut file, state).map_err(io::Error::other)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        fs::File::open(parent)?.sync_all()?;
        Ok::<(), io::Error>(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Message {
    protocol: String,
    version: u8,
    kind: String,
    branch: u8,
    vlan: u8,
    node_id: String,
    nonce: u64,
    assigned_x: u8,
    ip_max: u8,
    proposed_x: u8,
}

#[derive(Serialize, Deserialize)]
struct SignedMessage {
    body: Message,
    tag: String,
}

impl Message {
    fn make(kind: &str, state: &State, nonce: u64, proposed_x: u8) -> Self {
        Self {
            protocol: PROTOCOL.into(),
            version: 1,
            kind: kind.into(),
            branch: state.branch,
            vlan: state.management_vlan,
            node_id: state.node_id.clone(),
            nonce,
            assigned_x: state.assigned_x,
            ip_max: state.ip_max,
            proposed_x,
        }
    }
}

fn encode_message(key: &hmac::Key, msg: &Message) -> io::Result<Vec<u8>> {
    let body = serde_json::to_vec(msg).map_err(io::Error::other)?;
    let tag = hex(hmac::sign(key, &body).as_ref());
    let encoded = serde_json::to_vec(&SignedMessage {
        body: msg.clone(),
        tag,
    })
    .map_err(io::Error::other)?;
    if encoded.len() > MAX_MESSAGE {
        return Err(bad("network message exceeds safe size"));
    }
    Ok(encoded)
}

fn decode_message(key: &hmac::Key, data: &[u8], branch: u8, vlan: u8) -> Option<Message> {
    if data.len() > MAX_MESSAGE {
        return None;
    }
    let wrapped: SignedMessage = serde_json::from_slice(data).ok()?;
    let encoded = serde_json::to_vec(&wrapped.body).ok()?;
    let signature = parse_hex(&wrapped.tag).ok()?;
    if hmac::verify(key, &encoded, &signature).is_err() {
        return None;
    }
    let m = wrapped.body;
    if m.protocol != PROTOCOL
        || m.version != 1
        || m.branch != branch
        || m.vlan != vlan
        || m.node_id.len() != 32
    {
        return None;
    }
    Some(m)
}

struct Link {
    fd: OwnedFd,
    ifindex: i32,
    mac: [u8; 6],
}

impl Link {
    fn open(interface: &str) -> io::Result<Self> {
        let c_if = CString::new(interface).map_err(|_| bad("invalid interface"))?;
        let ifindex = unsafe { libc::if_nametoindex(c_if.as_ptr()) };
        if ifindex == 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                i32::from(ETHERTYPE.to_be()),
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        addr.sll_family = libc::AF_PACKET as u16;
        addr.sll_protocol = ETHERTYPE.to_be();
        addr.sll_ifindex = ifindex as i32;
        let result = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                &raw const addr as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        let mac_txt = fs::read_to_string(format!("/sys/class/net/{interface}/address"))?;
        let parts = mac_txt.trim().split(':').collect::<Vec<_>>();
        if parts.len() != 6 {
            return Err(bad("invalid MAC address"));
        }
        let mut mac = [0u8; 6];
        for (idx, part) in parts.iter().enumerate() {
            mac[idx] = u8::from_str_radix(part, 16).map_err(|_| bad("invalid MAC address"))?;
        }
        Ok(Self {
            fd,
            ifindex: ifindex as i32,
            mac,
        })
    }

    fn send(&self, data: &[u8]) -> io::Result<()> {
        if data.len() > MAX_MESSAGE {
            return Err(bad("frame too large"));
        }
        let mut frame = Vec::with_capacity(14 + data.len());
        frame.extend_from_slice(&[0xff; 6]);
        frame.extend_from_slice(&self.mac);
        frame.extend_from_slice(&ETHERTYPE.to_be_bytes());
        frame.extend_from_slice(data);
        let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        addr.sll_family = libc::AF_PACKET as u16;
        addr.sll_protocol = ETHERTYPE.to_be();
        addr.sll_ifindex = self.ifindex;
        addr.sll_halen = 6;
        addr.sll_addr[..6].copy_from_slice(&[0xff; 6]);
        let result = unsafe {
            libc::sendto(
                self.fd.as_raw_fd(),
                frame.as_ptr().cast(),
                frame.len(),
                0,
                &raw const addr as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        if result as usize != frame.len() {
            return Err(io::Error::new(io::ErrorKind::WriteZero, "short raw frame"));
        }
        Ok(())
    }

    fn receive(&self, wait: Duration) -> io::Result<Option<Vec<u8>>> {
        let timeout_ms = wait.as_millis().min(i32::MAX as u128) as i32;
        let mut pollfd = libc::pollfd {
            fd: self.fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&mut pollfd, 1, timeout_ms) };
        if ready == 0 {
            return Ok(None);
        }
        if ready < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                return Ok(None);
            }
            return Err(error);
        }
        let mut frame = [0u8; MAX_FRAME];
        let size = unsafe {
            libc::recv(
                self.fd.as_raw_fd(),
                frame.as_mut_ptr().cast(),
                frame.len(),
                libc::MSG_DONTWAIT,
            )
        };
        if size < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::WouldBlock {
                return Ok(None);
            }
            return Err(error);
        }
        let size = size as usize;
        if size < 14 || frame[12..14] != ETHERTYPE.to_be_bytes() || frame[6..12] == self.mac {
            return Ok(None);
        }
        Ok(Some(frame[14..size].to_vec()))
    }
}

fn send_message(link: &Link, key: &hmac::Key, msg: &Message) -> io::Result<()> {
    link.send(&encode_message(key, msg)?)
}

fn validated_message(
    link: &Link,
    key: &hmac::Key,
    state: &State,
    wait: Duration,
) -> io::Result<Option<Message>> {
    let data = match link.receive(wait)? {
        Some(data) => data,
        None => return Ok(None),
    };
    let msg = decode_message(key, &data, state.branch, state.management_vlan);
    Ok(msg.filter(|m| m.node_id != state.node_id))
}

fn advance_max(
    state: &mut State,
    path: &Path,
    received: u8,
    cfg: &NetworkConfig,
) -> io::Result<bool> {
    if received < cfg.ip_first || received > cfg.ip_last || received <= state.ip_max {
        return Ok(false);
    }
    let mut new_state = state.clone();
    new_state.ip_max = received;
    save_state(path, &new_state)?;
    *state = new_state;
    println!("ARES-NET: durable IP_MAX={received}");
    Ok(true)
}

fn handle_peer(
    link: &Link,
    key: &hmac::Key,
    cfg: &NetworkConfig,
    state: &mut State,
    msg: Message,
) -> io::Result<()> {
    match msg.kind.as_str() {
        "CONF_REQ" => {
            send_message(link, key, &Message::make("CONF_RESP", state, msg.nonce, 0))?;
        }
        "CLAIM_REQ" => {
            let accept = msg.proposed_x >= cfg.ip_first
                && msg.proposed_x <= cfg.ip_last
                && msg.proposed_x > state.ip_max;
            if accept {
                advance_max(state, &cfg.state_file, msg.proposed_x, cfg)?;
            }
            let kind = if accept { "CLAIM_ACK" } else { "CLAIM_NAK" };
            send_message(
                link,
                key,
                &Message::make(kind, state, msg.nonce, msg.proposed_x),
            )?;
        }
        "MAX_IP" | "IP_SYNC" => {
            advance_max(state, &cfg.state_file, msg.ip_max, cfg)?;
        }
        _ => {}
    }
    Ok(())
}

fn discover(
    link: &Link,
    key: &hmac::Key,
    state: &State,
    cfg: &NetworkConfig,
) -> io::Result<(HashSet<String>, u8)> {
    let nonce = new_nonce()?;
    send_message(link, key, &Message::make("CONF_REQ", state, nonce, 0))?;
    let deadline = Instant::now() + DISCOVERY_WAIT;
    let mut peers = HashSet::new();
    let mut maximum = state.ip_max;
    while let Some(wait) = deadline.checked_duration_since(Instant::now()) {
        if let Some(msg) = validated_message(link, key, state, wait)?
            && msg.kind == "CONF_RESP"
            && msg.nonce == nonce
            && msg.ip_max >= cfg.ip_first
            && msg.ip_max <= cfg.ip_last
        {
            peers.insert(msg.node_id);
            maximum = maximum.max(msg.ip_max).max(msg.assigned_x);
        }
    }
    Ok((peers, maximum))
}

fn allocate(
    link: &Link,
    key: &hmac::Key,
    cfg: &NetworkConfig,
    state: &mut State,
) -> io::Result<()> {
    let (peers, max_seen) = discover(link, key, state, cfg)?;
    println!(
        "ARES-NET: responding peers={}, high water={max_seen}",
        peers.len()
    );
    let new_x = if peers.is_empty() {
        if !cfg.allow_first_node {
            return Err(bad(
                "no peers; refuse to bootstrap without allow_first_node=true",
            ));
        }
        cfg.ip_first
    } else {
        max_seen
            .checked_add(1)
            .filter(|x| *x <= cfg.ip_last)
            .ok_or_else(|| bad("allocated address range exhausted"))?
    };
    println!("ARES-NET: proposed final octet x={new_x}");
    // Test duplicate address using ARP before accepting the allocation.
    // An offline host is not discoverable; peer high-water is the stronger safeguard.
    let gateway_iface = interface_name(link.ifindex)?;
    let candidate = Ipv4Addr::new(10, state.branch, cfg.management_vlan, new_x);
    // A matching ARP reply is definite evidence that this address is occupied.
    // No reply is NOT proof of vacancy; high-water state is also required.
    if arp::probe(&gateway_iface, candidate)?.is_some() {
        return Err(bad(format!(
            "address {candidate} answered ARP: already occupied"
        )));
    }
    if !peers.is_empty() {
        let nonce = new_nonce()?;
        send_message(link, key, &Message::make("CLAIM_REQ", state, nonce, new_x))?;
        let deadline = Instant::now() + CLAIM_WAIT;
        let mut confirmed = false;
        while let Some(wait) = deadline.checked_duration_since(Instant::now()) {
            if let Some(msg) = validated_message(link, key, state, wait)?
                && msg.nonce == nonce
                && msg.proposed_x == new_x
                && peers.contains(&msg.node_id)
            {
                if msg.kind == "CLAIM_ACK" {
                    confirmed = true;
                }
                if msg.kind == "CLAIM_NAK" {
                    return Err(bad(format!(
                        "peer rejected claim, its IP_MAX={}",
                        msg.ip_max
                    )));
                }
            }
        }
        if !confirmed {
            return Err(bad("no peer confirmed durable reservation"));
        }
    }
    state.assigned_x = new_x;
    state.ip_max = state.ip_max.max(max_seen).max(new_x);
    save_state(&cfg.state_file, state)?;
    println!(
        "ARES-NET: RESERVED {} (state persisted; OS IP NOT configured)",
        candidate
    );
    for _ in 0..3 {
        send_message(link, key, &Message::make("MAX_IP", state, new_nonce()?, 0))?;
    }
    Ok(())
}

fn interface_name(ifindex: i32) -> io::Result<String> {
    for name in interfaces()? {
        let c = CString::new(name.clone()).map_err(|_| bad("invalid interface"))?;
        if unsafe { libc::if_nametoindex(c.as_ptr()) } as i32 == ifindex {
            return Ok(name);
        }
    }
    Err(bad("interface vanished"))
}

fn run(cfg: &NetworkConfig, iface: &str, branch: u8) -> io::Result<()> {
    // Do not let two allocator instances on the same VM allocate independently.
    let state_dir = cfg
        .state_file
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(state_dir)?;
    let lock_path = cfg.state_file.with_extension("lock");
    let lock = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(&lock_path)?;
    let lock_result = unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if lock_result != 0 {
        return Err(bad("another ares-net process already holds the state lock"));
    }
    let key = load_key(&cfg.auth_key_file)?;
    let link = Link::open(iface)?;
    let mut state = match read_state(&cfg.state_file)? {
        Some(existing) => {
            if existing.branch != branch
                || existing.management_vlan != cfg.management_vlan
                || existing.assigned_x < cfg.ip_first
                || existing.assigned_x > cfg.ip_last
                || existing.ip_max < existing.assigned_x
                || existing.ip_max > cfg.ip_last
            {
                return Err(bad(
                    "persisted identity does not match this site/network: refusing reassignment",
                ));
            }
            existing
        }
        None => State {
            branch,
            management_vlan: cfg.management_vlan,
            node_id: new_node_id()?,
            assigned_x: 0,
            ip_max: 0,
        },
    };
    if state.assigned_x == 0 {
        allocate(&link, &key, cfg, &mut state)?;
    }
    println!(
        "ARES-NET: node={} management_ip=10.{}.{}.{} IP_MAX={}; OS network unchanged",
        state.node_id, branch, cfg.management_vlan, state.assigned_x, state.ip_max
    );
    let mut next_sync = Instant::now();
    loop {
        if Instant::now() >= next_sync {
            send_message(
                &link,
                &key,
                &Message::make("IP_SYNC", &state, new_nonce()?, 0),
            )?;
            next_sync = Instant::now() + Duration::from_secs(cfg.sync_seconds);
        }
        let wait = next_sync
            .saturating_duration_since(Instant::now())
            .min(Duration::from_millis(500));
        if let Some(msg) = validated_message(&link, &key, &state, wait)? {
            handle_peer(&link, &key, cfg, &mut state, msg)?;
        }
    }
}

fn print_usage() {
    eprintln!(
        "Usage: ares-net probe|run <ares-network.toml>\n       ares-net arp-probe <interface> <IPv4>\n  probe: read-only ARP interface detection\n  run: reserve x via authenticated local-L2 messages, persist IP_MAX, 60s sync; NEVER configure interface IP"
    );
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = env::args_os().skip(1);
    let operation = args.next().ok_or_else(|| {
        print_usage();
        bad("operation missing")
    })?;
    if operation.to_str() == Some("arp-probe") {
        let interface = args.next().ok_or_else(|| bad("interface missing"))?;
        let target = args.next().ok_or_else(|| bad("IPv4 address missing"))?;
        if args.next().is_some() {
            return Err(bad("too many arguments").into());
        }
        let interface = interface
            .to_str()
            .ok_or_else(|| bad("invalid interface name"))?;
        let target: Ipv4Addr = target
            .to_str()
            .ok_or_else(|| bad("invalid IP address"))?
            .parse()?;
        match arp::probe(interface, target)? {
            Some(mac) => println!(
                "ARES-NET: ARP reply interface={interface} ip={target} mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
            ),
            None => {
                println!("ARES-NET: no ARP reply interface={interface} ip={target} (inconclusive)")
            }
        }
        return Ok(());
    }
    let config = args.next().ok_or_else(|| {
        print_usage();
        bad("config missing")
    })?;
    if args.next().is_some() {
        print_usage();
        return Err(bad("too many arguments").into());
    }
    let cfg = load_config(Path::new(&config))?;
    let (iface, branch) = find_management(&cfg)?;
    println!(
        "ARES-NET: management interface={iface}, branch={branch}, VLAN={}",
        cfg.management_vlan
    );
    match operation.to_str() {
        Some("probe") => Ok(()),
        Some("run") => run(&cfg, &iface, branch).map_err(Into::into),
        _ => {
            print_usage();
            Err(bad("unknown operation").into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_hmac_round_trip_and_tamper() {
        let key = hmac::Key::new(hmac::HMAC_SHA256, &[7u8; 32]);
        let state = State {
            branch: 30,
            management_vlan: 18,
            node_id: "a".repeat(32),
            assigned_x: 101,
            ip_max: 101,
        };
        let msg = Message::make("CONF_RESP", &state, 42, 0);
        let encoded = encode_message(&key, &msg).unwrap();
        let decoded = decode_message(&key, &encoded, 30, 18).unwrap();
        assert_eq!(decoded.ip_max, 101);
        assert!(decode_message(&key, &encoded, 31, 18).is_none());
        let mut altered = encoded;
        let pos = altered.iter().position(|x| *x == b'3').unwrap();
        altered[pos] = b'9';
        assert!(decode_message(&key, &altered, 30, 18).is_none());
    }
    #[test]
    fn test_range_validation() {
        let cfg = NetworkConfig {
            management_vlan: 18,
            branch: toml::Value::Integer(30),
            branches_file: None,
            state_file: "state.json".into(),
            auth_key_file: "key".into(),
            ip_first: 100,
            ip_last: 240,
            allow_first_node: false,
            sync_seconds: 60,
        };
        cfg.validate().unwrap();
        assert_eq!(branch_candidates(&cfg).unwrap(), vec![30]);
    }
    #[test]
    fn test_monotonic_high_water() {
        let path = env::temp_dir().join(format!("ares-net-test-{}.json", new_node_id().unwrap()));
        let cfg = NetworkConfig {
            management_vlan: 18,
            branch: toml::Value::Integer(30),
            branches_file: None,
            state_file: path.clone(),
            auth_key_file: "key".into(),
            ip_first: 100,
            ip_last: 240,
            allow_first_node: false,
            sync_seconds: 60,
        };
        let mut s = State {
            branch: 30,
            management_vlan: 18,
            node_id: "a".repeat(32),
            assigned_x: 102,
            ip_max: 105,
        };
        assert!(!advance_max(&mut s, &path, 103, &cfg).unwrap());
        assert!(advance_max(&mut s, &path, 108, &cfg).unwrap());
        assert_eq!(read_state(&path).unwrap().unwrap().ip_max, 108);
        fs::remove_file(path).unwrap();
    }
}
