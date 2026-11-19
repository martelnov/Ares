//! Minimal IPv4 ARP probes on an unnumbered Linux Ethernet interface.
//!
//! No network configuration is changed. The probe uses an AF_PACKET raw socket,
//! an Ethernet ARP request, and sender IPv4 0.0.0.0 (RFC 5227-style probe).
//! A lack of reply is NOT proof that an IP address is unoccupied.

use std::ffi::CString;
use std::fs;
use std::io;
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::Path;
use std::time::{Duration, Instant};

const ETH_P_ARP: u16 = 0x0806;
const ETH_P_IP: u16 = 0x0800;
const ARP_REQUEST: u16 = 1;
const ARP_REPLY: u16 = 2;
const ETHERNET: u16 = 1;
const HEADER_LEN: usize = 14;
const ARP_LEN: usize = 28;
const FRAME_LEN: usize = HEADER_LEN + ARP_LEN;
const RETRIES: usize = 3;
const PER_TRY_TIMEOUT: Duration = Duration::from_millis(650);

struct ArpSocket {
    fd: OwnedFd,
    index: i32,
    mac: [u8; 6],
}

impl ArpSocket {
    fn open(interface: &str) -> io::Result<Self> {
        let c_interface = CString::new(interface)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid interface name"))?;
        let index = unsafe { libc::if_nametoindex(c_interface.as_ptr()) };
        if index == 0 {
            return Err(io::Error::last_os_error());
        }
        // Restrict to ARP frames on this NIC. Works without an IPv4 address.
        let raw_fd = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                i32::from(ETH_P_ARP.to_be()),
            )
        };
        if raw_fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
        let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        addr.sll_family = libc::AF_PACKET as u16;
        addr.sll_protocol = ETH_P_ARP.to_be();
        addr.sll_ifindex = index as i32;
        let rc = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                (&raw const addr).cast(),
                std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }

        let path = Path::new("/sys/class/net").join(interface).join("address");
        let mac = parse_mac(fs::read_to_string(path)?.trim())?;
        if mac == [0; 6] || mac[0] & 1 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid Ethernet source MAC",
            ));
        }
        Ok(Self {
            fd,
            index: index as i32,
            mac,
        })
    }

    fn send_request(&self, target: Ipv4Addr) -> io::Result<()> {
        let frame = request_frame(self.mac, target);
        let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        addr.sll_family = libc::AF_PACKET as u16;
        addr.sll_protocol = ETH_P_ARP.to_be();
        addr.sll_ifindex = self.index;
        addr.sll_halen = 6;
        addr.sll_addr[..6].fill(0xff);
        let written = unsafe {
            libc::sendto(
                self.fd.as_raw_fd(),
                frame.as_ptr().cast(),
                frame.len(),
                0,
                (&raw const addr).cast(),
                std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if written < 0 {
            return Err(io::Error::last_os_error());
        }
        if written as usize != frame.len() {
            return Err(io::Error::new(io::ErrorKind::WriteZero, "short ARP frame"));
        }
        Ok(())
    }

    fn await_reply(&self, target: Ipv4Addr, timeout: Duration) -> io::Result<Option<[u8; 6]>> {
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(None);
            }
            let timeout_ms = remaining.as_millis().min(i32::MAX as u128).max(1) as i32;
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
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(err);
            }
            if pollfd.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
                return Err(io::Error::other("ARP socket became unavailable"));
            }
            if pollfd.revents & libc::POLLIN == 0 {
                continue;
            }
            let mut frame = [0u8; 1518];
            let size = unsafe {
                libc::recv(
                    self.fd.as_raw_fd(),
                    frame.as_mut_ptr().cast(),
                    frame.len(),
                    libc::MSG_DONTWAIT,
                )
            };
            if size < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::WouldBlock
                    || err.kind() == io::ErrorKind::Interrupted
                {
                    continue;
                }
                return Err(err);
            }
            if let Some(mac) = parse_reply(&frame[..size as usize], self.mac, target) {
                return Ok(Some(mac));
            }
        }
    }
}

fn parse_mac(text: &str) -> io::Result<[u8; 6]> {
    let mut mac = [0u8; 6];
    let mut parts = text.split(':');
    for octet in &mut mac {
        let part = parts
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "malformed MAC address"))?;
        if part.len() != 2 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "malformed MAC address",
            ));
        }
        *octet = u8::from_str_radix(part, 16)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "malformed MAC address"))?;
    }
    if parts.next().is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "malformed MAC address",
        ));
    }
    Ok(mac)
}

fn request_frame(mac: [u8; 6], target: Ipv4Addr) -> [u8; FRAME_LEN] {
    let mut frame = [0u8; FRAME_LEN];
    frame[0..6].fill(0xff);
    frame[6..12].copy_from_slice(&mac);
    frame[12..14].copy_from_slice(&ETH_P_ARP.to_be_bytes());
    frame[14..16].copy_from_slice(&ETHERNET.to_be_bytes());
    frame[16..18].copy_from_slice(&ETH_P_IP.to_be_bytes());
    frame[18] = 6;
    frame[19] = 4;
    frame[20..22].copy_from_slice(&ARP_REQUEST.to_be_bytes());
    frame[22..28].copy_from_slice(&mac);
    // Sender protocol address stays 0.0.0.0, even if the NIC has another IP.
    frame[38..42].copy_from_slice(&target.octets());
    frame
}

fn parse_reply(frame: &[u8], own_mac: [u8; 6], target: Ipv4Addr) -> Option<[u8; 6]> {
    if frame.len() < FRAME_LEN
        || frame[12..14] != ETH_P_ARP.to_be_bytes()
        || frame[14..16] != ETHERNET.to_be_bytes()
        || frame[16..18] != ETH_P_IP.to_be_bytes()
        || frame[18] != 6
        || frame[19] != 4
        || frame[20..22] != ARP_REPLY.to_be_bytes()
        || frame[28..32] != target.octets()
        || frame[32..38] != own_mac
        || (frame[0..6] != own_mac && frame[0..6] != [0xff; 6])
        || frame[38..42] != [0; 4]
        || frame[6..12] != frame[22..28]
    {
        return None;
    }
    let mut reply_mac = [0u8; 6];
    reply_mac.copy_from_slice(&frame[22..28]);
    if reply_mac == [0; 6] || reply_mac[0] & 1 != 0 || reply_mac == own_mac {
        return None;
    }
    Some(reply_mac)
}

/// Probe an IPv4 address at L2 on a named interface. Returns a matching MAC,
/// or None when no matching ARP reply arrived. No IPv4 address is necessary.
/// A timeout does not prove the target address is free.
pub(super) fn probe(interface: &str, target: Ipv4Addr) -> io::Result<Option<[u8; 6]>> {
    let sock = ArpSocket::open(interface)?;
    for _ in 0..RETRIES {
        sock.send_request(target)?;
        if let Some(mac) = sock.await_reply(target, PER_TRY_TIMEOUT)? {
            return Ok(Some(mac));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    const OWN: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
    const PEER: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];
    const TARGET: Ipv4Addr = Ipv4Addr::new(10, 30, 18, 1);

    fn valid_reply() -> [u8; FRAME_LEN] {
        let mut frame = [0u8; FRAME_LEN];
        frame[..6].copy_from_slice(&OWN);
        frame[6..12].copy_from_slice(&PEER);
        frame[12..14].copy_from_slice(&ETH_P_ARP.to_be_bytes());
        frame[14..16].copy_from_slice(&ETHERNET.to_be_bytes());
        frame[16..18].copy_from_slice(&ETH_P_IP.to_be_bytes());
        frame[18] = 6;
        frame[19] = 4;
        frame[20..22].copy_from_slice(&ARP_REPLY.to_be_bytes());
        frame[22..28].copy_from_slice(&PEER);
        frame[28..32].copy_from_slice(&TARGET.octets());
        frame[32..38].copy_from_slice(&OWN);
        frame
    }

    #[test]
    fn request_uses_zero_sender_ip() {
        let req = request_frame(OWN, TARGET);
        assert_eq!(&req[..6], &[0xff; 6]);
        assert_eq!(&req[6..12], &OWN);
        assert_eq!(&req[28..32], &[0, 0, 0, 0]);
        assert_eq!(&req[38..42], &TARGET.octets());
        assert_eq!(req[20..22], ARP_REQUEST.to_be_bytes());
    }

    #[test]
    fn accepts_correct_reply() {
        assert_eq!(parse_reply(&valid_reply(), OWN, TARGET), Some(PEER));
    }

    #[test]
    fn rejects_reply_for_wrong_ip_or_mac_or_operation() {
        let mut bad_ip = valid_reply();
        bad_ip[28] = 42;
        assert_eq!(parse_reply(&bad_ip, OWN, TARGET), None);
        let mut bad_mac = valid_reply();
        bad_mac[32] ^= 1;
        assert_eq!(parse_reply(&bad_mac, OWN, TARGET), None);
        let mut bad_op = valid_reply();
        bad_op[21] = 1;
        assert_eq!(parse_reply(&bad_op, OWN, TARGET), None);
        let mut bad_eth = valid_reply();
        bad_eth[6] ^= 1;
        assert_eq!(parse_reply(&bad_eth, OWN, TARGET), None);
        assert_eq!(parse_reply(&valid_reply()[..41], OWN, TARGET), None);
    }

    #[test]
    fn parse_mac_validates_syntax() {
        assert_eq!(
            parse_mac("02:01:ab:cd:ef:99").unwrap(),
            [2, 1, 171, 205, 239, 153]
        );
        assert!(parse_mac("02:01:ab:cd:ef").is_err());
        assert!(parse_mac("02:01:ab:cd:ef:gg").is_err());
    }
}
