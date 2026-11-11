//! ICMP echo discovery.
//!
//! Linux exposes unprivileged ICMP datagram sockets (the `ping_group_range`
//! sysctl), so a normal user can sweep a LAN without setuid binaries. If the
//! kernel refuses, the scanner reports the limitation instead of silently
//! claiming hosts are offline.

use netcontrol_core::{Error, Result};
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct PingReply {
    pub ip: Ipv4Addr,
    pub rtt_ms: f64,
}

pub fn ping_sweep(
    local_ip: Ipv4Addr,
    targets: &[Ipv4Addr],
    timeout: Duration,
) -> Result<Vec<PingReply>> {
    if targets.is_empty() {
        return Ok(Vec::new());
    }
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4))
        .map_err(|e| Error::Unsupported(format!("unprivileged ICMP unavailable: {e}")))?;
    socket
        .set_read_timeout(Some(Duration::from_millis(60)))
        .map_err(|e| Error::Internal(format!("ICMP socket setup failed: {e}")))?;
    let bind = SocketAddr::V4(SocketAddrV4::new(local_ip, 0));
    socket
        .bind(&bind.into())
        .map_err(|e| Error::Unsupported(format!("cannot bind ICMP socket: {e}")))?;
    let udp: UdpSocket = socket.into();

    let id = (std::process::id() & 0xffff) as u16;
    let started = Instant::now();
    let mut sent_at: HashMap<u16, Instant> = HashMap::new();
    for (index, target) in targets.iter().enumerate() {
        let seq = ((index + 1) & 0xffff) as u16;
        if seq == 0 {
            continue;
        }
        let packet = echo_request(id, seq);
        if udp.send_to(&packet, SocketAddrV4::new(*target, 0)).is_ok() {
            sent_at.insert(seq, Instant::now());
        }
    }

    let deadline = started + timeout;
    let mut buf = [0u8; 1500];
    let mut replies: HashMap<Ipv4Addr, f64> = HashMap::new();
    while Instant::now() < deadline {
        match udp.recv_from(&mut buf) {
            Ok((size, SocketAddr::V4(from))) => {
                let data = &buf[..size];
                let icmp = strip_ip_header(data);
                if icmp.len() < 8 {
                    continue;
                }
                let kind = icmp[0];
                if kind != 0 {
                    continue; // only echo replies
                }
                let seq = u16::from_be_bytes([icmp[6], icmp[7]]);
                if let Some(sent) = sent_at.get(&seq) {
                    let rtt = sent.elapsed().as_secs_f64() * 1000.0;
                    replies
                        .entry(*from.ip())
                        .and_modify(|existing| *existing = existing.min(rtt))
                        .or_insert(rtt);
                }
            }
            Ok(_) => continue,
            Err(err)
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                continue;
            }
            Err(err) => return Err(Error::Io(err)),
        }
    }
    let mut out: Vec<PingReply> = replies
        .into_iter()
        .map(|(ip, rtt_ms)| PingReply { ip, rtt_ms })
        .collect();
    out.sort_by_key(|r| r.ip);
    Ok(out)
}

fn echo_request(id: u16, seq: u16) -> [u8; 24] {
    let mut packet = [0u8; 24];
    packet[0] = 8; // echo request
    packet[4] = (id >> 8) as u8;
    packet[5] = id as u8;
    packet[6] = (seq >> 8) as u8;
    packet[7] = seq as u8;
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    packet[8..16].copy_from_slice(&stamp.to_be_bytes());
    // Linux ping sockets compute the checksum; raw sockets need it.
    let checksum = checksum(&packet);
    packet[2] = (checksum >> 8) as u8;
    packet[3] = checksum as u8;
    packet
}

fn checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut chunks = data.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    if let Some(rest) = chunks.remainder().first() {
        sum += (*rest as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Raw sockets include the IPv4 header; ping sockets do not.
fn strip_ip_header(data: &[u8]) -> &[u8] {
    if !data.is_empty() && data[0] >> 4 == 4 {
        let ihl = (data[0] & 0x0f) as usize * 4;
        if data.len() > ihl {
            return &data[ihl..];
        }
    }
    data
}

/// A bounded TCP connect probe. Used as a fallback when ICMP is unavailable
/// and as the explicit port-discovery mechanism.
pub async fn tcp_probe(target: IpAddr, ports: &[u16], timeout: Duration) -> Vec<u16> {
    let mut open = Vec::new();
    for port in ports {
        let addr = SocketAddr::new(target, *port);
        match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => {
                open.push(*port);
                drop(stream);
            }
            _ => continue,
        }
    }
    open
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_is_stable() {
        let packet = echo_request(1, 1);
        assert_eq!(packet[0], 8);
        // Checksum of a valid ICMP packet with checksum field zeroed and
        // recalculated must match.
        let mut zeroed = packet;
        zeroed[2] = 0;
        zeroed[3] = 0;
        assert_eq!(
            u16::from_be_bytes([packet[2], packet[3]]),
            checksum(&zeroed)
        );
    }

    #[test]
    fn ip_header_stripping() {
        let data = [0u8; 8];
        assert_eq!(strip_ip_header(&data).len(), 8);
    }
}
