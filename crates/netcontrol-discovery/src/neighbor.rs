//! Neighbor table (ARP/NDP) reading and unprivileged ARP cache priming.
//!
//! Sending a UDP datagram to an on-link address makes the kernel perform ARP
//! resolution, which populates the neighbor table without raw sockets. This is
//! how NetControl discovers hosts as an unprivileged user. Raw ARP scanning is
//! additionally supported through `arp-scan` when available.

use netcontrol_core::util::normalize_mac;
use netcontrol_core::Result;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::process::Command;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct NeighborEntry {
    pub ip: IpAddr,
    pub mac: Option<String>,
    pub interface: String,
    pub state: Option<String>,
}

pub fn read_table(interface: Option<&str>) -> Vec<NeighborEntry> {
    let mut entries = read_ipv4_arp();
    entries.extend(read_ipv6_neigh(interface));
    let mut seen: HashMap<IpAddr, NeighborEntry> = HashMap::new();
    for entry in entries {
        if let Some(iface) = interface {
            if entry.interface != iface {
                continue;
            }
        }
        seen.entry(entry.ip).or_insert(entry);
    }
    let mut out: Vec<NeighborEntry> = seen.into_values().collect();
    out.sort_by_key(|e| e.ip);
    out
}

#[cfg(target_os = "linux")]
fn read_ipv4_arp() -> Vec<NeighborEntry> {
    let Ok(raw) = std::fs::read_to_string("/proc/net/arp") else {
        return Vec::new();
    };
    raw.lines()
        .skip(1)
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 6 {
                return None;
            }
            let flags = u32::from_str_radix(f[2].trim_start_matches("0x"), 16).unwrap_or(0);
            if flags & 0x2 == 0 {
                return None; // incomplete entry
            }
            let ip: Ipv4Addr = f[0].parse().ok()?;
            let mac = normalize_mac(f[3]);
            Some(NeighborEntry {
                ip: IpAddr::V4(ip),
                mac,
                interface: f[5].to_string(),
                state: Some("reachable".into()),
            })
        })
        .collect()
}

#[cfg(windows)]
fn read_ipv4_arp() -> Vec<NeighborEntry> {
    let Ok(output) = Command::new("arp").arg("-a").output() else {
        return Vec::new();
    };
    let text = String::from_utf8_lossy(&output.stdout);
    let mut current_iface = String::new();
    let mut out = Vec::new();
    for line in text.lines() {
        if let Some(start) = line.find("Interface:") {
            current_iface = line[start + 10..]
                .split_whitespace()
                .next()
                .unwrap_or("")
                .to_string();
            continue;
        }
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() >= 2 {
            if let Ok(ip) = f[0].parse::<Ipv4Addr>() {
                let mac = normalize_mac(f[1]);
                if mac.is_some() {
                    out.push(NeighborEntry {
                        ip: IpAddr::V4(ip),
                        mac,
                        interface: current_iface.clone(),
                        state: Some("reachable".into()),
                    });
                }
            }
        }
    }
    out
}

#[cfg(not(any(target_os = "linux", windows)))]
fn read_ipv4_arp() -> Vec<NeighborEntry> {
    Vec::new()
}

#[cfg(target_os = "linux")]
fn read_ipv6_neigh(interface: Option<&str>) -> Vec<NeighborEntry> {
    let mut command = Command::new("ip");
    command.args(["-6", "neigh", "show"]);
    if let Some(iface) = interface {
        command.args(["dev", iface]);
    }
    let Ok(output) = command.output() else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }
    let text = String::from_utf8_lossy(&output.stdout);
    text.lines()
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.is_empty() {
                return None;
            }
            let ip: IpAddr = f[0].parse().ok()?;
            let mac = f
                .iter()
                .position(|tok| *tok == "lladdr")
                .and_then(|idx| f.get(idx + 1))
                .and_then(|mac| normalize_mac(mac));
            let iface = f
                .iter()
                .position(|tok| *tok == "dev")
                .and_then(|idx| f.get(idx + 1))
                .map(|s| s.to_string())
                .unwrap_or_default();
            let state = f
                .iter()
                .find(|tok| {
                    matches!(
                        tok.to_ascii_uppercase().as_str(),
                        "REACHABLE"
                            | "STALE"
                            | "DELAY"
                            | "PROBE"
                            | "PERMANENT"
                            | "FAILED"
                            | "INCOMPLETE"
                            | "NOARP"
                    )
                })
                .map(|s| s.to_ascii_lowercase());
            Some(NeighborEntry {
                ip,
                mac,
                interface: iface,
                state,
            })
        })
        .collect()
}

#[cfg(not(target_os = "linux"))]
fn read_ipv6_neigh(_interface: Option<&str>) -> Vec<NeighborEntry> {
    Vec::new()
}

/// Populate the kernel ARP cache for every target on the local link.
pub fn prime_arp(local_ip: Ipv4Addr, targets: &[Ipv4Addr], wait: Duration) -> Result<usize> {
    let bind = SocketAddr::V4(SocketAddrV4::new(local_ip, 0));
    let socket = UdpSocket::bind(bind)?;
    socket.set_write_timeout(Some(Duration::from_millis(50)))?;
    let mut sent = 0usize;
    // Batch the probes. Firing 254 datagrams at once overflows the kernel's
    // unresolved-neighbour queue on some drivers, which delays ARP resolution
    // past the scan window.
    for (index, target) in targets.iter().enumerate() {
        // Port 9 (discard) is never expected to answer; the packet exists only
        // to trigger neighbor resolution.
        let dest = SocketAddrV4::new(*target, 9);
        if socket.send_to(&[0u8], dest).is_ok() {
            sent += 1;
        }
        if index % 32 == 31 {
            std::thread::sleep(Duration::from_millis(25));
        }
    }
    std::thread::sleep(wait);
    Ok(sent)
}

/// Parse `arp-scan`'s simple output when the operator has installed it.
pub fn arp_scan(interface: &str, cidr: &str) -> Result<Vec<NeighborEntry>> {
    let output = Command::new("arp-scan")
        .args([
            "--interface",
            interface,
            "--retry",
            "2",
            "--ignoredups",
            cidr,
        ])
        .output()?;
    if !output.status.success() {
        return Err(netcontrol_core::Error::Gateway(format!(
            "arp-scan failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    let text = String::from_utf8_lossy(&output.stdout);
    Ok(text
        .lines()
        .filter_map(|line| {
            let f: Vec<&str> = line.split('\t').collect();
            if f.len() < 2 {
                return None;
            }
            let ip = f[0].trim().parse::<Ipv4Addr>().ok()?;
            let mac = normalize_mac(f[1].trim());
            mac.as_ref()?;
            Some(NeighborEntry {
                ip: IpAddr::V4(ip),
                mac,
                interface: interface.to_string(),
                state: Some("reachable".into()),
            })
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn neighbor_table_reads_without_privileges() {
        let entries = read_table(None);
        for entry in entries {
            if let Some(mac) = &entry.mac {
                assert!(netcontrol_core::util::is_valid_mac(mac));
            }
            assert!(entry.ip.is_ipv4() || entry.ip.is_ipv6());
        }
    }
}
