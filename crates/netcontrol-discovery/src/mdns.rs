//! Minimal but real mDNS (DNS-SD) discovery.
//!
//! Queries service types on 224.0.0.251:5353, parses compressed DNS answers
//! and correlates PTR -> SRV -> A/AAAA records. This yields hostnames and
//! service fingerprints for TVs, printers, speakers, Apple devices and IoT.
//! No external mDNS daemon is required, though coexistence with Avahi is
//! handled using SO_REUSEADDR/SO_REUSEPORT.

use netcontrol_core::{Error, Result};
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::time::{Duration, Instant};

const MDNS_ADDR: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const MDNS_PORT: u16 = 5353;

const SERVICE_TYPES: &[&str] = &[
    "_http._tcp.local",
    "_https._tcp.local",
    "_workstation._tcp.local",
    "_smb._tcp.local",
    "_afpovertcp._tcp.local",
    "_rfb._tcp.local",
    "_ssh._tcp.local",
    "_ipp._tcp.local",
    "_ipps._tcp.local",
    "_printer._tcp.local",
    "_pdl-datastream._tcp.local",
    "_airplay._tcp.local",
    "_raop._tcp.local",
    "_googlecast._tcp.local",
    "_spotify-connect._tcp.local",
    "_sonos._tcp.local",
    "_homekit._tcp.local",
    "_hap._tcp.local",
    "_matter._tcp.local",
    "_companion-link._tcp.local",
    "_apple-mobdev2._tcp.local",
    "_device-info._tcp.local",
    "_axis-video._tcp.local",
    "_onvif._tcp.local",
    "_rtsp._tcp.local",
    "_xbox._tcp.local",
    "_ipp-usb._tcp.local",
    "_uscans._tcp.local",
    "_esphomelib._tcp.local",
    "_shelly._tcp.local",
    "_kdeconnect._udp.local",
    "_nvstream_dbd._tcp.local",
    "_steamlink._tcp.local",
    "_sleep-proxy._udp.local",
];

#[derive(Debug, Clone)]
pub struct MdnsHost {
    pub hostname: Option<String>,
    pub addresses: Vec<IpAddr>,
    pub services: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct MdnsDiscovery {
    pub hosts: Vec<MdnsHost>,
    pub service_types: Vec<String>,
    pub warnings: Vec<String>,
    pub responses: usize,
}

pub fn discover(local_ip: Option<Ipv4Addr>, timeout: Duration) -> Result<MdnsDiscovery> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .map_err(|e| Error::Internal(format!("mDNS socket: {e}")))?;
    socket.set_reuse_address(true).ok();
    #[cfg(target_os = "linux")]
    {
        let _ = socket.set_reuse_port(true);
    }
    let mut warnings = Vec::new();
    let bound = socket.bind(&SocketAddr::from((Ipv4Addr::UNSPECIFIED, MDNS_PORT)).into());
    let socket = if bound.is_ok() {
        socket
    } else {
        warnings.push(format!(
            "mDNS port 5353 unavailable ({}); using an ephemeral port, some responders may be missed",
            bound.err().map(|e| e.to_string()).unwrap_or_default()
        ));
        let fallback = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
            .map_err(|e| Error::Internal(format!("mDNS socket: {e}")))?;
        fallback
            .bind(&SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)).into())
            .map_err(|e| Error::Internal(format!("mDNS bind: {e}")))?;
        fallback
    };
    if let Some(ip) = local_ip {
        if let Err(err) = socket.join_multicast_v4(&MDNS_ADDR, &ip) {
            warnings.push(format!("could not join mDNS multicast group: {err}"));
        }
        socket.set_multicast_if_v4(&ip).ok();
    }
    socket.set_multicast_ttl_v4(255).ok();
    socket
        .set_read_timeout(Some(Duration::from_millis(120)))
        .map_err(|e| Error::Internal(format!("mDNS timeout: {e}")))?;

    let dest = SocketAddr::V4(SocketAddrV4::new(MDNS_ADDR, MDNS_PORT));
    let udp: UdpSocket = socket.into();
    // Keep each query below the legacy 512-byte DNS limit. Several responders
    // (including some embedded stacks) ignore oversized multi-question mDNS
    // queries.
    let mut sent_any = false;
    for batch in SERVICE_TYPES.chunks(4) {
        let query = build_query(batch);
        if udp.send_to(&query, dest).is_ok() {
            sent_any = true;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    if !sent_any {
        return Err(Error::Internal(
            "mDNS query could not be sent on this interface".into(),
        ));
    }

    let deadline = Instant::now() + timeout;
    let mut buf = [0u8; 9000];
    let mut records = Vec::new();
    let mut responses = 0usize;
    while Instant::now() < deadline {
        match udp.recv_from(&mut buf) {
            Ok((size, _)) => {
                if let Some(mut parsed) = parse_message(&buf[..size]) {
                    responses += 1;
                    records.append(&mut parsed);
                }
            }
            Err(err)
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(err) => {
                warnings.push(format!("mDNS receive error: {err}"));
                break;
            }
        }
    }

    Ok(correlate(records, responses, warnings))
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
enum RecordData {
    A(Ipv4Addr),
    Aaaa(std::net::Ipv6Addr),
    Ptr(String),
    Srv { target: String, port: u16 },
    Txt(Vec<String>),
    Other,
}

#[derive(Debug, Clone)]
struct Record {
    name: String,
    data: RecordData,
}

fn correlate(records: Vec<Record>, responses: usize, warnings: Vec<String>) -> MdnsDiscovery {
    let mut ip_to_host: HashMap<IpAddr, String> = HashMap::new();
    let mut host_to_ips: HashMap<String, Vec<IpAddr>> = HashMap::new();
    let mut srv: HashMap<String, (String, u16)> = HashMap::new();
    let mut instance_services: HashMap<String, Vec<String>> = HashMap::new();
    let mut service_types: HashSet<String> = HashSet::new();

    for record in &records {
        match &record.data {
            RecordData::A(ip) => {
                let host = normalize_name(&record.name);
                ip_to_host.insert(IpAddr::V4(*ip), host.clone());
                host_to_ips.entry(host).or_default().push(IpAddr::V4(*ip));
            }
            RecordData::Aaaa(ip) => {
                let host = normalize_name(&record.name);
                ip_to_host.insert(IpAddr::V6(*ip), host.clone());
                host_to_ips.entry(host).or_default().push(IpAddr::V6(*ip));
            }
            RecordData::Srv { target, port } => {
                srv.insert(
                    normalize_name(&record.name),
                    (normalize_name(target), *port),
                );
            }
            RecordData::Ptr(target) => {
                let owner = normalize_name(&record.name);
                let instance = normalize_name(target);
                if owner.starts_with('_') && !owner.starts_with("_services") {
                    service_types.insert(owner.clone());
                    instance_services
                        .entry(instance)
                        .or_default()
                        .push(owner.clone());
                }
            }
            _ => {}
        }
    }

    let mut hosts: HashMap<String, MdnsHost> = HashMap::new();
    // Instances that advertise a service and resolve to a host.
    for (instance, (target, _port)) in &srv {
        let services = instance_services.get(instance).cloned().unwrap_or_default();
        let addresses = host_to_ips.get(target).cloned().unwrap_or_default();
        if addresses.is_empty() {
            continue;
        }
        let entry = hosts.entry(target.clone()).or_insert_with(|| MdnsHost {
            hostname: Some(target.clone()),
            addresses: Vec::new(),
            services: Vec::new(),
        });
        for addr in addresses {
            if !entry.addresses.contains(&addr) {
                entry.addresses.push(addr);
            }
        }
        for service in services {
            if !entry.services.contains(&service) {
                entry.services.push(service);
            }
        }
    }
    // Plain A/AAAA hosts.
    for (host, addresses) in host_to_ips {
        let entry = hosts.entry(host.clone()).or_insert_with(|| MdnsHost {
            hostname: Some(host),
            addresses: Vec::new(),
            services: Vec::new(),
        });
        for addr in addresses {
            if !entry.addresses.contains(&addr) {
                entry.addresses.push(addr);
            }
        }
    }

    let mut hosts: Vec<MdnsHost> = hosts
        .into_values()
        .filter(|h| !h.addresses.is_empty())
        .collect();
    hosts.sort_by(|a, b| a.hostname.cmp(&b.hostname));
    let mut service_types: Vec<String> = service_types.into_iter().collect();
    service_types.sort();
    MdnsDiscovery {
        hosts,
        service_types,
        warnings,
        responses,
    }
}

fn normalize_name(name: &str) -> String {
    name.trim_end_matches('.')
        .trim_end_matches(".local")
        .to_string()
}

fn build_query(services: &[&str]) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.extend_from_slice(&0u16.to_be_bytes()); // id
    packet.extend_from_slice(&0u16.to_be_bytes()); // flags: standard query
    packet.extend_from_slice(&(services.len() as u16).to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes()); // answers
    packet.extend_from_slice(&0u16.to_be_bytes()); // authority
    packet.extend_from_slice(&0u16.to_be_bytes()); // additional
    for service in services {
        encode_name(service, &mut packet);
        packet.extend_from_slice(&12u16.to_be_bytes()); // PTR
        packet.extend_from_slice(&1u16.to_be_bytes()); // IN
    }
    packet
}

fn encode_name(name: &str, out: &mut Vec<u8>) {
    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() || label.len() > 63 {
            continue;
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
}

fn parse_message(data: &[u8]) -> Option<Vec<Record>> {
    if data.len() < 12 {
        return None;
    }
    let flags = u16::from_be_bytes([data[2], data[3]]);
    if flags & 0x8000 == 0 {
        return None; // not a response
    }
    let qd = u16::from_be_bytes([data[4], data[5]]) as usize;
    let an = u16::from_be_bytes([data[6], data[7]]) as usize;
    let ns = u16::from_be_bytes([data[8], data[9]]) as usize;
    let ar = u16::from_be_bytes([data[10], data[11]]) as usize;
    let mut pos = 12usize;
    for _ in 0..qd {
        let _ = read_name(data, &mut pos)?;
        pos = pos.checked_add(4)?;
        if pos > data.len() {
            return None;
        }
    }
    let mut out = Vec::new();
    for _ in 0..(an + ns + ar) {
        let name = read_name(data, &mut pos)?;
        if pos + 10 > data.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
        pos += 4; // type + class
        let _ttl = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
        pos += 4;
        let rdlen = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        if pos + rdlen > data.len() {
            return None;
        }
        let rdata_start = pos;
        let record_data = match rtype {
            1 if rdlen == 4 => RecordData::A(Ipv4Addr::new(
                data[pos],
                data[pos + 1],
                data[pos + 2],
                data[pos + 3],
            )),
            28 if rdlen == 16 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&data[pos..pos + 16]);
                RecordData::Aaaa(std::net::Ipv6Addr::from(octets))
            }
            12 => {
                let mut ptr_pos = pos;
                read_name(data, &mut ptr_pos)
                    .map(RecordData::Ptr)
                    .unwrap_or(RecordData::Other)
            }
            33 => {
                if rdlen >= 7 {
                    let _priority = u16::from_be_bytes([data[pos], data[pos + 1]]);
                    let _weight = u16::from_be_bytes([data[pos + 2], data[pos + 3]]);
                    let port = u16::from_be_bytes([data[pos + 4], data[pos + 5]]);
                    let mut target_pos = pos + 6;
                    match read_name(data, &mut target_pos) {
                        Some(target) => RecordData::Srv { target, port },
                        None => RecordData::Other,
                    }
                } else {
                    RecordData::Other
                }
            }
            16 => {
                let mut strings = Vec::new();
                let mut p = pos;
                while p < pos + rdlen {
                    let len = data[p] as usize;
                    p += 1;
                    if p + len > pos + rdlen {
                        break;
                    }
                    strings.push(String::from_utf8_lossy(&data[p..p + len]).to_string());
                    p += len;
                }
                RecordData::Txt(strings)
            }
            _ => RecordData::Other,
        };
        out.push(Record {
            name,
            data: record_data,
        });
        pos = rdata_start + rdlen;
    }
    Some(out)
}

fn read_name(data: &[u8], pos: &mut usize) -> Option<String> {
    let mut labels = Vec::new();
    let mut cursor = *pos;
    let mut next_pos: Option<usize> = None;
    let mut jumps = 0usize;
    loop {
        if cursor >= data.len() {
            return None;
        }
        let len = data[cursor];
        if len == 0 {
            cursor += 1;
            break;
        }
        if len & 0xc0 == 0xc0 {
            if cursor + 1 >= data.len() {
                return None;
            }
            let offset = (((len & 0x3f) as usize) << 8) | data[cursor + 1] as usize;
            if next_pos.is_none() {
                next_pos = Some(cursor + 2);
            }
            jumps += 1;
            if jumps > 32 || offset >= data.len() {
                return None;
            }
            cursor = offset;
            continue;
        }
        let len = len as usize;
        if len > 63 || cursor + 1 + len > data.len() {
            return None;
        }
        labels.push(String::from_utf8_lossy(&data[cursor + 1..cursor + 1 + len]).to_string());
        cursor += 1 + len;
    }
    *pos = next_pos.unwrap_or(cursor);
    Some(labels.join("."))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_compression_roundtrip() {
        let mut packet = Vec::new();
        encode_name("_http._tcp.local", &mut packet);
        let mut pos = 0;
        assert_eq!(
            read_name(&packet, &mut pos).as_deref(),
            Some("_http._tcp.local")
        );
        assert_eq!(pos, packet.len());
    }

    #[test]
    fn query_is_well_formed() {
        let query = build_query(&["_http._tcp.local", "_ipp._tcp.local"]);
        assert_eq!(&query[4..6], &2u16.to_be_bytes());
        assert_eq!(query[12], 5); // "_http" length
    }

    #[test]
    fn parses_a_record_response() {
        // Header + one A record for "tv.local" 192.168.1.50
        let mut packet = Vec::new();
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&0x8400u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        encode_name("tv.local", &mut packet);
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&120u32.to_be_bytes());
        packet.extend_from_slice(&4u16.to_be_bytes());
        packet.extend_from_slice(&[192, 168, 1, 50]);
        let records = parse_message(&packet).unwrap();
        assert_eq!(records.len(), 1);
        assert!(matches!(records[0].data, RecordData::A(ip) if ip == Ipv4Addr::new(192,168,1,50)));
    }
}
