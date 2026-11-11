//! Discovery orchestration: combine neighbor tables, ARP priming, ICMP, TCP,
//! Nmap, mDNS and reverse DNS into one de-duplicated host inventory.

use crate::icmp::{ping_sweep, tcp_probe};
use crate::interfaces::{InterfaceManager, ToolAvailability};
use crate::mdns;
use crate::neighbor;
use crate::nmap;
use netcontrol_core::classify;
use netcontrol_core::models::{
    DeviceCategory, HostObservation, NetworkInfo, NetworkInterface, ScanMethod, ScanOptions,
    ScanReport,
};
use netcontrol_core::util::{normalize_mac, now_ts, parse_network, usable_hosts, validate_scope};
use netcontrol_core::{Error, Result};
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

pub struct DiscoveryEngine {
    pub tools: ToolAvailability,
}

impl Default for DiscoveryEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl DiscoveryEngine {
    pub fn new() -> Self {
        Self {
            tools: ToolAvailability::detect(),
        }
    }

    pub async fn scan_active(
        &self,
        opts: &ScanOptions,
    ) -> Result<(NetworkInterface, NetworkInfo, ScanReport)> {
        let (iface, net) = InterfaceManager::detect_active(opts.interface.as_deref())?;
        let report = self.scan(&iface, &net, opts).await?;
        Ok((iface, net, report))
    }

    pub async fn scan(
        &self,
        iface: &NetworkInterface,
        net: &NetworkInfo,
        opts: &ScanOptions,
    ) -> Result<ScanReport> {
        self.scan_with_session(iface, net, opts, uuid::Uuid::new_v4().to_string())
            .await
    }

    pub async fn scan_with_session(
        &self,
        iface: &NetworkInterface,
        net: &NetworkInfo,
        opts: &ScanOptions,
        session_id: String,
    ) -> Result<ScanReport> {
        if !opts.confirmed {
            return Err(Error::Forbidden(
                "scan not started: explicit authorization confirmation is required (--yes / confirm=true)"
                    .into(),
            ));
        }
        let started_at = now_ts();
        let parsed = parse_network(&net.cidr)?;
        validate_scope(&parsed, opts.allow_public)?;
        let local_v4: Option<Ipv4Addr> = net.local_ip.parse().ok();
        let gateway: Option<IpAddr> = net.gateway.as_deref().and_then(|g| g.parse().ok());

        let mut hosts: BTreeMap<String, HostObservation> = BTreeMap::new();
        let mut warnings = Vec::new();
        let mut methods_used: Vec<ScanMethod> = Vec::new();
        let mut targets: Vec<Ipv4Addr> = Vec::new();

        if let ipnet::IpNet::V4(_) = parsed {
            targets = usable_hosts(&parsed, opts.max_hosts)?
                .into_iter()
                .filter_map(|ip| match ip {
                    IpAddr::V4(v4) => Some(v4),
                    _ => None,
                })
                .collect();
        } else {
            warnings.push(
                "IPv6 discovery relies on the neighbor table and mDNS; host enumeration of large IPv6 prefixes is intentionally disabled"
                    .into(),
            );
        }

        // 1. Existing neighbor table.
        let neighbors = neighbor::read_table(Some(&iface.name));
        if !targets.is_empty() || !neighbors.is_empty() {
            methods_used.push(ScanMethod::Neighbor);
        }
        merge_neighbors(&mut hosts, &neighbors, &iface.name);

        // 2. Raw ARP when explicitly requested and permitted.
        let wants_arp = opts.methods.contains(&ScanMethod::Arp);
        if wants_arp {
            if self.tools.arp_scan && self.tools.privileged_scan() {
                match neighbor::arp_scan(&iface.name, &net.cidr) {
                    Ok(entries) => {
                        methods_used.push(ScanMethod::Arp);
                        merge_neighbors(&mut hosts, &entries, &iface.name);
                    }
                    Err(err) => warnings.push(format!("arp-scan failed: {err}")),
                }
            } else if self.tools.arp_scan {
                warnings.push(
                    "arp-scan is installed but raw ARP requires root or CAP_NET_RAW; used kernel ARP priming instead"
                        .into(),
                );
            } else {
                warnings.push(
                    "arp-scan is not installed; used unprivileged kernel ARP priming and the neighbor table"
                        .into(),
                );
            }
        }

        // 3. Prime the kernel's neighbor cache with a UDP datagram per target.
        if !targets.is_empty()
            && opts
                .methods
                .iter()
                .any(|m| matches!(m, ScanMethod::Neighbor | ScanMethod::Icmp | ScanMethod::Arp))
        {
            if let Some(local) = local_v4 {
                let prime_targets = targets.clone();
                let sent = tokio::task::spawn_blocking(move || {
                    neighbor::prime_arp(local, &prime_targets, Duration::from_millis(700))
                })
                .await
                .map_err(|e| Error::Internal(format!("ARP priming task failed: {e}")))?;
                if let Ok(count) = sent {
                    tracing::debug!(count, "primed ARP cache");
                }
                let after = neighbor::read_table(Some(&iface.name));
                merge_neighbors(&mut hosts, &after, &iface.name);
            }
        }

        // 4. ICMP echo.
        if opts.methods.contains(&ScanMethod::Icmp) && !targets.is_empty() {
            if let Some(local) = local_v4 {
                let ping_targets = targets.clone();
                let timeout = Duration::from_millis(opts.timeout_ms.clamp(200, 10_000));
                let result =
                    tokio::task::spawn_blocking(move || ping_sweep(local, &ping_targets, timeout))
                        .await
                        .map_err(|e| Error::Internal(format!("ICMP task failed: {e}")))?;
                match result {
                    Ok(replies) => {
                        methods_used.push(ScanMethod::Icmp);
                        for reply in replies {
                            let obs = entry(&mut hosts, &reply.ip.to_string(), "icmp");
                            obs.rtt_ms = Some(reply.rtt_ms);
                        }
                    }
                    Err(err) => warnings.push(format!(
                        "ICMP sweep unavailable ({err}); continuing with ARP/neighbor and mDNS data"
                    )),
                }
            }
        }

        // Active probes (ICMP above, TCP below) make the kernel refresh ARP
        // entries for hosts that do not answer ICMP. Read the table again so
        // MAC addresses and online state are not lost.
        merge_neighbors(
            &mut hosts,
            &neighbor::read_table(Some(&iface.name)),
            &iface.name,
        );

        // 5. Nmap host discovery (optional).
        let wants_nmap = opts.nmap || opts.methods.contains(&ScanMethod::Nmap);
        if wants_nmap {
            if nmap::available(&self.tools.nmap_path_or_default()).await {
                match nmap::discover(
                    &self.tools.nmap_path_or_default(),
                    &net.cidr,
                    Duration::from_secs(120),
                )
                .await
                {
                    Ok(found) => {
                        methods_used.push(ScanMethod::Nmap);
                        merge_observations(&mut hosts, found);
                    }
                    Err(err) => warnings.push(format!("nmap discovery failed: {err}")),
                }
            } else {
                warnings
                    .push("nmap is not installed; skipped Nmap discovery (pacman -S nmap)".into());
            }
        }

        // 6. TCP liveness / explicit port discovery.
        let wants_tcp = opts.ports || opts.methods.contains(&ScanMethod::Tcp);
        if wants_tcp {
            let probe_ports: &[u16] = if opts.ports {
                &[
                    22, 53, 80, 443, 445, 554, 631, 1883, 3389, 5900, 8008, 8080, 8443, 9100,
                    32400, 62078,
                ]
            } else {
                &[22, 80, 443]
            };
            let connect_timeout = Duration::from_millis(350);
            let mut found_tcp = false;
            let mut results = Vec::new();
            {
                use futures::stream::StreamExt;
                let mut stream = futures::stream::iter(targets.iter().copied())
                    .map(|ip| async move {
                        let open = tcp_probe(IpAddr::V4(ip), probe_ports, connect_timeout).await;
                        (ip, open)
                    })
                    .buffer_unordered(64);
                while let Some((ip, open)) = stream.next().await {
                    results.push((ip, open));
                }
            }
            for (ip, open) in results {
                if open.is_empty() {
                    continue;
                }
                found_tcp = true;
                let obs = entry(&mut hosts, &ip.to_string(), "tcp");
                if !obs.services.iter().any(|s| s == "tcp") {
                    obs.services.push("tcp".into());
                }
                if opts.ports {
                    for port in open {
                        if !obs.open_ports.contains(&port) {
                            obs.open_ports.push(port);
                        }
                    }
                }
            }
            if found_tcp {
                methods_used.push(ScanMethod::Tcp);
            }
        }

        merge_neighbors(
            &mut hosts,
            &neighbor::read_table(Some(&iface.name)),
            &iface.name,
        );

        // 7. mDNS service and hostname discovery.
        if opts.mdns && opts.methods.contains(&ScanMethod::Mdns) {
            let timeout = Duration::from_millis(1200);
            let result = tokio::task::spawn_blocking(move || mdns::discover(local_v4, timeout))
                .await
                .map_err(|e| Error::Internal(format!("mDNS task failed: {e}")))?;
            match result {
                Ok(discovery) => {
                    if discovery.responses > 0 {
                        methods_used.push(ScanMethod::Mdns);
                    }
                    warnings.extend(discovery.warnings);
                    for mdns_host in &discovery.hosts {
                        for addr in &mdns_host.addresses {
                            let key = addr.to_string();
                            let obs = entry(&mut hosts, &key, "mdns");
                            if let Some(name) = &mdns_host.hostname {
                                if obs.hostname.is_none() {
                                    obs.hostname = Some(name.clone());
                                }
                            }
                            for service in &mdns_host.services {
                                if !obs.services.iter().any(|s| s == service) {
                                    obs.services.push(service.clone());
                                }
                            }
                        }
                    }
                }
                Err(err) => warnings.push(format!("mDNS discovery failed: {err}")),
            }
        }

        // 8. Reverse DNS for hosts still lacking a hostname (bounded).
        let unresolved: Vec<IpAddr> = hosts
            .values()
            .filter(|h| h.hostname.is_none() && h.ip.is_some())
            .filter_map(|h| h.ip.as_deref().and_then(|ip| ip.parse().ok()))
            .take(64)
            .collect();
        if !unresolved.is_empty() {
            let resolved = reverse_dns_batch(unresolved, 8).await;
            for (ip, name) in resolved {
                if let Some(obs) = hosts.get_mut(&ip.to_string()) {
                    if obs.hostname.is_none() {
                        obs.hostname = Some(name);
                    }
                }
            }
        }

        // The gateway is a known device even if it filters probes.
        if let Some(gw) = gateway {
            if matches!(gw, IpAddr::V4(_)) {
                let obs = entry(&mut hosts, &gw.to_string(), "gateway");
                obs.category = DeviceCategory::Router;
                if obs.hostname.is_none() {
                    obs.hostname = Some("Network gateway".into());
                }
            }
        }

        // 9. Vendor and category enrichment.
        for obs in hosts.values_mut() {
            if obs.ip.as_deref() == Some("") {
                obs.ip = None;
            }
            if let Some(raw_mac) = obs.mac.clone() {
                if let Some(mac) = normalize_mac(&raw_mac) {
                    if obs.vendor.is_none() {
                        obs.vendor = netcontrol_core::oui::lookup(&mac);
                        if obs.vendor.is_none()
                            && netcontrol_core::oui::is_locally_administered(&mac)
                        {
                            obs.vendor = Some("Private (randomized MAC)".into());
                        }
                    }
                    obs.mac = Some(mac);
                } else {
                    obs.mac = None;
                }
            }
            if obs.ip.as_deref() == Some(net.local_ip.as_str()) && obs.mac.is_none() {
                obs.mac = iface.mac.clone();
            }
            if obs.ip.as_deref() == Some(net.local_ip.as_str()) {
                obs.category = DeviceCategory::Desktop;
                if obs.hostname.is_none() {
                    obs.hostname = Some("This host".into());
                }
            }
            if matches!(obs.category, DeviceCategory::Unknown) {
                let result = classify::classify(
                    obs.vendor.as_deref(),
                    obs.hostname.as_deref(),
                    &obs.services,
                    &obs.open_ports,
                );
                obs.category = result.category;
            }
            dedupe(&mut obs.sources);
            dedupe(&mut obs.services);
            obs.open_ports.sort_unstable();
            obs.open_ports.dedup();
            if obs.ip.is_none() && obs.ipv6.is_none() && obs.mac.is_none() {
                obs.sources.clear();
            }
        }

        // Remove observations that carry no address at all.
        hosts.retain(|_, h| h.ip.is_some() || h.ipv6.is_some());
        let mut host_list: Vec<HostObservation> = hosts.into_values().collect();
        sort_hosts(&mut host_list);
        warnings.sort();
        warnings.dedup();

        Ok(ScanReport {
            session_id,
            interface: iface.name.clone(),
            cidr: net.cidr.clone(),
            gateway: net.gateway.clone(),
            started_at,
            finished_at: now_ts(),
            methods_used,
            privileged: self.tools.privileged_scan(),
            hosts: host_list,
            new_devices: 0,
            warnings,
        })
    }
}

fn entry<'a>(
    hosts: &'a mut BTreeMap<String, HostObservation>,
    key: &str,
    source: &str,
) -> &'a mut HostObservation {
    let obs = hosts.entry(key.to_string()).or_insert_with(|| {
        let parsed = key.parse::<IpAddr>().ok();
        let mut obs = HostObservation {
            ip: None,
            ipv6: None,
            mac: None,
            hostname: None,
            vendor: None,
            category: DeviceCategory::Unknown,
            rtt_ms: None,
            open_ports: Vec::new(),
            services: Vec::new(),
            sources: Vec::new(),
        };
        match parsed {
            Some(IpAddr::V4(_)) => obs.ip = Some(key.to_string()),
            Some(IpAddr::V6(_)) => obs.ipv6 = Some(key.to_string()),
            None => {}
        }
        obs
    });
    if !obs.sources.iter().any(|s| s == source) {
        obs.sources.push(source.to_string());
    }
    obs
}

fn merge_neighbors(
    hosts: &mut BTreeMap<String, HostObservation>,
    entries: &[neighbor::NeighborEntry],
    interface: &str,
) {
    for neighbor in entries {
        let key = neighbor.ip.to_string();
        let obs = entry(hosts, &key, "neighbor");
        if obs.mac.is_none() {
            obs.mac = neighbor.mac.clone();
        }
        match neighbor.ip {
            IpAddr::V4(_) => {
                if obs.ip.is_none() {
                    obs.ip = Some(key.clone());
                }
            }
            IpAddr::V6(_) => {
                if obs.ipv6.is_none() {
                    obs.ipv6 = Some(key.clone());
                }
            }
        }
        obs.sources.push(format!("neighbor:{}", neighbor.interface));
        let _ = interface;
    }
}

fn merge_observations(
    hosts: &mut BTreeMap<String, HostObservation>,
    observations: Vec<HostObservation>,
) {
    for found in observations {
        let key = found
            .ip
            .clone()
            .or_else(|| found.ipv6.clone())
            .or_else(|| found.mac.clone())
            .unwrap_or_default();
        if key.is_empty() {
            continue;
        }
        let obs = entry(hosts, &key, "nmap");
        if let Some(ip) = found.ip {
            obs.ip = Some(ip);
        }
        if let Some(ipv6) = found.ipv6 {
            obs.ipv6 = Some(ipv6);
        }
        if let Some(mac) = found.mac {
            obs.mac = Some(mac);
        }
        if let Some(hostname) = found.hostname {
            if obs.hostname.is_none() {
                obs.hostname = Some(hostname);
            }
        }
        if let Some(vendor) = found.vendor {
            if obs.vendor.is_none() {
                obs.vendor = Some(vendor);
            }
        }
        for port in found.open_ports {
            if !obs.open_ports.contains(&port) {
                obs.open_ports.push(port);
            }
        }
        for service in found.services {
            if !obs.services.contains(&service) {
                obs.services.push(service);
            }
        }
        obs.rtt_ms = found.rtt_ms.or(obs.rtt_ms);
    }
}

fn dedupe(values: &mut Vec<String>) {
    let mut seen = std::collections::HashSet::new();
    values.retain(|v| seen.insert(v.to_ascii_lowercase()));
}

fn sort_hosts(hosts: &mut [HostObservation]) {
    hosts.sort_by(|a, b| {
        let key = |h: &HostObservation| -> (u8, u32, String) {
            if let Some(ip) = h.ip.as_deref().and_then(|i| i.parse::<Ipv4Addr>().ok()) {
                (0, u32::from(ip), String::new())
            } else if let Some(ip6) = h.ipv6.as_deref().and_then(|i| i.parse::<Ipv6Addr>().ok()) {
                (1, 0, ip6.to_string())
            } else {
                (2, 0, h.mac.clone().unwrap_or_default())
            }
        };
        key(a).cmp(&key(b))
    });
}

async fn reverse_dns_batch(addrs: Vec<IpAddr>, concurrency: usize) -> Vec<(IpAddr, String)> {
    use futures::stream::StreamExt;
    let results = futures::stream::iter(addrs)
        .map(|ip| async move {
            let hostname = tokio::time::timeout(
                Duration::from_millis(900),
                tokio::task::spawn_blocking(move || reverse_dns(ip)),
            )
            .await
            .ok()
            .and_then(|r| r.ok())
            .flatten();
            hostname.map(|name| (ip, name))
        })
        .buffer_unordered(concurrency)
        .filter_map(|x| async move { x })
        .collect::<Vec<_>>()
        .await;
    results
}

#[cfg(unix)]
fn reverse_dns(ip: IpAddr) -> Option<String> {
    use std::ffi::CStr;
    use std::mem::size_of;
    unsafe {
        let mut buf = [0i8; 256];
        let result = match ip {
            IpAddr::V4(v4) => {
                let sa = libc::sockaddr_in {
                    sin_family: libc::AF_INET as libc::sa_family_t,
                    sin_port: 0,
                    sin_addr: libc::in_addr {
                        s_addr: u32::from_ne_bytes(v4.octets()),
                    },
                    sin_zero: [0; 8],
                };
                libc::getnameinfo(
                    &sa as *const libc::sockaddr_in as *const libc::sockaddr,
                    size_of::<libc::sockaddr_in>() as libc::socklen_t,
                    buf.as_mut_ptr(),
                    buf.len() as libc::socklen_t,
                    std::ptr::null_mut(),
                    0,
                    libc::NI_NAMEREQD,
                )
            }
            IpAddr::V6(v6) => {
                let sa = libc::sockaddr_in6 {
                    sin6_family: libc::AF_INET6 as libc::sa_family_t,
                    sin6_port: 0,
                    sin6_flowinfo: 0,
                    sin6_addr: libc::in6_addr {
                        s6_addr: v6.octets(),
                    },
                    sin6_scope_id: 0,
                };
                libc::getnameinfo(
                    &sa as *const libc::sockaddr_in6 as *const libc::sockaddr,
                    size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                    buf.as_mut_ptr(),
                    buf.len() as libc::socklen_t,
                    std::ptr::null_mut(),
                    0,
                    libc::NI_NAMEREQD,
                )
            }
        };
        if result != 0 {
            return None;
        }
        let name = CStr::from_ptr(buf.as_ptr()).to_string_lossy().to_string();
        let name = name.trim_end_matches('.').to_string();
        if name.is_empty() {
            None
        } else {
            Some(name)
        }
    }
}

#[cfg(not(unix))]
fn reverse_dns(_ip: IpAddr) -> Option<String> {
    None
}

/// Add DHCP lease and gateway client information to a report. This is used by
/// the service once an authorized gateway has returned its client list.
pub fn merge_gateway_clients(
    report: &mut ScanReport,
    clients: &[netcontrol_core::models::GatewayClient],
) {
    let mut map: BTreeMap<String, HostObservation> = report
        .hosts
        .drain(..)
        .filter_map(|h| {
            h.ip.clone()
                .or_else(|| h.ipv6.clone())
                .or_else(|| h.mac.clone())
                .map(|k| (k, h))
        })
        .collect();
    for client in clients {
        let key = client
            .ip
            .clone()
            .or_else(|| client.mac.clone())
            .unwrap_or_default();
        if key.is_empty() {
            continue;
        }
        let obs = entry(&mut map, &key, "dhcp");
        if let Some(mac) = &client.mac {
            obs.mac = Some(mac.clone());
        }
        if let Some(ip) = &client.ip {
            obs.ip = Some(ip.clone());
        }
        if obs.hostname.is_none() {
            obs.hostname = client.hostname.clone();
        }
        if obs.vendor.is_none() {
            obs.vendor = client.vendor.clone();
        }
    }
    let mut hosts: Vec<HostObservation> = map.into_values().collect();
    sort_hosts(&mut hosts);
    report.hosts = hosts;
}

impl ToolAvailability {
    pub fn nmap_path_or_default(&self) -> String {
        // Presence was already checked; use the standard binary name so PATH
        // resolution stays under the operator's control.
        "nmap".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_without_confirmation() {
        let engine = DiscoveryEngine::new();
        let iface = InterfaceManager::choose(None).unwrap();
        let net = InterfaceManager::network_for(&iface).unwrap();
        let opts = ScanOptions::default();
        let result = futures::executor::block_on(engine.scan(&iface, &net, &opts));
        assert!(result.is_err());
    }

    #[test]
    fn sorts_ipv4_numerically() {
        let mut hosts = vec![
            HostObservation::new("192.168.1.20", "test"),
            HostObservation::new("192.168.1.3", "test"),
            HostObservation::new("192.168.1.100", "test"),
        ];
        sort_hosts(&mut hosts);
        assert_eq!(hosts[0].ip.as_deref(), Some("192.168.1.3"));
        assert_eq!(hosts[2].ip.as_deref(), Some("192.168.1.100"));
    }

    #[test]
    fn scan_safe_ip_guard() {
        use netcontrol_core::util::is_scan_safe_ip;
        assert!(is_scan_safe_ip("192.168.1.1".parse().unwrap()));
        assert!(!is_scan_safe_ip("8.8.8.8".parse().unwrap()));
    }
}
