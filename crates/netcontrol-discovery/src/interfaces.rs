//! Network interface and local network detection.
//!
//! Linux is the reference implementation and is tested against Wi-Fi, Ethernet
//! and virtual interfaces. Windows uses the same pnet enumeration plus
//! PowerShell's `Get-NetIPConfiguration` for gateway/DNS metadata (fixed
//! script, no shell interpolation of user input). Android does not run this
//! crate; the mobile client talks to the management service.

use netcontrol_core::models::{InterfaceKind, Ipv4Info, NetworkInfo, NetworkInterface};
use netcontrol_core::util::{is_private_ipv4, prefix_to_netmask};
use netcontrol_core::{Error, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::process::Command;

#[derive(Debug, Clone, Default)]
pub struct ToolAvailability {
    pub nmap: bool,
    pub iw: bool,
    pub arp_scan: bool,
    pub avahi: bool,
    pub nft: bool,
    pub tc: bool,
    pub ip: bool,
    pub root: bool,
    pub cap_net_raw: bool,
}

impl ToolAvailability {
    pub fn detect() -> Self {
        Self {
            nmap: which("nmap"),
            iw: which("iw"),
            arp_scan: which("arp-scan"),
            avahi: which("avahi-browse"),
            nft: which("nft"),
            tc: which("tc"),
            ip: which("ip"),
            root: is_root(),
            cap_net_raw: has_cap_net_raw(),
        }
    }

    pub fn privileged_scan(&self) -> bool {
        self.root || self.cap_net_raw
    }
}

pub fn which(tool: &str) -> bool {
    // Only fixed, internal names are ever passed here.
    let path = std::env::var_os("PATH").unwrap_or_default();
    std::env::split_paths(&path).any(|dir| dir.join(tool).is_file())
}

#[cfg(unix)]
pub fn is_root() -> bool {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() == 0 }
}

#[cfg(not(unix))]
pub fn is_root() -> bool {
    false
}

/// True when the process holds CAP_NET_RAW (bit 13) even without full root.
pub fn has_cap_net_raw() -> bool {
    if is_root() {
        return true;
    }
    #[cfg(target_os = "linux")]
    {
        if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
            for line in status.lines() {
                if let Some(hex) = line.strip_prefix("CapEff:") {
                    if let Ok(bits) = u64::from_str_radix(hex.trim(), 16) {
                        return bits & (1 << 13) != 0;
                    }
                }
            }
        }
    }
    false
}

pub struct InterfaceManager;

impl InterfaceManager {
    pub fn list() -> Result<Vec<NetworkInterface>> {
        let mut interfaces = platform::enumerate()?;
        interfaces.sort_by(|a, b| {
            b.is_default
                .cmp(&a.is_default)
                .then_with(|| b.is_up.cmp(&a.is_up))
                .then_with(|| a.name.cmp(&b.name))
        });
        Ok(interfaces)
    }

    /// Choose the interface the administrator means: explicit preference,
    /// then the default-route interface, then the first usable private network.
    pub fn choose(preferred: Option<&str>) -> Result<NetworkInterface> {
        let interfaces = Self::list()?;
        if let Some(name) = preferred {
            return interfaces
                .into_iter()
                .find(|i| i.name == name)
                .ok_or_else(|| Error::NotFound(format!("network interface {name}")));
        }
        let usable = |i: &NetworkInterface| {
            i.is_up
                && !i.is_loopback
                && i.primary_ipv4().is_some()
                && !matches!(i.kind, InterfaceKind::Virtual | InterfaceKind::Loopback)
        };
        if let Some(iface) = interfaces
            .iter()
            .find(|i| i.is_default && usable(i))
            .cloned()
        {
            return Ok(iface);
        }
        if let Some(iface) = interfaces.iter().find(|i| usable(i)).cloned() {
            return Ok(iface);
        }
        interfaces
            .into_iter()
            .find(|i| i.is_up && i.primary_ipv4().is_some() && !i.is_loopback)
            .ok_or_else(|| {
                Error::NotFound(
                    "no active IPv4 network interface found; connect to Wi-Fi or Ethernet".into(),
                )
            })
    }

    pub fn network_for(iface: &NetworkInterface) -> Result<NetworkInfo> {
        let v4 = iface.primary_ipv4().ok_or_else(|| {
            Error::NotFound(format!(
                "interface {} has no IPv4 address; IPv6-only discovery is limited to neighbor tables",
                iface.name
            ))
        })?;
        Ok(NetworkInfo {
            id: None,
            interface: iface.name.clone(),
            kind: iface.kind,
            ssid: iface.ssid.clone(),
            cidr: v4.cidr.clone(),
            local_ip: v4.address.clone(),
            gateway: iface.gateway4.clone(),
            dns: iface.dns.clone(),
            mac: iface.mac.clone(),
            online: iface.is_up,
            first_seen: None,
            last_seen: None,
        })
    }

    pub fn detect_active(preferred: Option<&str>) -> Result<(NetworkInterface, NetworkInfo)> {
        let iface = Self::choose(preferred)?;
        let net = Self::network_for(&iface)?;
        Ok((iface, net))
    }

    /// Every connected interface with an IPv4 network, including secondary
    /// Wi-Fi/Ethernet/USB adapters. Useful for the interface picker.
    pub fn connected_networks() -> Result<Vec<(NetworkInterface, NetworkInfo)>> {
        let mut out = Vec::new();
        for iface in Self::list()? {
            if iface.is_up && !iface.is_loopback && iface.primary_ipv4().is_some() {
                match Self::network_for(&iface) {
                    Ok(net) => out.push((iface, net)),
                    Err(_) => continue,
                }
            }
        }
        Ok(out)
    }
}

fn ipv4_from_pnet(v4: ipnetwork::Ipv4Network) -> Ipv4Info {
    let prefix = v4.prefix();
    Ipv4Info {
        address: v4.ip().to_string(),
        prefix,
        netmask: prefix_to_netmask(prefix),
        broadcast: (prefix < 31).then(|| v4.broadcast().to_string()),
        cidr: v4.to_string(),
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use super::*;
    use netcontrol_core::util::normalize_mac;
    use pnet_datalink::NetworkInterface as PnetInterface;

    pub fn enumerate() -> Result<Vec<NetworkInterface>> {
        let routes = default_routes_v4();
        let best_route = routes
            .iter()
            .min_by_key(|(_, (_, metric))| *metric)
            .map(|(name, _)| name.clone());
        let default_v6 = default_route_v6();
        let mut out = Vec::new();
        for pnet in pnet_datalink::interfaces() {
            if pnet.name.is_empty() {
                continue;
            }
            let gateway4 = routes.get(&pnet.name).map(|(gateway, _)| gateway.clone());
            let is_default = best_route.as_deref() == Some(pnet.name.as_str());
            let iface = convert(pnet, gateway4, is_default, default_v6.as_ref())?;
            out.push(iface);
        }
        Ok(out)
    }

    fn convert(
        pnet: PnetInterface,
        gateway4: Option<String>,
        is_default: bool,
        default_v6: Option<&(String, String)>,
    ) -> Result<NetworkInterface> {
        let name = pnet.name.clone();
        let is_loopback = pnet.is_loopback() || name == "lo";
        let sysfs = format!("/sys/class/net/{name}");
        let wireless =
            std::path::Path::new(&format!("{sysfs}/wireless")).exists() || name.starts_with("wl");
        let usb = device_is_usb(&sysfs);
        let kind = if is_loopback {
            InterfaceKind::Loopback
        } else if wireless {
            InterfaceKind::Wifi
        } else if usb && (name.starts_with("en") || name.starts_with("eth")) {
            InterfaceKind::UsbEthernet
        } else if is_virtual_name(&name) {
            InterfaceKind::Virtual
        } else if name.starts_with("en") || name.starts_with("eth") {
            InterfaceKind::Ethernet
        } else {
            InterfaceKind::Other
        };

        let mut ipv4 = Vec::new();
        let mut ipv6 = Vec::new();
        for ip in &pnet.ips {
            match ip {
                ipnetwork::IpNetwork::V4(v4) => ipv4.push(ipv4_from_pnet(*v4)),
                ipnetwork::IpNetwork::V6(v6) => ipv6.push(v6.ip().to_string()),
            }
        }
        ipv4.sort_by_key(|v| {
            let addr: Ipv4Addr = v.address.parse().unwrap_or(Ipv4Addr::UNSPECIFIED);
            (!is_private_ipv4(addr), addr.octets())
        });
        ipv4.dedup_by(|a, b| a.address == b.address);

        let gateway6 = default_v6
            .filter(|(iface, _)| iface == &name)
            .map(|(_, gw)| gw.clone());
        let dns = dns_for_interface(&name);
        let ssid = if matches!(kind, InterfaceKind::Wifi) {
            ssid_for_interface(&name)
        } else {
            None
        };
        let operstate = std::fs::read_to_string(format!("{sysfs}/operstate"))
            .unwrap_or_else(|_| "unknown".into())
            .trim()
            .to_ascii_lowercase();
        let is_up = pnet.is_up()
            && !matches!(
                operstate.as_str(),
                "down" | "no-carrier" | "lowerlayerdown" | "notpresent"
            );
        let speed_mbps = std::fs::read_to_string(format!("{sysfs}/speed"))
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .filter(|v| *v > 0);
        let driver = std::fs::read_link(format!("{sysfs}/device/driver"))
            .ok()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()));

        Ok(NetworkInterface {
            is_default,
            mac: pnet
                .mac
                .map(|m| m.to_string())
                .and_then(|m| normalize_mac(&m)),
            name,
            kind,
            is_up,
            is_loopback,
            ipv4,
            ipv6,
            gateway4,
            gateway6,
            dns,
            ssid,
            speed_mbps,
            driver,
            usb,
        })
    }

    fn is_virtual_name(name: &str) -> bool {
        const PREFIXES: &[&str] = &[
            "docker",
            "br-",
            "virbr",
            "veth",
            "tun",
            "tap",
            "wg",
            "tailscale",
            "zt",
            "vmnet",
            "vboxnet",
            "podman",
            "cni",
            "flannel",
            "kube",
            "lo",
        ];
        PREFIXES.iter().any(|p| name.starts_with(p))
    }

    fn device_is_usb(sysfs: &str) -> bool {
        std::fs::canonicalize(format!("{sysfs}/device"))
            .map(|p| p.to_string_lossy().contains("/usb"))
            .unwrap_or(false)
    }

    /// Every interface can carry its own default route (Wi-Fi + Ethernet
    /// simultaneously). The kernel stores IPv4 addresses in little-endian hex,
    /// so the octets must be reversed explicitly.
    fn default_routes_v4() -> std::collections::HashMap<String, (String, u32)> {
        let mut routes = std::collections::HashMap::new();
        let Ok(raw) = std::fs::read_to_string("/proc/net/route") else {
            return routes;
        };
        for line in raw.lines().skip(1) {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 8 {
                continue;
            }
            let dest = u32::from_str_radix(f[1], 16).unwrap_or(1);
            let gw = f[2];
            let flags = u32::from_str_radix(f[3], 16).unwrap_or(0);
            let metric = f[6].parse::<u32>().unwrap_or(u32::MAX);
            if dest != 0 || flags & 0x1 == 0 || gw == "00000000" || gw.len() != 8 {
                continue;
            }
            let octet = |idx: usize| u8::from_str_radix(&gw[idx * 2..idx * 2 + 2], 16).unwrap_or(0);
            let gateway = Ipv4Addr::new(octet(3), octet(2), octet(1), octet(0)).to_string();
            let entry = routes.entry(f[0].to_string()).or_insert((gateway, metric));
            if metric < entry.1 {
                *entry = (entry.0.clone(), metric);
            }
        }
        routes
    }

    fn default_route_v6() -> Option<(String, String)> {
        let raw = std::fs::read_to_string("/proc/net/ipv6_route").ok()?;
        for line in raw.lines() {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 10 {
                continue;
            }
            if f[0].chars().all(|c| c == '0')
                && f[1] == "00"
                && f[4] != "00000000000000000000000000000000"
            {
                let hex = f[4];
                let mut segments = [0u16; 8];
                for (i, seg) in hex.as_bytes().chunks(4).take(8).enumerate() {
                    if let Ok(value) =
                        u16::from_str_radix(std::str::from_utf8(seg).unwrap_or("0"), 16)
                    {
                        segments[i] = value;
                    }
                }
                let gw = Ipv6Addr::from(segments).to_string();
                return Some((f[9].to_string(), gw));
            }
        }
        None
    }

    fn dns_for_interface(name: &str) -> Vec<String> {
        // resolvectl is the authoritative per-link view on systemd-resolved
        // systems (Arch/Omarchy default). Fall back to resolv.conf.
        if let Ok(output) = Command::new("resolvectl").args(["dns", name]).output() {
            if output.status.success() {
                let text = String::from_utf8_lossy(&output.stdout);
                let servers: Vec<String> = text
                    .split(|c: char| c.is_whitespace() || c == ':')
                    .filter(|token| token.parse::<IpAddr>().is_ok())
                    .map(|token| token.to_string())
                    .collect();
                if !servers.is_empty() {
                    return servers;
                }
            }
        }
        std::fs::read_to_string("/etc/resolv.conf")
            .map(|raw| {
                raw.lines()
                    .filter_map(|line| line.trim().strip_prefix("nameserver "))
                    .filter_map(|ip| ip.trim().parse::<IpAddr>().ok())
                    .filter(|ip| !ip.is_loopback())
                    .map(|ip| ip.to_string())
                    .collect()
            })
            .unwrap_or_default()
    }

    fn ssid_for_interface(name: &str) -> Option<String> {
        if let Ok(output) = Command::new("iw").args(["dev", name, "link"]).output() {
            if output.status.success() {
                let text = String::from_utf8_lossy(&output.stdout);
                for line in text.lines() {
                    let line = line.trim();
                    if let Some(ssid) = line.strip_prefix("SSID:") {
                        let ssid = ssid.trim();
                        if !ssid.is_empty() {
                            return Some(ssid.to_string());
                        }
                    }
                }
            }
        }
        if let Ok(output) = Command::new("iwgetid").args(["-r", name]).output() {
            if output.status.success() {
                let ssid = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !ssid.is_empty() {
                    return Some(ssid);
                }
            }
        }
        None
    }
}

#[cfg(windows)]
mod platform {
    use super::*;
    use netcontrol_core::util::normalize_mac;
    use serde_json::Value;

    #[derive(Default, Clone)]
    struct WinMeta {
        alias: String,
        description: String,
        gateway: Option<String>,
        dns: Vec<String>,
        ssid: Option<String>,
        speed: Option<u64>,
    }

    pub fn enumerate() -> Result<Vec<NetworkInterface>> {
        let meta = windows_metadata();
        let mut out = Vec::new();
        for pnet in pnet_datalink::interfaces() {
            if pnet.name.is_empty() {
                continue;
            }
            let info = meta.iter().find(|m| {
                m.alias.eq_ignore_ascii_case(&pnet.name) || m.description == pnet.description
            });
            let is_loopback = pnet.is_loopback();
            let mut ipv4 = Vec::new();
            let mut ipv6 = Vec::new();
            for ip in &pnet.ips {
                match ip {
                    ipnetwork::IpNetwork::V4(v4) => ipv4.push(ipv4_from_pnet(*v4)),
                    ipnetwork::IpNetwork::V6(v6) => ipv6.push(v6.ip().to_string()),
                }
            }
            let gateway4 = info.and_then(|m| m.gateway.clone());
            let desc = pnet.description.to_ascii_lowercase();
            let kind = if is_loopback {
                InterfaceKind::Loopback
            } else if info.and_then(|m| m.ssid.as_ref()).is_some() || desc.contains("wireless") {
                InterfaceKind::Wifi
            } else if desc.contains("usb") {
                InterfaceKind::UsbEthernet
            } else if desc.contains("virtual")
                || desc.contains("hyper-v")
                || desc.contains("vmware")
                || desc.contains("tap")
            {
                InterfaceKind::Virtual
            } else {
                InterfaceKind::Ethernet
            };
            out.push(NetworkInterface {
                is_default: gateway4.is_some(),
                name: pnet.name.clone(),
                kind,
                mac: pnet
                    .mac
                    .map(|m| m.to_string())
                    .and_then(|m| normalize_mac(&m)),
                is_up: pnet.is_up(),
                is_loopback,
                ipv4,
                ipv6,
                gateway4,
                gateway6: None,
                dns: info.map(|m| m.dns.clone()).unwrap_or_default(),
                ssid: info.and_then(|m| m.ssid.clone()),
                speed_mbps: info.and_then(|m| m.speed),
                driver: None,
                usb: desc.contains("usb"),
            });
        }
        Ok(out)
    }

    fn windows_metadata() -> Vec<WinMeta> {
        let script = "Get-NetIPConfiguration | Select-Object InterfaceAlias,InterfaceDescription,@{n='Gateway';e={$_.IPv4DefaultGateway.NextHop}},@{n='Dns';e={$_.DNSServer.ServerAddresses}},@{n='Ssid';e={$_.NetProfile.Name}},@{n='Speed';e={$_.NetAdapter.LinkSpeed}} | ConvertTo-Json -Compress";
        let output = Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", script])
            .output();
        let Ok(output) = output else {
            return Vec::new();
        };
        if !output.status.success() {
            return Vec::new();
        }
        let text = String::from_utf8_lossy(&output.stdout);
        let value: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
        let items: Vec<&Value> = match &value {
            Value::Array(items) => items.iter().collect(),
            Value::Object(_) => vec![&value],
            _ => Vec::new(),
        };
        items
            .into_iter()
            .map(|item| {
                let dns = item
                    .get("Dns")
                    .map(|v| match v {
                        Value::Array(a) => a
                            .iter()
                            .filter_map(|x| x.as_str().map(str::to_string))
                            .collect(),
                        Value::String(s) => vec![s.clone()],
                        _ => Vec::new(),
                    })
                    .unwrap_or_default();
                let speed = item
                    .get("Speed")
                    .and_then(|v| v.as_str())
                    .and_then(parse_link_speed_mbps);
                WinMeta {
                    alias: item
                        .get("InterfaceAlias")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string(),
                    description: item
                        .get("InterfaceDescription")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string(),
                    gateway: item
                        .get("Gateway")
                        .and_then(Value::as_str)
                        .map(str::to_string),
                    dns,
                    ssid: item
                        .get("Ssid")
                        .and_then(Value::as_str)
                        .filter(|s| !s.is_empty())
                        .map(str::to_string),
                    speed,
                }
            })
            .collect()
    }

    fn parse_link_speed_mbps(value: &str) -> Option<u64> {
        let raw = value.trim();
        let number: f64 = raw
            .trim_end_matches("bps")
            .trim_end_matches(' ')
            .parse()
            .ok()?;
        let mbps = if raw.contains("Gbps") {
            number * 1000.0
        } else if raw.contains("Mbps") {
            number
        } else if raw.contains("Kbps") {
            number / 1000.0
        } else {
            number / 1_000_000.0
        };
        Some(mbps.round() as u64)
    }
}

#[cfg(not(any(target_os = "linux", windows)))]
mod platform {
    use super::*;
    pub fn enumerate() -> Result<Vec<NetworkInterface>> {
        let mut out = Vec::new();
        for pnet in pnet_datalink::interfaces() {
            let mut ipv4 = Vec::new();
            let mut ipv6 = Vec::new();
            for ip in &pnet.ips {
                match ip {
                    ipnetwork::IpNetwork::V4(v4) => ipv4.push(ipv4_from_pnet(*v4)),
                    ipnetwork::IpNetwork::V6(v6) => ipv6.push(v6.ip().to_string()),
                }
            }
            out.push(NetworkInterface {
                is_default: false,
                name: pnet.name.clone(),
                kind: if pnet.is_loopback() {
                    InterfaceKind::Loopback
                } else {
                    InterfaceKind::Other
                },
                mac: pnet.mac.map(|m| m.to_string()),
                is_up: pnet.is_up(),
                is_loopback: pnet.is_loopback(),
                ipv4,
                ipv6,
                gateway4: None,
                gateway6: None,
                dns: Vec::new(),
                ssid: None,
                speed_mbps: None,
                driver: None,
                usb: false,
            });
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lists_interfaces_and_chooses_one() {
        let ifaces = InterfaceManager::list().expect("list interfaces");
        assert!(!ifaces.is_empty());
        assert!(ifaces.iter().any(|i| i.is_loopback));
        for iface in &ifaces {
            for v4 in &iface.ipv4 {
                assert!(v4.cidr.contains('/'));
                assert!(v4.netmask.parse::<Ipv4Addr>().is_ok());
            }
        }
    }

    #[test]
    fn detects_network_details() {
        let ifaces = InterfaceManager::connected_networks().expect("networks");
        for (iface, net) in ifaces {
            assert_eq!(iface.name, net.interface);
            assert!(net.cidr.contains('/'));
            assert!(!net.local_ip.is_empty());
        }
    }
}
