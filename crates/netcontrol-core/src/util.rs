use crate::error::{Error, Result};
use chrono::{SecondsFormat, Utc};
use ipnet::IpNet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub fn now_ts() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}

pub fn parse_ts(value: &str) -> Option<chrono::DateTime<Utc>> {
    chrono::DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}

pub fn normalize_mac(input: &str) -> Option<String> {
    let hex: String = input
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect::<String>()
        .to_ascii_lowercase();
    if hex.len() != 12 || hex.chars().all(|c| c == '0') {
        return None;
    }
    Some(
        hex.as_bytes()
            .chunks(2)
            .map(|c| std::str::from_utf8(c).unwrap_or("00"))
            .collect::<Vec<_>>()
            .join(":"),
    )
}

pub fn is_valid_mac(input: &str) -> bool {
    normalize_mac(input).is_some()
}

pub fn is_private_ipv4(ip: Ipv4Addr) -> bool {
    ip.is_private()
        || ip.is_link_local()
        || ip.is_loopback()
        || ip.octets()[0] == 100 && (64..128).contains(&ip.octets()[1])
}

pub fn is_scan_safe_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_private_ipv4(v4) && !v4.is_loopback() && !v4.is_broadcast(),
        IpAddr::V6(v6) => {
            let first = v6.segments()[0];
            (first & 0xfe00) == 0xfc00 || (first & 0xffc0) == 0xfe80
        }
    }
}

pub fn parse_network(value: &str) -> Result<IpNet> {
    let net: IpNet = value
        .parse()
        .map_err(|_| Error::Validation(format!("invalid CIDR: {value}")))?;
    Ok(net)
}

/// Enumerate usable host addresses. For IPv6 the function refuses to expand a
/// subnet larger than /120 because enumerating a /64 is never appropriate;
/// IPv6 discovery relies on neighbor tables and mDNS instead.
pub fn usable_hosts(net: &IpNet, max_hosts: u32) -> Result<Vec<IpAddr>> {
    let mut out = Vec::new();
    match net {
        IpNet::V4(v4) => {
            if v4.prefix_len() < 16 {
                return Err(Error::Validation(
                    "refusing to enumerate subnets larger than /16; narrow the interface subnet or lower scope"
                        .into(),
                ));
            }
            let network = u32::from(v4.network());
            let broadcast = u32::from(v4.broadcast());
            if broadcast <= network + 1 {
                return Ok(out);
            }
            let count = broadcast - network - 1;
            if count > max_hosts {
                return Err(Error::Validation(format!(
                    "subnet contains {count} hosts which exceeds the configured max_hosts={max_hosts}; increase \
                     max_hosts explicitly if this is intentional"
                )));
            }
            for raw in (network + 1)..broadcast {
                out.push(IpAddr::V4(Ipv4Addr::from(raw)));
            }
        }
        IpNet::V6(v6) => {
            if v6.prefix_len() < 120 {
                return Err(Error::Validation(
                    "IPv6 host enumeration is limited to /120 or narrower; larger prefixes rely on neighbor discovery"
                        .into(),
                ));
            }
            let network = u128::from(v6.network());
            let broadcast = u128::from(v6.broadcast());
            for raw in (network + 1)..broadcast {
                if out.len() as u32 >= max_hosts {
                    return Err(Error::Validation(format!(
                        "subnet exceeds configured max_hosts={max_hosts}"
                    )));
                }
                out.push(IpAddr::V6(Ipv6Addr::from(raw)));
            }
        }
    }
    Ok(out)
}

pub fn prefix_to_netmask(prefix: u8) -> String {
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix.min(32))
    };
    Ipv4Addr::from(mask).to_string()
}

pub fn parse_rate_kbps(value: &str) -> Result<Option<i64>> {
    let raw = value.trim().to_ascii_lowercase().replace(' ', "");
    if raw.is_empty() {
        return Err(Error::Validation("empty bandwidth value".into()));
    }
    if matches!(raw.as_str(), "unlimited" | "none" | "off") {
        return Ok(None);
    }
    let (number, unit) = raw
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .map(|idx| (&raw[..idx], &raw[idx..]))
        .unwrap_or((&raw[..], "kbps"));
    let number: f64 = number
        .parse()
        .map_err(|_| Error::Validation(format!("invalid bandwidth value: {value}")))?;
    if !number.is_finite() || number < 0.0 {
        return Err(Error::Validation(format!(
            "invalid bandwidth value: {value}"
        )));
    }
    let multiplier = match unit {
        "kbps" | "k" | "kbit" | "kbit/s" => 1.0,
        "mbps" | "m" | "mbit" | "mbit/s" => 1_000.0,
        "gbps" | "g" | "gbit" | "gbit/s" => 1_000_000.0,
        "bps" | "b" => 0.001,
        _ => {
            return Err(Error::Validation(format!(
                "unsupported bandwidth unit in {value:?}; use Kbps, Mbps or Gbps"
            )))
        }
    };
    let kbps = (number * multiplier).round() as i64;
    if kbps == 0 {
        Ok(None)
    } else {
        Ok(Some(kbps))
    }
}

pub fn format_kbps(kbps: i64) -> String {
    if kbps >= 1_000_000 {
        format!("{:.2} Gbps", kbps as f64 / 1_000_000.0)
    } else if kbps >= 1_000 {
        format!("{:.2} Mbps", kbps as f64 / 1_000.0)
    } else {
        format!("{kbps} Kbps")
    }
}

pub fn format_bps(bps: u64) -> String {
    let units = ["bps", "Kbps", "Mbps", "Gbps", "Tbps"];
    let mut value = bps as f64;
    let mut idx = 0;
    while value >= 1000.0 && idx < units.len() - 1 {
        value /= 1000.0;
        idx += 1;
    }
    if idx == 0 {
        format!("{bps} bps")
    } else {
        format!("{value:.2} {}", units[idx])
    }
}

pub fn format_bytes(bytes: u64, per_second: bool) -> String {
    let units = ["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut idx = 0;
    while value >= 1000.0 && idx < units.len() - 1 {
        value /= 1000.0;
        idx += 1;
    }
    let suffix = if per_second { "/s" } else { "" };
    if idx == 0 {
        format!("{} B{suffix}", value as u64)
    } else {
        format!("{value:.2} {}{suffix}", units[idx])
    }
}

pub fn format_duration_short(seconds: u64) -> String {
    if seconds < 60 {
        format!("{seconds}s")
    } else if seconds < 3600 {
        format!("{}m", seconds / 60)
    } else if seconds < 86_400 {
        format!("{}h {}m", seconds / 3600, (seconds % 3600) / 60)
    } else {
        format!("{}d", seconds / 86_400)
    }
}

pub fn safe_hostname(value: &str) -> Option<String> {
    let trimmed = value.trim().trim_end_matches('.');
    if trimmed.is_empty() || trimmed.len() > 253 {
        return None;
    }
    let valid = trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
    valid.then(|| trimmed.to_ascii_lowercase())
}

/// Values that must never be written to logs or audit records.
pub const SECRET_FIELD_NAMES: &[&str] = &[
    "password",
    "secret",
    "token",
    "api_key",
    "apikey",
    "authorization",
    "private_key",
    "credential",
];

pub fn redact_for_log(message: &str) -> String {
    let mut out = message.to_string();
    for key in SECRET_FIELD_NAMES {
        for sep in ["=", ":", "=>"] {
            let pattern = format!("{key}{sep}");
            if let Some(idx) = out.to_ascii_lowercase().find(&pattern) {
                let start = idx + pattern.len();
                let end = out[start..]
                    .find([',', ' ', '}', '\n'])
                    .map(|p| start + p)
                    .unwrap_or(out.len());
                out.replace_range(start..end, " [redacted]");
            }
        }
    }
    out
}

pub fn validate_scope(net: &IpNet, allow_public: bool) -> Result<()> {
    if allow_public {
        return Ok(());
    }
    match net {
        IpNet::V4(v4) => {
            if !is_private_ipv4(v4.network()) {
                return Err(Error::Forbidden(format!(
                    "{} is not a private/link-local network. Scanning public address space requires \
                     --allow-public and explicit authorization",
                    net
                )));
            }
        }
        IpNet::V6(v6) => {
            let first = v6.network().segments()[0];
            let safe = (first & 0xfe00) == 0xfc00 || (first & 0xffc0) == 0xfe80;
            if !safe {
                return Err(Error::Forbidden(format!(
                    "{} is not a ULA/link-local IPv6 network. Scanning global IPv6 requires \
                     --allow-public and explicit authorization",
                    net
                )));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_normalization() {
        assert_eq!(
            normalize_mac("AA:BB:CC:DD:EE:FF").as_deref(),
            Some("aa:bb:cc:dd:ee:ff")
        );
        assert_eq!(
            normalize_mac("aabb.ccdd.eeff").as_deref(),
            Some("aa:bb:cc:dd:ee:ff")
        );
        assert!(normalize_mac("00:00:00:00:00:00").is_none());
        assert!(normalize_mac("nope").is_none());
    }

    #[test]
    fn rates() {
        assert_eq!(parse_rate_kbps("10Mbps").unwrap(), Some(10_000));
        assert_eq!(parse_rate_kbps("512Kbps").unwrap(), Some(512));
        assert_eq!(parse_rate_kbps("1Gbps").unwrap(), Some(1_000_000));
        assert_eq!(parse_rate_kbps("unlimited").unwrap(), None);
        assert_eq!(parse_rate_kbps("0").unwrap(), None);
        assert!(parse_rate_kbps("10 widgets").is_err());
    }

    #[test]
    fn scope_guard_blocks_public() {
        let net: IpNet = "8.8.8.0/24".parse().unwrap();
        assert!(validate_scope(&net, false).is_err());
        let net: IpNet = "192.168.18.0/24".parse().unwrap();
        assert!(validate_scope(&net, false).is_ok());
    }

    #[test]
    fn host_enumeration() {
        let net: IpNet = "192.168.1.0/29".parse().unwrap();
        let hosts = usable_hosts(&net, 100).unwrap();
        assert_eq!(hosts.len(), 6);
        let big: IpNet = "10.0.0.0/8".parse().unwrap();
        assert!(usable_hosts(&big, 1024).is_err());
    }

    #[test]
    fn redaction() {
        let msg = "login user=admin password=hunter2 token=abc123 ok";
        let red = redact_for_log(msg);
        assert!(!red.contains("hunter2"));
        assert!(!red.contains("abc123"));
    }
}
