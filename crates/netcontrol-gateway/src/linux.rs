//! Linux gateway enforcement.
//!
//! Blocking uses nftables (`inet netcontrol` table with a timeout-capable set)
//! on the forward hook. Bandwidth shaping uses HTB on the LAN interface for
//! download and ingress policing for upload. Both require CAP_NET_ADMIN, so an
//! unprivileged NetControl process delegates to the whitelist-only
//! `netcontrol-helper` binary through `sudo -n`.
//!
//! No shell is ever used. Every value is validated before it becomes an nft
//! script token or a tc argument.

use crate::traits::{verify_result, AdapterSecret, EnforcedRule, GatewayAdapter, Target};
use async_trait::async_trait;
use netcontrol_core::models::{
    BandwidthLimit, EnforcementResult, GatewayCapabilities, GatewayClient, GatewayConfig,
    GatewayKind, GatewayProbe,
};
use netcontrol_core::util::normalize_mac;
use netcontrol_core::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Instant;

pub const NFT_TABLE: &str = "netcontrol";
const HELPER_ENV: &str = "NETCONTROL_HELPER";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum HelperRequest {
    Status {
        interface: Option<String>,
    },
    Block {
        ip: Option<String>,
        mac: Option<String>,
        expires_at: Option<String>,
    },
    Unblock {
        ip: Option<String>,
        mac: Option<String>,
    },
    SetLimit {
        ip: Option<String>,
        mac: Option<String>,
        interface: Option<String>,
        download_kbps: Option<i64>,
        upload_kbps: Option<i64>,
        priority: Option<i32>,
    },
    ClearLimit {
        ip: Option<String>,
        mac: Option<String>,
        interface: Option<String>,
    },
    List,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelperResponse {
    pub ok: bool,
    pub verified: bool,
    pub detail: String,
    pub rule_id: Option<String>,
    #[serde(default)]
    pub data: serde_json::Value,
}

impl HelperResponse {
    fn ok(detail: impl Into<String>, verified: bool) -> Self {
        Self {
            ok: true,
            verified,
            detail: detail.into(),
            rule_id: None,
            data: serde_json::Value::Null,
        }
    }

    fn fail(detail: impl Into<String>) -> Self {
        Self {
            ok: false,
            verified: false,
            detail: detail.into(),
            rule_id: None,
            data: serde_json::Value::Null,
        }
    }
}

fn validate_ipv4(value: &str) -> Result<Ipv4Addr> {
    let ip: Ipv4Addr = value
        .trim()
        .parse()
        .map_err(|_| Error::Validation(format!("invalid IPv4 address: {value}")))?;
    if !netcontrol_core::util::is_scan_safe_ip(std::net::IpAddr::V4(ip)) {
        return Err(Error::Validation(format!(
            "{ip} is not a private, link-local or loopback address; refusing to enforce on it"
        )));
    }
    Ok(ip)
}

fn validate_interface(value: &str) -> Result<String> {
    if value.is_empty()
        || value.len() > 32
        || !value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        return Err(Error::Validation(format!(
            "invalid network interface name: {value:?}"
        )));
    }
    Ok(value.to_string())
}

fn validate_rate(value: Option<i64>) -> Result<Option<i64>> {
    match value {
        None => Ok(None),
        Some(0) => Ok(None),
        Some(rate) if (1..=10_000_000).contains(&rate) => Ok(Some(rate)),
        Some(_) => Err(Error::Validation(
            "bandwidth must be between 1 Kbps and 10 Gbps".into(),
        )),
    }
}

fn validate_priority(priority: Option<i32>) -> Result<Option<i32>> {
    match priority {
        None => Ok(None),
        Some(p) if (0..=7).contains(&p) => Ok(Some(p)),
        Some(_) => Err(Error::Validation("priority must be 0..7".into())),
    }
}

fn resolve_ip(ip: Option<&str>, mac: Option<&str>) -> Result<Ipv4Addr> {
    if let Some(ip) = ip.filter(|v| !v.trim().is_empty()) {
        return validate_ipv4(ip);
    }
    if let Some(mac) = mac.and_then(normalize_mac) {
        if let Some(found) = arp_ip_for_mac(&mac) {
            return validate_ipv4(&found);
        }
        return Err(Error::Unsupported(
            "this L3 gateway can only enforce on an IP address; the MAC is not currently present in the ARP table"
                .into(),
        ));
    }
    Err(Error::Validation("an IP or MAC target is required".into()))
}

fn arp_ip_for_mac(mac: &str) -> Option<String> {
    let raw = std::fs::read_to_string("/proc/net/arp").ok()?;
    raw.lines().skip(1).find_map(|line| {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() >= 6 && normalize_mac(fields[3]).as_deref() == Some(mac) {
            Some(fields[0].to_string())
        } else {
            None
        }
    })
}

fn run_command(program: &str, args: &[&str], stdin: Option<&str>) -> Result<(bool, String)> {
    let mut command = Command::new(program);
    command
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if stdin.is_some() {
        command.stdin(Stdio::piped());
    }
    let mut child = command
        .spawn()
        .map_err(|e| Error::Unsupported(format!("cannot execute {program}: {e}")))?;
    if let (Some(data), Some(pipe)) = (stdin, child.stdin.as_mut()) {
        use std::io::Write;
        pipe.write_all(data.as_bytes())?;
    }
    let output = child.wait_with_output()?;
    let mut text = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if !stderr.is_empty() {
        if !text.is_empty() {
            text.push('\n');
        }
        text.push_str(&stderr);
    }
    Ok((output.status.success(), text))
}

fn nft_available() -> bool {
    Command::new("nft")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

pub fn table_script() -> String {
    r#"table inet netcontrol {
  set blocked {
    type ipv4_addr
    flags timeout
  }
  chain forward {
    type filter hook forward priority 0; policy accept;
    ip saddr @blocked drop
    ip daddr @blocked drop
  }
}
"#
    .to_string()
}

fn block_script(ip: Ipv4Addr, seconds: Option<u64>) -> String {
    match seconds {
        Some(seconds) => {
            format!("add element inet netcontrol blocked {{ {ip} timeout {seconds}s }}\n")
        }
        None => format!("add element inet netcontrol blocked {{ {ip} }}\n"),
    }
}

fn unblock_script(ip: Ipv4Addr) -> String {
    format!("delete element inet netcontrol blocked {{ {ip} }}\n")
}

fn ensure_table() -> Result<()> {
    let (exists, _) = run_command("nft", &["list", "table", "inet", NFT_TABLE], None)?;
    if !exists {
        let (ok, detail) = run_command("nft", &["-f", "-"], Some(&table_script()))?;
        if !ok {
            return Err(Error::Gateway(format!(
                "nftables table creation failed: {detail}"
            )));
        }
    } else {
        // Repair a partially created table (for example after a manual flush).
        let (set_ok, _) = run_command("nft", &["list", "set", "inet", NFT_TABLE, "blocked"], None)?;
        if !set_ok {
            let (ok, detail) = run_command("nft", &["-f", "-"], Some(&table_script()))?;
            if !ok {
                return Err(Error::Gateway(format!(
                    "nftables table repair failed: {detail}"
                )));
            }
        }
    }
    Ok(())
}

fn blocked_ips() -> Result<Vec<String>> {
    let (ok, output) = run_command("nft", &["list", "set", "inet", NFT_TABLE, "blocked"], None)?;
    if !ok {
        return Ok(Vec::new());
    }
    let mut ips = Vec::new();
    for token in
        output.split(|c: char| c.is_whitespace() || c == ',' || c == ';' || c == '{' || c == '}')
    {
        let token = token.trim();
        if token.parse::<Ipv4Addr>().is_ok() {
            ips.push(token.to_string());
        }
    }
    ips.sort();
    ips.dedup();
    Ok(ips)
}

fn parse_expiry_seconds(expires_at: Option<&str>) -> Result<Option<u64>> {
    let Some(value) = expires_at else {
        return Ok(None);
    };
    let parsed = netcontrol_core::util::parse_ts(value)
        .ok_or_else(|| Error::Validation("expires_at must be RFC3339".into()))?;
    let seconds = (parsed - chrono::Utc::now()).num_seconds();
    Ok(Some(seconds.max(5) as u64))
}

fn minor_for(ip: Ipv4Addr) -> u16 {
    let octets = ip.octets();
    let base = ((octets[2] as u16) << 8) | octets[3] as u16;
    if base < 32 {
        base + 1000
    } else {
        base
    }
}

fn link_speed_kbit(interface: &str) -> u64 {
    std::fs::read_to_string(format!("/sys/class/net/{interface}/speed"))
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|v| *v > 0)
        .map(|mbps| mbps * 1000)
        .unwrap_or(1_000_000)
}

fn qdisc_owned_or_default(interface: &str) -> Result<bool> {
    let (ok, output) = run_command("tc", &["qdisc", "show", "dev", interface], None)?;
    if !ok {
        return Err(Error::Gateway(format!(
            "cannot inspect qdiscs on {interface}: {output}"
        )));
    }
    if output.contains("htb 1:") {
        return Ok(true);
    }
    // Replacing a hardware/mq or third-party shaping root would break the
    // administrator's existing QoS. Refuse instead.
    let risky = ["mq", "cake", "htb", "hfsc", "cbq", "prio", "taprio"];
    for line in output.lines() {
        for kind in risky {
            if line.contains(&format!("qdisc {kind} ")) {
                return Err(Error::Unsupported(format!(
                    "interface {interface} already has a {kind} root qdisc; refusing to replace existing QoS"
                )));
            }
        }
    }
    Ok(false)
}

/// Build the exact tc command sequence for a bandwidth rule. Returned as
/// argument vectors so tests can assert that no shell interpolation occurs.
pub fn tc_limit_plan(
    interface: &str,
    ip: Ipv4Addr,
    download_kbps: Option<i64>,
    upload_kbps: Option<i64>,
    priority: Option<i32>,
) -> Result<Vec<Vec<String>>> {
    let interface = validate_interface(interface)?;
    let download = validate_rate(download_kbps)?;
    let upload = validate_rate(upload_kbps)?;
    if download.is_none() && upload.is_none() {
        return Err(Error::Validation(
            "at least one of download/upload must be set".into(),
        ));
    }
    let priority = validate_priority(priority)?.unwrap_or(0);
    let minor = minor_for(ip);
    let mut plan: Vec<Vec<String>> = Vec::new();
    if download.is_some() {
        plan.push(vec![
            "tc".into(),
            "qdisc".into(),
            "replace".into(),
            "dev".into(),
            interface.clone(),
            "root".into(),
            "handle".into(),
            "1:".into(),
            "htb".into(),
            "default".into(),
            "30".into(),
        ]);
        plan.push(vec![
            "tc".into(),
            "class".into(),
            "replace".into(),
            "dev".into(),
            interface.clone(),
            "parent".into(),
            "1:".into(),
            "classid".into(),
            "1:30".into(),
            "htb".into(),
            "rate".into(),
            format!("{}kbit", link_speed_kbit(&interface)),
            "ceil".into(),
            format!("{}kbit", link_speed_kbit(&interface)),
        ]);
        plan.push(vec![
            "tc".into(),
            "class".into(),
            "replace".into(),
            "dev".into(),
            interface.clone(),
            "parent".into(),
            "1:".into(),
            "classid".into(),
            format!("1:{minor}"),
            "htb".into(),
            "rate".into(),
            format!("{}kbit", download.unwrap()),
            "ceil".into(),
            format!("{}kbit", download.unwrap()),
            "prio".into(),
            priority.to_string(),
        ]);
        plan.push(vec![
            "tc".into(),
            "filter".into(),
            "del".into(),
            "dev".into(),
            interface.clone(),
            "parent".into(),
            "1:".into(),
            "protocol".into(),
            "ip".into(),
            "prio".into(),
            minor.to_string(),
        ]);
        plan.push(vec![
            "tc".into(),
            "filter".into(),
            "add".into(),
            "dev".into(),
            interface.clone(),
            "parent".into(),
            "1:".into(),
            "protocol".into(),
            "ip".into(),
            "prio".into(),
            minor.to_string(),
            "u32".into(),
            "match".into(),
            "ip".into(),
            "dst".into(),
            format!("{ip}/32"),
            "flowid".into(),
            format!("1:{minor}"),
        ]);
    }
    if let Some(up) = upload {
        plan.push(vec![
            "tc".into(),
            "qdisc".into(),
            "add".into(),
            "dev".into(),
            interface.clone(),
            "handle".into(),
            "ffff:".into(),
            "ingress".into(),
        ]);
        plan.push(vec![
            "tc".into(),
            "filter".into(),
            "del".into(),
            "dev".into(),
            interface.clone(),
            "parent".into(),
            "ffff:".into(),
            "protocol".into(),
            "ip".into(),
            "prio".into(),
            minor.to_string(),
        ]);
        plan.push(vec![
            "tc".into(),
            "filter".into(),
            "add".into(),
            "dev".into(),
            interface.clone(),
            "parent".into(),
            "ffff:".into(),
            "protocol".into(),
            "ip".into(),
            "prio".into(),
            minor.to_string(),
            "u32".into(),
            "match".into(),
            "ip".into(),
            "src".into(),
            format!("{ip}/32"),
            "police".into(),
            "rate".into(),
            format!("{up}kbit"),
            "burst".into(),
            "32k".into(),
            "drop".into(),
        ]);
    }
    Ok(plan)
}

pub fn tc_clear_plan(interface: &str, ip: Ipv4Addr) -> Result<Vec<Vec<String>>> {
    let interface = validate_interface(interface)?;
    let minor = minor_for(ip);
    Ok(vec![
        vec![
            "tc".into(),
            "filter".into(),
            "del".into(),
            "dev".into(),
            interface.clone(),
            "parent".into(),
            "1:".into(),
            "protocol".into(),
            "ip".into(),
            "prio".into(),
            minor.to_string(),
        ],
        vec![
            "tc".into(),
            "class".into(),
            "del".into(),
            "dev".into(),
            interface.clone(),
            "classid".into(),
            format!("1:{minor}"),
        ],
        vec![
            "tc".into(),
            "filter".into(),
            "del".into(),
            "dev".into(),
            interface.clone(),
            "parent".into(),
            "ffff:".into(),
            "protocol".into(),
            "ip".into(),
            "prio".into(),
            minor.to_string(),
        ],
    ])
}

fn run_tc_plan(plan: &[Vec<String>]) -> Vec<String> {
    let mut notes = Vec::new();
    for command in plan {
        let args: Vec<&str> = command.iter().skip(1).map(String::as_str).collect();
        match run_command(&command[0], &args, None) {
            Ok((ok, output)) => {
                if !ok {
                    // qdisc add and filter del legitimately fail when the object
                    // already exists / does not exist. Keep the note but let
                    // verification decide the final state.
                    notes.push(format!("{}: {}", command.join(" "), output));
                }
            }
            Err(err) => notes.push(format!("{}: {err}", command.join(" "))),
        }
    }
    notes
}

fn tc_class_present(interface: &str, ip: Ipv4Addr) -> bool {
    let minor = minor_for(ip);
    run_command("tc", &["class", "show", "dev", interface], None)
        .map(|(ok, out)| ok && out.contains(&format!("1:{minor}")))
        .unwrap_or(false)
}

fn tc_filter_present(interface: &str, ip: Ipv4Addr, upload: bool) -> bool {
    let parent = if upload { "ffff:" } else { "1:" };
    // tc prints u32 matches as hex on some versions and dotted-quad on others.
    let dotted = ip.to_string();
    let hex = format!("{:08x}", u32::from(ip));
    run_command(
        "tc",
        &["filter", "show", "dev", interface, "parent", parent],
        None,
    )
    .map(|(ok, out)| ok && (out.contains(&dotted) || out.contains(&hex)))
    .unwrap_or(false)
}

fn default_interface() -> Option<String> {
    let raw = std::fs::read_to_string("/proc/net/route").ok()?;
    raw.lines().skip(1).find_map(|line| {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() >= 8 && f[1] == "00000000" {
            Some(f[0].to_string())
        } else {
            None
        }
    })
}

fn dnsmasq_hostnames() -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    for path in ["/var/lib/misc/dnsmasq.leases", "/tmp/dhcp.leases"] {
        if let Ok(raw) = std::fs::read_to_string(path) {
            for line in raw.lines() {
                let f: Vec<&str> = line.split_whitespace().collect();
                if f.len() >= 4 {
                    if let Some(mac) = normalize_mac(f[1]) {
                        map.insert(mac, format!("{}|{}", f[2], f[3]));
                    }
                }
            }
        }
    }
    map
}

fn arp_clients() -> Vec<GatewayClient> {
    let hostnames = dnsmasq_hostnames();
    let Ok(raw) = std::fs::read_to_string("/proc/net/arp") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for line in raw.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 6 {
            continue;
        }
        let Some(mac) = normalize_mac(f[3]) else {
            continue;
        };
        let lease = hostnames.get(&mac);
        let hostname = lease.map(|v| {
            let mut parts = v.splitn(2, '|');
            let _ip = parts.next().unwrap_or("");
            parts.next().unwrap_or("").to_string()
        });
        out.push(GatewayClient {
            mac: Some(mac.clone()),
            ip: Some(f[0].to_string()),
            hostname: hostname.filter(|h| !h.is_empty() && h != "*"),
            vendor: netcontrol_core::oui::lookup(&mac),
            interface: Some(f[5].to_string()),
            ssid: None,
            online: f[2].trim_start_matches("0x") != "0",
            rx_bytes: None,
            tx_bytes: None,
            rx_bps: None,
            tx_bps: None,
            blocked: None,
        });
    }
    out
}

/// Synchronous helper entry point. The helper binary calls this after
/// confirming it is root; the in-process adapter calls it when already root.
pub fn execute_helper(request: &HelperRequest) -> HelperResponse {
    match execute_inner(request) {
        Ok(response) => response,
        Err(err) => HelperResponse::fail(err.to_string()),
    }
}

fn execute_inner(request: &HelperRequest) -> Result<HelperResponse> {
    if !interfaces::is_root() {
        return Ok(HelperResponse::fail(
            "netcontrol-helper must run as root (install the sudoers rule described in docs/GATEWAYS.md)",
        ));
    }
    match request {
        HelperRequest::Status { interface } => {
            let nft = nft_available();
            let (table_ok, _) = run_command("nft", &["list", "table", "inet", NFT_TABLE], None)
                .unwrap_or((false, String::new()));
            let blocked = blocked_ips().unwrap_or_default();
            let iface = interface
                .clone()
                .or_else(default_interface)
                .unwrap_or_default();
            let (_, qdiscs) = run_command("tc", &["qdisc", "show", "dev", &iface], None)
                .unwrap_or((false, String::new()));
            let mut response = HelperResponse::ok("linux gateway ready", true);
            response.data = json!({
                "nft": nft,
                "table": table_ok,
                "blocked": blocked,
                "interface": iface,
                "qdiscs": qdiscs,
                "root": true
            });
            Ok(response)
        }
        HelperRequest::Block {
            ip,
            mac,
            expires_at,
        } => {
            ensure_table()?;
            let ip = resolve_ip(ip.as_deref(), mac.as_deref())?;
            let seconds = parse_expiry_seconds(expires_at.as_deref())?;
            let (ok, detail) = run_command("nft", &["-f", "-"], Some(&block_script(ip, seconds)))?;
            if !ok && !detail.to_ascii_lowercase().contains("exists") {
                return Ok(HelperResponse::fail(format!(
                    "nftables rejected the block rule: {detail}"
                )));
            }
            let present = blocked_ips()?.iter().any(|value| value == &ip.to_string());
            let mut response = HelperResponse::ok(
                if present {
                    format!("blocked {ip} in nftables set netcontrol/blocked")
                } else {
                    format!("nftables did not report {ip} in the blocked set after applying")
                },
                present,
            );
            response.rule_id = Some(ip.to_string());
            Ok(response)
        }
        HelperRequest::Unblock { ip, mac } => {
            let ip = resolve_ip(ip.as_deref(), mac.as_deref())?;
            let (_, detail) = run_command("nft", &["-f", "-"], Some(&unblock_script(ip)))?;
            let present = blocked_ips()?.iter().any(|value| value == &ip.to_string());
            let mut response = HelperResponse::ok(
                if present {
                    format!("{ip} is still present in the blocked set: {detail}")
                } else {
                    format!("removed {ip} from nftables set netcontrol/blocked")
                },
                !present,
            );
            response.rule_id = Some(ip.to_string());
            Ok(response)
        }
        HelperRequest::SetLimit {
            ip,
            mac,
            interface,
            download_kbps,
            upload_kbps,
            priority,
        } => {
            let ip = resolve_ip(ip.as_deref(), mac.as_deref())?;
            let interface = interface
                .clone()
                .filter(|i| !i.is_empty())
                .or_else(default_interface)
                .ok_or_else(|| {
                    Error::Unsupported(
                        "bandwidth shaping needs the LAN interface (set interface_hint on the gateway)"
                            .into(),
                    )
                })?;
            validate_interface(&interface)?;
            if !qdisc_owned_or_default(&interface)? {
                tracing::info!(%interface, "installing NetControl HTB root qdisc");
            }
            let plan = tc_limit_plan(&interface, ip, *download_kbps, *upload_kbps, *priority)?;
            let notes = run_tc_plan(&plan);
            let down_ok = download_kbps.unwrap_or(0) <= 0 || tc_class_present(&interface, ip);
            let up_ok = upload_kbps.unwrap_or(0) <= 0 || tc_filter_present(&interface, ip, true);
            let down_filter_ok =
                download_kbps.unwrap_or(0) <= 0 || tc_filter_present(&interface, ip, false);
            let verified = down_ok && up_ok && down_filter_ok;
            let mut response = HelperResponse::ok(
                if verified {
                    format!("bandwidth rule verified for {ip} on {interface}")
                } else {
                    format!(
                        "tc did not confirm the rule for {ip} on {interface}: {}",
                        notes.join(" | ")
                    )
                },
                verified,
            );
            response.rule_id = Some(format!("tc:{}:{}", interface, ip));
            response.data = json!({ "notes": notes });
            Ok(response)
        }
        HelperRequest::ClearLimit { ip, mac, interface } => {
            let ip = resolve_ip(ip.as_deref(), mac.as_deref())?;
            let interface = interface
                .clone()
                .filter(|i| !i.is_empty())
                .or_else(default_interface)
                .ok_or_else(|| Error::Validation("interface is required".into()))?;
            validate_interface(&interface)?;
            let plan = tc_clear_plan(&interface, ip)?;
            run_tc_plan(&plan);
            let class_gone = !tc_class_present(&interface, ip);
            let filters_gone = !tc_filter_present(&interface, ip, true)
                && !tc_filter_present(&interface, ip, false);
            let mut response = HelperResponse::ok(
                if class_gone && filters_gone {
                    format!("removed bandwidth limit for {ip} on {interface}")
                } else {
                    format!("some tc objects for {ip} could not be confirmed removed")
                },
                class_gone && filters_gone,
            );
            response.rule_id = Some(format!("tc:{}:{}", interface, ip));
            Ok(response)
        }
        HelperRequest::List => {
            let blocked = blocked_ips()?;
            let mut rules = Vec::new();
            for ip in blocked {
                rules.push(EnforcedRule {
                    kind: "block".into(),
                    target: ip.clone(),
                    rule_id: Some(ip),
                    detail: "nftables inet netcontrol blocked set".into(),
                });
            }
            let mut response = HelperResponse::ok(format!("{} enforced rules", rules.len()), true);
            response.data = serde_json::to_value(rules)?;
            Ok(response)
        }
    }
}

pub struct LinuxAdapter {
    config: GatewayConfig,
    _secret: Option<AdapterSecret>,
    helper: PathBuf,
}

impl LinuxAdapter {
    pub fn new(config: GatewayConfig, secret: Option<AdapterSecret>) -> Self {
        Self {
            config,
            _secret: secret,
            helper: find_helper(),
        }
    }

    async fn call(&self, request: HelperRequest) -> Result<HelperResponse> {
        if interfaces::is_root() {
            return tokio::task::spawn_blocking(move || execute_helper(&request))
                .await
                .map_err(|e| Error::Internal(format!("enforcement task failed: {e}")));
        }
        let helper = self.helper.clone();
        tokio::task::spawn_blocking(move || call_helper_process(&helper, &request))
            .await
            .map_err(|e| Error::Internal(format!("enforcement task failed: {e}")))?
    }

    async fn enforce(
        &self,
        request: HelperRequest,
        action: &str,
        target: &Target,
    ) -> Result<EnforcementResult> {
        match self.call(request).await {
            Ok(response) => Ok(verify_result(
                "linux",
                action,
                target,
                response.verified,
                response.rule_id,
                response.detail,
            )),
            Err(err) => Ok(EnforcementResult::failed(
                "linux",
                &target.label,
                err.to_string(),
            )),
        }
    }
}

fn find_helper() -> PathBuf {
    if let Ok(value) = std::env::var(HELPER_ENV) {
        return PathBuf::from(value);
    }
    let candidates = [
        PathBuf::from("/usr/lib/netcontrol/netcontrol-helper"),
        PathBuf::from("/usr/local/lib/netcontrol/netcontrol-helper"),
    ];
    for candidate in candidates {
        if candidate.is_file() {
            return candidate;
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            let sibling = parent.join("netcontrol-helper");
            if sibling.is_file() {
                return sibling;
            }
        }
    }
    PathBuf::from("netcontrol-helper")
}

fn call_helper_process(path: &PathBuf, request: &HelperRequest) -> Result<HelperResponse> {
    let payload = serde_json::to_string(request)?;
    let output = Command::new("sudo")
        .args(["-n", "--"])
        .arg(path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            if let Some(stdin) = child.stdin.as_mut() {
                stdin.write_all(payload.as_bytes())?;
            }
            child.wait_with_output()
        })
        .map_err(|e| {
            Error::Forbidden(format!(
                "privileged helper could not be executed via sudo -n: {e}. Install {path:?} and the sudoers rule from docs/GATEWAYS.md"
            ))
        })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        return Err(Error::Forbidden(format!(
            "netcontrol-helper failed (exit {:?}): {}{}",
            output.status.code(),
            if stderr.is_empty() { "" } else { &stderr },
            if stdout.is_empty() {
                String::new()
            } else {
                format!(" {stdout}")
            }
        )));
    }
    let parsed: HelperResponse = serde_json::from_slice(&output.stdout)
        .map_err(|e| Error::Gateway(format!("invalid response from netcontrol-helper: {e}")))?;
    Ok(parsed)
}

#[async_trait]
impl GatewayAdapter for LinuxAdapter {
    fn kind(&self) -> GatewayKind {
        GatewayKind::Linux
    }

    fn name(&self) -> String {
        self.config.name.clone()
    }

    fn config(&self) -> &GatewayConfig {
        &self.config
    }

    fn capabilities(&self) -> GatewayCapabilities {
        GatewayCapabilities {
            discovery: true,
            dhcp_leases: true,
            block: true,
            unblock: true,
            bandwidth: true,
            priority: true,
            schedules: true,
            traffic_stats: false,
        }
    }

    async fn probe(&self) -> Result<GatewayProbe> {
        let started = Instant::now();
        let response = self
            .call(HelperRequest::Status {
                interface: self.config.interface_hint.clone(),
            })
            .await
            .unwrap_or_else(|err| HelperResponse::fail(err.to_string()));
        let message = if !response.ok && response.detail.to_ascii_lowercase().contains("sudo") {
            "The privileged helper is not configured. Install netcontrol-helper and the sudoers rule from docs/GATEWAYS.md to enable nftables/tc enforcement. Discovery and monitoring are unaffected.".to_string()
        } else {
            response.detail.clone()
        };
        Ok(GatewayProbe {
            ok: response.ok,
            kind: GatewayKind::Linux,
            name: self.config.name.clone(),
            version: Some(env!("CARGO_PKG_VERSION").into()),
            model: Some("Linux gateway (nftables + tc)".into()),
            capabilities: self.capabilities(),
            latency_ms: started.elapsed().as_millis() as u64,
            message,
        })
    }

    async fn clients(&self) -> Result<Vec<GatewayClient>> {
        Ok(arp_clients())
    }

    async fn block(&self, target: &Target, expires_at: Option<&str>) -> Result<EnforcementResult> {
        self.enforce(
            HelperRequest::Block {
                ip: target.ip.clone(),
                mac: target.mac.clone(),
                expires_at: expires_at.map(str::to_string),
            },
            "block",
            target,
        )
        .await
    }

    async fn unblock(&self, target: &Target) -> Result<EnforcementResult> {
        self.enforce(
            HelperRequest::Unblock {
                ip: target.ip.clone(),
                mac: target.mac.clone(),
            },
            "unblock",
            target,
        )
        .await
    }

    async fn set_bandwidth(
        &self,
        target: &Target,
        limit: &BandwidthLimit,
    ) -> Result<EnforcementResult> {
        self.enforce(
            HelperRequest::SetLimit {
                ip: target.ip.clone(),
                mac: target.mac.clone(),
                interface: self.config.interface_hint.clone(),
                download_kbps: limit.download_kbps,
                upload_kbps: limit.upload_kbps,
                priority: limit.priority,
            },
            "limit",
            target,
        )
        .await
    }

    async fn clear_bandwidth(&self, target: &Target) -> Result<EnforcementResult> {
        self.enforce(
            HelperRequest::ClearLimit {
                ip: target.ip.clone(),
                mac: target.mac.clone(),
                interface: self.config.interface_hint.clone(),
            },
            "clear_limit",
            target,
        )
        .await
    }

    async fn list_enforced(&self) -> Result<Vec<EnforcedRule>> {
        let response = self.call(HelperRequest::List).await?;
        if !response.ok {
            return Err(Error::Gateway(response.detail));
        }
        serde_json::from_value(response.data)
            .map_err(|e| Error::Gateway(format!("invalid helper rule list: {e}")))
    }
}

mod interfaces {
    #[cfg(unix)]
    pub fn is_root() -> bool {
        // SAFETY: geteuid has no preconditions.
        unsafe { libc::geteuid() == 0 }
    }

    #[cfg(not(unix))]
    pub fn is_root() -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nft_script_is_scoped() {
        let script = block_script("192.168.1.20".parse().unwrap(), Some(60));
        assert!(script.contains("192.168.1.20"));
        assert!(script.contains("timeout 60s"));
        assert!(script.contains("inet netcontrol"));
        assert!(table_script().contains("ip daddr @blocked drop"));
    }

    #[test]
    fn blocks_public_targets() {
        assert!(validate_ipv4("8.8.8.8").is_err());
        assert!(validate_ipv4("192.168.1.20").is_ok());
        assert!(validate_ipv4("192.168.1.20; rm -rf /").is_err());
    }

    #[test]
    fn priority_and_rates_are_bounded() {
        assert!(validate_rate(Some(10_000)).is_ok());
        assert!(validate_rate(Some(0)).unwrap().is_none());
        assert!(validate_rate(Some(-1)).is_err());
        assert!(validate_priority(Some(9)).is_err());
    }

    #[test]
    fn tc_plan_has_no_shell_tokens() {
        let plan = tc_limit_plan(
            "lan0",
            "192.168.1.20".parse().unwrap(),
            Some(10_000),
            Some(2_000),
            Some(3),
        )
        .unwrap();
        let flat: Vec<String> = plan.iter().flatten().cloned().collect();
        assert!(flat.iter().any(|a| a == "192.168.1.20/32"));
        assert!(flat.iter().any(|a| a == "10000kbit"));
        assert!(flat.iter().any(|a| a == "2000kbit"));
        assert!(!flat.iter().any(|a| a.contains(';')));
        assert!(plan.iter().all(|command| command[0] == "tc"));
    }

    #[test]
    fn tc_minor_is_deterministic() {
        let ip: Ipv4Addr = "192.168.1.20".parse().unwrap();
        assert_eq!(minor_for(ip), 276);
        let ip: Ipv4Addr = "192.168.1.200".parse().unwrap();
        assert_eq!(minor_for(ip), 456);
    }

    #[test]
    fn helper_refuses_unprivileged_or_validates() {
        let response = execute_helper(&HelperRequest::Block {
            ip: Some("8.8.8.8".into()),
            mac: None,
            expires_at: None,
        });
        // Running the test suite unprivileged must never mutate the firewall.
        assert!(!response.ok);
    }
}
