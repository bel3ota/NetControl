//! OpenWrt adapter (SSH + UCI/fw4 + tc).
//!
//! Blocking creates a persistent UCI firewall rule (REJECT from lan to wan,
//! matched by MAC and/or IP) and reloads the firewall. Bandwidth shaping uses
//! tc on an explicitly configured LAN interface. SSH key authentication is
//! recommended; password authentication requires `sshpass`.

use crate::linux;
use crate::ssh::{sh_quote, SshClient};
use crate::traits::{verify_result, AdapterSecret, EnforcedRule, GatewayAdapter, Target};
use async_trait::async_trait;
use netcontrol_core::models::{
    BandwidthLimit, EnforcementResult, GatewayCapabilities, GatewayClient, GatewayConfig,
    GatewayKind, GatewayProbe,
};
use netcontrol_core::util::normalize_mac;
use netcontrol_core::{Error, Result};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::Instant;

const PREFIX: &str = "netcontrol_block_";

pub struct OpenWrtAdapter {
    config: GatewayConfig,
    ssh: SshClient,
    has_tc: std::sync::atomic::AtomicBool,
    has_fw: std::sync::atomic::AtomicBool,
}

impl OpenWrtAdapter {
    pub fn new(config: GatewayConfig, secret: Option<AdapterSecret>) -> Result<Self> {
        let ssh = SshClient::new(&config, secret)?;
        Ok(Self {
            config,
            ssh,
            has_tc: std::sync::atomic::AtomicBool::new(false),
            has_fw: std::sync::atomic::AtomicBool::new(true),
        })
    }

    async fn uci_rules(&self) -> Result<Vec<UciRule>> {
        let output = self.ssh.run("uci show firewall 2>/dev/null").await?;
        Ok(parse_uci_rules(&output))
    }

    fn slug(target: &Target) -> String {
        target
            .mac
            .as_deref()
            .and_then(normalize_mac)
            .map(|m| m.replace(':', ""))
            .or_else(|| target.ip.as_deref().map(|ip| ip.replace('.', "_")))
            .unwrap_or_else(|| "unknown".into())
    }

    async fn remote_tc(&self, commands: &[Vec<String>]) -> Result<String> {
        let interface = self
            .config
            .interface_hint
            .clone()
            .filter(|i| !i.is_empty())
            .ok_or_else(|| {
                Error::Unsupported(
                    "OpenWrt bandwidth shaping requires interface_hint (for example br-lan)".into(),
                )
            })?;
        if !interface
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        {
            return Err(Error::Validation("invalid interface_hint".into()));
        }
        let mut script = String::from("set -e\n");
        script.push_str(&format!(
            "if tc qdisc show dev {} | grep -Eq 'qdisc (mq|cake|hfsc|cbq|taprio) '; then echo 'foreign qdisc present' >&2; exit 3; fi\n",
            sh_quote(&interface)
        ));
        for command in commands {
            script.push_str(
                &command
                    .iter()
                    .map(|arg| sh_quote(arg))
                    .collect::<Vec<_>>()
                    .join(" "),
            );
            script.push('\n');
        }
        self.ssh.run(&script).await
    }
}

#[derive(Debug, Clone)]
struct UciRule {
    section: String,
    name: Option<String>,
    src_mac: Option<String>,
    src_ip: Option<String>,
    target: Option<String>,
}

fn parse_uci_rules(output: &str) -> Vec<UciRule> {
    let mut rules: std::collections::HashMap<String, UciRule> = std::collections::HashMap::new();
    for line in output.lines() {
        let Some(rest) = line.strip_prefix("firewall.") else {
            continue;
        };
        let Some((section, field_value)) = rest.split_once('.') else {
            continue;
        };
        let Some((field, value)) = field_value.split_once('=') else {
            continue;
        };
        let value = value.trim_matches('\'').to_string();
        let rule = rules.entry(section.to_string()).or_insert_with(|| UciRule {
            section: section.to_string(),
            name: None,
            src_mac: None,
            src_ip: None,
            target: None,
        });
        match field {
            "name" => rule.name = Some(value),
            "src_mac" => rule.src_mac = normalize_mac(&value),
            "src_ip" => rule.src_ip = Some(value),
            "target" => rule.target = Some(value),
            _ => {}
        }
    }
    rules.into_values().collect()
}

#[async_trait]
impl GatewayAdapter for OpenWrtAdapter {
    fn kind(&self) -> GatewayKind {
        GatewayKind::OpenWrt
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
            block: self.has_fw.load(std::sync::atomic::Ordering::Relaxed),
            unblock: self.has_fw.load(std::sync::atomic::Ordering::Relaxed),
            bandwidth: self.has_tc.load(std::sync::atomic::Ordering::Relaxed)
                && self.config.interface_hint.is_some(),
            priority: self.has_tc.load(std::sync::atomic::Ordering::Relaxed)
                && self.config.interface_hint.is_some(),
            schedules: true,
            traffic_stats: false,
        }
    }

    async fn probe(&self) -> Result<GatewayProbe> {
        let started = Instant::now();
        let output = self
            .ssh
            .run(
                "cat /etc/openwrt_release 2>/dev/null; echo '---'; command -v tc >/dev/null && echo TC_OK; \
                 command -v fw4 >/dev/null && echo FW4_OK; command -v fw3 >/dev/null && echo FW3_OK; \
                 ubus call system board 2>/dev/null",
            )
            .await;
        match output {
            Ok(text) => {
                let version = text
                    .lines()
                    .find_map(|line| line.strip_prefix("DISTRIB_DESCRIPTION="))
                    .map(|v| v.trim_matches('\'').to_string())
                    .or_else(|| {
                        text.lines()
                            .find_map(|line| line.strip_prefix("DISTRIB_RELEASE="))
                            .map(|v| format!("OpenWrt {}", v.trim_matches('\'')))
                    });
                let has_tc = text.contains("TC_OK");
                let has_fw = text.contains("FW4_OK") || text.contains("FW3_OK");
                self.has_tc
                    .store(has_tc, std::sync::atomic::Ordering::Relaxed);
                self.has_fw
                    .store(has_fw, std::sync::atomic::Ordering::Relaxed);
                let bandwidth = has_tc && self.config.interface_hint.is_some();
                Ok(GatewayProbe {
                    ok: has_fw,
                    kind: GatewayKind::OpenWrt,
                    name: self.config.name.clone(),
                    version,
                    model: Some("OpenWrt".into()),
                    capabilities: GatewayCapabilities {
                        discovery: true,
                        dhcp_leases: true,
                        block: has_fw,
                        unblock: has_fw,
                        bandwidth,
                        priority: bandwidth,
                        schedules: true,
                        traffic_stats: false,
                    },
                    latency_ms: started.elapsed().as_millis() as u64,
                    message: if has_fw {
                        if bandwidth {
                            "OpenWrt ready: UCI/fw4 blocking and tc shaping".into()
                        } else {
                            "OpenWrt ready: blocking available; set interface_hint (e.g. br-lan) to enable bandwidth shaping"
                                .into()
                        }
                    } else {
                        "OpenWrt reachable but neither fw4 nor fw3 was found; blocking disabled"
                            .into()
                    },
                })
            }
            Err(err) => Ok(GatewayProbe {
                ok: false,
                kind: GatewayKind::OpenWrt,
                name: self.config.name.clone(),
                version: None,
                model: None,
                capabilities: self.capabilities(),
                latency_ms: started.elapsed().as_millis() as u64,
                message: format!("SSH probe failed: {err}"),
            }),
        }
    }

    async fn clients(&self) -> Result<Vec<GatewayClient>> {
        let output = self
            .ssh
            .run(
                "cat /tmp/dhcp.leases 2>/dev/null; echo '---ARP---'; cat /proc/net/arp 2>/dev/null",
            )
            .await?;
        let (leases, arp) = output
            .split_once("---ARP---")
            .unwrap_or((output.as_str(), ""));
        let mut clients: std::collections::HashMap<String, GatewayClient> = HashMap::new();
        for line in leases.lines() {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 4 {
                continue;
            }
            let key = f[0].to_string();
            clients.insert(
                key,
                GatewayClient {
                    mac: normalize_mac(f[1]),
                    ip: Some(f[2].to_string()),
                    hostname: Some(f[3].to_string()).filter(|h| h != "*"),
                    vendor: normalize_mac(f[1])
                        .as_deref()
                        .and_then(netcontrol_core::oui::lookup),
                    interface: None,
                    ssid: None,
                    online: true,
                    rx_bytes: None,
                    tx_bytes: None,
                    rx_bps: None,
                    tx_bps: None,
                    blocked: None,
                },
            );
        }
        for line in arp.lines().skip(1) {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 6 || f[3] == "00:00:00:00:00:00" {
                continue;
            }
            let mac = normalize_mac(f[3]);
            let key = mac.clone().unwrap_or_else(|| f[0].to_string());
            clients.entry(key).or_insert(GatewayClient {
                mac,
                ip: Some(f[0].to_string()),
                hostname: None,
                vendor: None,
                interface: Some(f[5].to_string()),
                ssid: None,
                online: true,
                rx_bytes: None,
                tx_bytes: None,
                rx_bps: None,
                tx_bps: None,
                blocked: None,
            });
        }
        let mut out: Vec<GatewayClient> = clients.into_values().collect();
        out.sort_by(|a, b| a.ip.cmp(&b.ip));
        Ok(out)
    }

    async fn block(&self, target: &Target, _expires_at: Option<&str>) -> Result<EnforcementResult> {
        let slug = Self::slug(target);
        let name = format!("{PREFIX}{slug}");
        let mac = target.mac.as_deref().and_then(normalize_mac);
        let ip = target
            .ip
            .as_deref()
            .map(|v| v.trim().parse::<Ipv4Addr>())
            .transpose()
            .map_err(|_| Error::Validation("invalid target IP".into()))?;
        if mac.is_none() && ip.is_none() {
            return Ok(EnforcementResult::unsupported(
                "openwrt",
                &target.label,
                "a MAC or IP address is required",
            ));
        }
        let existing = self.uci_rules().await?;
        let mut script = String::from("set -e\n");
        for rule in existing
            .iter()
            .filter(|r| r.name.as_deref() == Some(name.as_str()))
        {
            script.push_str(&format!(
                "uci delete firewall.{} >/dev/null 2>&1 || true\n",
                rule.section
            ));
        }
        script.push_str("uci add firewall rule >/dev/null\n");
        script.push_str(&format!(
            "uci set firewall.@rule[-1].name={}\n",
            sh_quote(&name)
        ));
        script.push_str("uci set firewall.@rule[-1].src='lan'\n");
        script.push_str("uci set firewall.@rule[-1].dest='wan'\n");
        script.push_str("uci set firewall.@rule[-1].target='REJECT'\n");
        script.push_str("uci set firewall.@rule[-1].enabled='1'\n");
        if let Some(mac) = &mac {
            script.push_str(&format!(
                "uci set firewall.@rule[-1].src_mac={}\n",
                sh_quote(mac)
            ));
        }
        if let Some(ip) = ip {
            script.push_str(&format!(
                "uci set firewall.@rule[-1].src_ip={}\n",
                sh_quote(&ip.to_string())
            ));
        }
        script.push_str("uci commit firewall\n");
        script.push_str("(fw4 reload || fw3 reload) >/dev/null 2>&1 || true\n");
        script.push_str("uci show firewall\n");
        let output = self.ssh.run(&script).await?;
        let applied = output
            .lines()
            .any(|line| line.contains(&format!("name='{name}'")))
            && (mac.is_none()
                || output.lines().any(|line| {
                    line.contains(".src_mac=")
                        && mac.as_deref().map(|m| line.contains(m)).unwrap_or(false)
                }))
            && (ip.is_none()
                || output.lines().any(|line| {
                    line.contains(".src_ip=")
                        && ip
                            .map(|value| line.contains(&value.to_string()))
                            .unwrap_or(false)
                }));
        Ok(verify_result(
            "openwrt",
            "block",
            target,
            applied,
            Some(name.clone()),
            if applied {
                format!("UCI firewall rule {name} applied and firewall reloaded")
            } else {
                "UCI rule was not found after commit; block not verified".into()
            },
        ))
    }

    async fn unblock(&self, target: &Target) -> Result<EnforcementResult> {
        let name = format!("{PREFIX}{}", Self::slug(target));
        let existing = self.uci_rules().await?;
        let matching: Vec<&UciRule> = existing
            .iter()
            .filter(|r| r.name.as_deref() == Some(name.as_str()))
            .collect();
        if matching.is_empty() {
            return Ok(verify_result(
                "openwrt",
                "unblock",
                target,
                true,
                Some(name),
                "no matching OpenWrt firewall rule; already unblocked",
            ));
        }
        let mut script = String::from("set -e\n");
        for rule in matching {
            script.push_str(&format!(
                "uci delete firewall.{} >/dev/null 2>&1 || true\n",
                rule.section
            ));
        }
        script.push_str("uci commit firewall\n");
        script.push_str("(fw4 reload || fw3 reload) >/dev/null 2>&1 || true\n");
        script.push_str("uci show firewall\n");
        let output = self.ssh.run(&script).await?;
        let still_present = output
            .lines()
            .any(|line| line.contains(&format!("name='{name}'")));
        Ok(verify_result(
            "openwrt",
            "unblock",
            target,
            !still_present,
            Some(name.clone()),
            if still_present {
                format!("rule {name} is still present after removal")
            } else {
                format!("removed rule {name} and reloaded the firewall")
            },
        ))
    }

    async fn set_bandwidth(
        &self,
        target: &Target,
        limit: &BandwidthLimit,
    ) -> Result<EnforcementResult> {
        let ip = target
            .ip
            .as_deref()
            .ok_or_else(|| Error::Unsupported("OpenWrt shaping requires an IP target".into()))?
            .parse::<Ipv4Addr>()
            .map_err(|_| Error::Validation("invalid target IP".into()))?;
        let interface = self.config.interface_hint.clone().ok_or_else(|| {
            Error::Unsupported("interface_hint is required for OpenWrt shaping".into())
        })?;
        let plan = linux::tc_limit_plan(
            &interface,
            ip,
            limit.download_kbps,
            limit.upload_kbps,
            limit.priority,
        )?;
        let result = self.remote_tc(&plan).await;
        match result {
            Ok(_) => {
                let iface = sh_quote(&interface);
                let class_section = self.ssh.run(&format!("tc class show dev {iface}")).await?;
                let dst_section = self
                    .ssh
                    .run(&format!("tc filter show dev {iface} parent 1:"))
                    .await
                    .unwrap_or_default();
                let src_section = self
                    .ssh
                    .run(&format!("tc filter show dev {iface} parent ffff:"))
                    .await
                    .unwrap_or_default();
                let download_ok = limit.download_kbps.unwrap_or(0) <= 0
                    || (class_section.contains(&format!("1:{}", minor(ip)))
                        && dst_section.contains(&ip.to_string()));
                let upload_ok =
                    limit.upload_kbps.unwrap_or(0) <= 0 || src_section.contains(&ip.to_string());
                let verified = download_ok && upload_ok;
                Ok(verify_result(
                    "openwrt",
                    "limit",
                    target,
                    verified,
                    Some(format!("tc:{interface}:{ip}")),
                    if verified {
                        format!("tc shaping verified on {interface}")
                    } else {
                        "tc commands ran but the class/filter could not be confirmed".into()
                    },
                ))
            }
            Err(err) => Ok(EnforcementResult::failed(
                "openwrt",
                &target.label,
                err.to_string(),
            )),
        }
    }

    async fn clear_bandwidth(&self, target: &Target) -> Result<EnforcementResult> {
        let ip = target
            .ip
            .as_deref()
            .ok_or_else(|| Error::Unsupported("OpenWrt shaping requires an IP target".into()))?
            .parse::<Ipv4Addr>()
            .map_err(|_| Error::Validation("invalid target IP".into()))?;
        let interface = self
            .config
            .interface_hint
            .clone()
            .ok_or_else(|| Error::Unsupported("interface_hint is required".into()))?;
        let plan = linux::tc_clear_plan(&interface, ip)?;
        let script = plan
            .iter()
            .map(|command| {
                format!(
                    "{} || true",
                    command
                        .iter()
                        .map(|a| sh_quote(a))
                        .collect::<Vec<_>>()
                        .join(" ")
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        let output = self
            .ssh
            .run(&format!(
                "{script}\ntc class show dev {}; tc filter show dev {}",
                sh_quote(&interface),
                sh_quote(&interface)
            ))
            .await?;
        let verified = !output.contains(&ip.to_string());
        Ok(verify_result(
            "openwrt",
            "clear_limit",
            target,
            verified,
            Some(format!("tc:{interface}:{ip}")),
            if verified {
                "tc shaping removed".to_string()
            } else {
                "tc rule may still be present".to_string()
            },
        ))
    }

    async fn list_enforced(&self) -> Result<Vec<EnforcedRule>> {
        let rules = self.uci_rules().await?;
        Ok(rules
            .into_iter()
            .filter(|r| {
                r.name
                    .as_deref()
                    .map(|n| n.starts_with(PREFIX))
                    .unwrap_or(false)
            })
            .map(|r| EnforcedRule {
                kind: "block".into(),
                target: r
                    .src_mac
                    .clone()
                    .or(r.src_ip.clone())
                    .unwrap_or_else(|| "unknown".into()),
                rule_id: Some(r.section),
                detail: format!("OpenWrt UCI rule {:?}", r.name),
            })
            .collect())
    }
}

fn minor(ip: Ipv4Addr) -> u16 {
    let o = ip.octets();
    let base = ((o[2] as u16) << 8) | o[3] as u16;
    if base < 32 {
        base + 1000
    } else {
        base
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_uci_output() {
        let output = "firewall.@rule[3].name='netcontrol_block_aabbccddeeff'\n\
firewall.@rule[3].src_mac='aa:bb:cc:dd:ee:ff'\n\
firewall.@rule[3].target='REJECT'\n\
firewall.@rule[4].name='Allow-DHCP'\n";
        let rules = parse_uci_rules(output);
        assert_eq!(rules.len(), 2);
        assert!(rules.iter().any(
            |r| r.name.as_deref() == Some("netcontrol_block_aabbccddeeff")
                && r.src_mac.as_deref() == Some("aa:bb:cc:dd:ee:ff")
        ));
    }

    #[test]
    fn target_slugs_are_safe() {
        let target = Target::new(
            Some("192.168.1.20".into()),
            Some("AA:BB:CC:DD:EE:FF".into()),
        );
        assert_eq!(OpenWrtAdapter::slug(&target), "aabbccddeeff");
    }
}
