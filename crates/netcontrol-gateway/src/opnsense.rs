//! OPNsense adapter over its REST API.
//!
//! Blocking is enforced through the `netcontrol_blocked` firewall alias. The
//! adapter creates that alias and a LAN block rule if they are missing, then
//! verifies both the alias content and the rule before reporting success. If
//! the installed OPNsense API cannot create the rule, the alias entry is
//! rolled back and the operation is reported as unsupported instead of
//! leaving a misleading half-configuration.

use crate::traits::{verify_result, AdapterSecret, EnforcedRule, GatewayAdapter, Target};
use async_trait::async_trait;
use netcontrol_core::models::{
    BandwidthLimit, EnforcementResult, GatewayCapabilities, GatewayClient, GatewayConfig,
    GatewayKind, GatewayProbe,
};
use netcontrol_core::util::normalize_mac;
use netcontrol_core::{Error, Result};
use reqwest::{Client, Method, StatusCode};
use serde_json::{json, Value};
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

const ALIAS: &str = "netcontrol_blocked";

pub struct OpnSenseAdapter {
    config: GatewayConfig,
    username: String,
    secret: Option<AdapterSecret>,
    http: Client,
}

impl OpnSenseAdapter {
    pub fn new(config: GatewayConfig, secret: Option<AdapterSecret>) -> Result<Self> {
        let username = config
            .username
            .clone()
            .filter(|u| !u.trim().is_empty())
            .ok_or_else(|| Error::Validation("OPNsense requires an API key".into()))?;
        if secret.is_none() {
            return Err(Error::Validation("OPNsense requires an API secret".into()));
        }
        let http = Client::builder()
            .danger_accept_invalid_certs(config.tls_insecure)
            .timeout(Duration::from_secs(20))
            .build()
            .map_err(|e| Error::Internal(format!("HTTP client: {e}")))?;
        Ok(Self {
            config,
            username,
            secret,
            http,
        })
    }

    fn base(&self) -> String {
        format!(
            "{}://{}:{}/api",
            if self.config.tls { "https" } else { "http" },
            self.config.host,
            self.config.port
        )
    }

    async fn call(&self, method: Method, path: &str, body: Option<Value>) -> Result<(u16, Value)> {
        let secret = self
            .secret
            .as_ref()
            .ok_or_else(|| Error::Validation("missing OPNsense API secret".into()))?;
        let mut request = self
            .http
            .request(method, format!("{}{}", self.base(), path))
            .basic_auth(&self.username, Some(secret.value.as_str()))
            .header("Accept", "application/json");
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request
            .send()
            .await
            .map_err(|e| Error::Gateway(format!("OPNsense request failed: {e}")))?;
        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        let value = if text.trim().is_empty() {
            Value::Null
        } else {
            serde_json::from_str(&text)
                .unwrap_or_else(|_| Value::String(text.chars().take(500).collect()))
        };
        if status.is_server_error() {
            return Err(Error::Gateway(format!(
                "OPNsense HTTP {}: {}",
                status.as_u16(),
                netcontrol_core::util::redact_for_log(&value.to_string())
            )));
        }
        if status == StatusCode::UNAUTHORIZED {
            return Err(Error::Forbidden(
                "OPNsense rejected the API credentials".into(),
            ));
        }
        Ok((status.as_u16(), value))
    }

    async fn alias_addresses(&self) -> Result<Vec<String>> {
        let (status, value) = self
            .call(
                Method::GET,
                &format!("/firewall/alias_util/list/{ALIAS}"),
                None,
            )
            .await?;
        if status >= 400 {
            return Ok(Vec::new());
        }
        Ok(extract_addresses(&value))
    }

    async fn ensure_alias(&self) -> Result<()> {
        let (status, _) = self
            .call(
                Method::GET,
                &format!("/firewall/alias_util/list/{ALIAS}"),
                None,
            )
            .await?;
        if status < 400 {
            return Ok(());
        }
        let (created, body) = self
            .call(
                Method::POST,
                "/firewall/alias/addItem",
                Some(json!({
                    "alias": {
                        "enabled": "1",
                        "name": ALIAS,
                        "type": "host",
                        "content": "",
                        "description": "Blocked clients managed by NetControl"
                    }
                })),
            )
            .await?;
        if created >= 400 {
            return Err(Error::Unsupported(format!(
                "OPNsense could not create the {ALIAS} alias via API: {}",
                body
            )));
        }
        let (_, _) = self
            .call(Method::POST, "/firewall/alias/reconfigure", Some(json!({})))
            .await?;
        Ok(())
    }

    async fn rule_present(&self) -> Result<bool> {
        let (status, value) = self
            .call(
                Method::POST,
                "/firewall/filter/searchRule",
                Some(json!({"current": 1, "rowCount": 500, "searchPhrase": ""})),
            )
            .await?;
        if status >= 400 {
            return Ok(false);
        }
        let rows = value
            .get("rows")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        Ok(rows.iter().any(rule_blocks_alias))
    }

    async fn ensure_rule(&self) -> Result<bool> {
        if self.rule_present().await? {
            return Ok(true);
        }
        let interface = self
            .config
            .interface_hint
            .clone()
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| "lan".into());
        let (status, body) = self
            .call(
                Method::POST,
                "/firewall/filter/addRule",
                Some(json!({
                    "rule": {
                        "enabled": "1",
                        "action": "block",
                        "interface": interface,
                        "direction": "in",
                        "source_net": ALIAS,
                        "destination_net": "any",
                        "description": "NetControl blocked clients"
                    }
                })),
            )
            .await?;
        if status >= 400 {
            return Ok(false);
        }
        let _ = self
            .call(Method::POST, "/firewall/filter/apply", Some(json!({})))
            .await;
        let _ = body;
        self.rule_present().await
    }

    async fn add_alias(&self, ip: Ipv4Addr) -> Result<()> {
        let (status, body) = self
            .call(
                Method::POST,
                &format!("/firewall/alias_util/add/{ALIAS}"),
                Some(json!({"address": ip.to_string()})),
            )
            .await?;
        if status >= 400 {
            return Err(Error::Gateway(format!(
                "OPNsense alias update failed: {body}"
            )));
        }
        let _ = self
            .call(Method::POST, "/firewall/alias/reconfigure", Some(json!({})))
            .await;
        Ok(())
    }

    async fn delete_alias(&self, ip: Ipv4Addr) -> Result<()> {
        let (status, body) = self
            .call(
                Method::POST,
                &format!("/firewall/alias_util/delete/{ALIAS}"),
                Some(json!({"address": ip.to_string()})),
            )
            .await?;
        if status >= 400 {
            return Err(Error::Gateway(format!(
                "OPNsense alias removal failed: {body}"
            )));
        }
        let _ = self
            .call(Method::POST, "/firewall/alias/reconfigure", Some(json!({})))
            .await;
        Ok(())
    }
}

fn extract_addresses(value: &Value) -> Vec<String> {
    let mut out = Vec::new();
    let mut push = |v: &Value| {
        if let Some(addr) = v
            .get("address")
            .and_then(Value::as_str)
            .or_else(|| v.as_str())
        {
            if addr.parse::<Ipv4Addr>().is_ok() {
                out.push(addr.to_string());
            }
        }
    };
    match value.get("rows").and_then(Value::as_array) {
        Some(rows) => rows.iter().for_each(&mut push),
        None => {
            if let Some(arr) = value.as_array() {
                arr.iter().for_each(&mut push);
            } else if let Some(obj) = value.as_object() {
                obj.values().for_each(&mut push);
            }
        }
    }
    out
}

fn rule_blocks_alias(rule: &Value) -> bool {
    let action = rule
        .get("action")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_ascii_lowercase();
    if !matches!(action.as_str(), "block" | "reject") {
        return false;
    }
    let enabled = rule
        .get("enabled")
        .and_then(|v| v.as_str().map(|s| s == "1").or_else(|| v.as_bool()))
        .unwrap_or(true);
    if !enabled {
        return false;
    }
    let text = format!(
        "{} {} {}",
        rule.get("source_net")
            .and_then(Value::as_str)
            .unwrap_or_default(),
        rule.get("destination_net")
            .and_then(Value::as_str)
            .unwrap_or_default(),
        rule.get("description")
            .and_then(Value::as_str)
            .unwrap_or_default()
    );
    text.contains(ALIAS) || text.to_ascii_lowercase().contains("netcontrol")
}

#[async_trait]
impl GatewayAdapter for OpnSenseAdapter {
    fn kind(&self) -> GatewayKind {
        GatewayKind::OpnSense
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
            dhcp_leases: false,
            block: true,
            unblock: true,
            bandwidth: false,
            priority: false,
            schedules: true,
            traffic_stats: false,
        }
    }

    async fn probe(&self) -> Result<GatewayProbe> {
        let started = Instant::now();
        let (status, value) = self
            .call(Method::GET, "/core/firmware/status", None)
            .await
            .unwrap_or((0, Value::Null));
        if status == 200 {
            let version = find_string(&value, &["product_version", "version", "product_name"]);
            let rule = self.rule_present().await.unwrap_or(false);
            return Ok(GatewayProbe {
                ok: true,
                kind: GatewayKind::OpnSense,
                name: self.config.name.clone(),
                version,
                model: Some("OPNsense".into()),
                capabilities: self.capabilities(),
                latency_ms: started.elapsed().as_millis() as u64,
                message: if rule {
                    "OPNsense API authenticated; NetControl block rule is present".into()
                } else {
                    "OPNsense API authenticated; the block rule will be created on first use".into()
                },
            });
        }
        Ok(GatewayProbe {
            ok: false,
            kind: GatewayKind::OpnSense,
            name: self.config.name.clone(),
            version: None,
            model: None,
            capabilities: self.capabilities(),
            latency_ms: started.elapsed().as_millis() as u64,
            message: format!(
                "OPNsense API probe failed (HTTP {status}); check the API key/secret and HTTPS access"
            ),
        })
    }

    async fn clients(&self) -> Result<Vec<GatewayClient>> {
        let (status, value) = self
            .call(Method::GET, "/diagnostics/interface/getArp", None)
            .await?;
        if status >= 400 {
            return Err(Error::Gateway(format!(
                "OPNsense ARP endpoint returned HTTP {status}"
            )));
        }
        let rows = value
            .get("rows")
            .and_then(Value::as_array)
            .cloned()
            .or_else(|| value.as_array().cloned())
            .unwrap_or_default();
        let mut out = Vec::new();
        for row in rows {
            let ip = row.get("ip").and_then(Value::as_str).map(str::to_string);
            let mac = row
                .get("mac")
                .and_then(Value::as_str)
                .and_then(normalize_mac);
            if ip.is_none() && mac.is_none() {
                continue;
            }
            out.push(GatewayClient {
                mac: mac.clone(),
                ip,
                hostname: row
                    .get("hostname")
                    .and_then(Value::as_str)
                    .map(str::to_string)
                    .filter(|h| !h.is_empty() && h != "?"),
                vendor: mac.as_deref().and_then(netcontrol_core::oui::lookup),
                interface: row
                    .get("intf_description")
                    .or_else(|| row.get("interface"))
                    .and_then(Value::as_str)
                    .map(str::to_string),
                ssid: None,
                online: true,
                rx_bytes: None,
                tx_bytes: None,
                rx_bps: None,
                tx_bps: None,
                blocked: None,
            });
        }
        Ok(out)
    }

    async fn block(&self, target: &Target, _expires_at: Option<&str>) -> Result<EnforcementResult> {
        let ip = target
            .ip
            .as_deref()
            .ok_or_else(|| {
                Error::Unsupported("OPNsense enforcement requires an IP address".into())
            })?
            .parse::<Ipv4Addr>()
            .map_err(|_| Error::Validation("invalid target IP".into()))?;
        self.ensure_alias().await?;
        let rule_ok = self.ensure_rule().await?;
        if !rule_ok {
            return Ok(EnforcementResult::unsupported(
                "opnsense",
                &target.label,
                format!(
                    "OPNsense API could not create a block rule for alias {ALIAS}. Create one LAN rule \
                     (source = {ALIAS}, action = block) once in the OPNsense UI, then retry."
                ),
            ));
        }
        self.add_alias(ip).await?;
        let addresses = self.alias_addresses().await?;
        let verified =
            addresses.iter().any(|a| a == &ip.to_string()) && self.rule_present().await?;
        if !verified {
            // Do not leave a half-applied alias entry behind.
            let _ = self.delete_alias(ip).await;
        }
        Ok(verify_result(
            "opnsense",
            "block",
            target,
            verified,
            Some(format!("{ALIAS}:{ip}")),
            if verified {
                format!("alias {ALIAS} contains {ip} and a blocking rule is present")
            } else {
                "OPNsense did not confirm both the alias entry and the blocking rule".into()
            },
        ))
    }

    async fn unblock(&self, target: &Target) -> Result<EnforcementResult> {
        let ip = target
            .ip
            .as_deref()
            .ok_or_else(|| {
                Error::Unsupported("OPNsense enforcement requires an IP address".into())
            })?
            .parse::<Ipv4Addr>()
            .map_err(|_| Error::Validation("invalid target IP".into()))?;
        self.delete_alias(ip).await?;
        let addresses = self.alias_addresses().await?;
        let verified = !addresses.iter().any(|a| a == &ip.to_string());
        Ok(verify_result(
            "opnsense",
            "unblock",
            target,
            verified,
            Some(format!("{ALIAS}:{ip}")),
            if verified {
                format!("removed {ip} from alias {ALIAS}")
            } else {
                "the address is still present in the alias".into()
            },
        ))
    }

    async fn set_bandwidth(
        &self,
        target: &Target,
        _limit: &BandwidthLimit,
    ) -> Result<EnforcementResult> {
        Ok(EnforcementResult::unsupported(
            "opnsense",
            &target.label,
            "OPNsense traffic shaping is not automated by NetControl",
        ))
    }

    async fn clear_bandwidth(&self, target: &Target) -> Result<EnforcementResult> {
        Ok(EnforcementResult::unsupported(
            "opnsense",
            &target.label,
            "no NetControl shaper is managed on OPNsense",
        ))
    }

    async fn list_enforced(&self) -> Result<Vec<EnforcedRule>> {
        Ok(self
            .alias_addresses()
            .await?
            .into_iter()
            .map(|ip| EnforcedRule {
                kind: "block".into(),
                target: ip,
                rule_id: Some(ALIAS.into()),
                detail: format!("OPNsense alias {ALIAS}"),
            })
            .collect())
    }
}

fn find_string(value: &Value, keys: &[&str]) -> Option<String> {
    if let Some(obj) = value.as_object() {
        for key in keys {
            if let Some(v) = obj.get(*key).and_then(Value::as_str) {
                return Some(v.to_string());
            }
        }
        for v in obj.values() {
            if let Some(found) = find_string(v, keys) {
                return Some(found);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_alias_addresses() {
        let value = json!({"rows":[{"address":"192.168.1.4"},{"address":"bad"}]});
        assert_eq!(extract_addresses(&value), vec!["192.168.1.4"]);
        let value = json!([{"address":"10.0.0.2"}]);
        assert_eq!(extract_addresses(&value), vec!["10.0.0.2"]);
    }

    #[test]
    fn detects_block_rule() {
        assert!(rule_blocks_alias(&json!({
            "action": "block", "enabled": "1", "source_net": "netcontrol_blocked"
        })));
        assert!(!rule_blocks_alias(&json!({
            "action": "pass", "enabled": "1", "source_net": "netcontrol_blocked"
        })));
        assert!(!rule_blocks_alias(&json!({
            "action": "block", "enabled": "0", "source_net": "netcontrol_blocked"
        })));
    }
}
