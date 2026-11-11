//! UniFi Network controller adapter (local controller or UniFi OS).
//!
//! Authentication uses the controller's own login API with a cookie jar.
//! Blocking uses `cmd/stamgr` and is verified by reading the client's
//! `blocked` flag back. Bandwidth uses per-client user groups with
//! `qos_rate_max_down/up` and is verified through the assigned group id.

use crate::traits::{verify_result, AdapterSecret, EnforcedRule, GatewayAdapter, Target};
use async_trait::async_trait;
use netcontrol_core::models::{
    BandwidthLimit, EnforcementResult, GatewayCapabilities, GatewayClient, GatewayConfig,
    GatewayKind, GatewayProbe,
};
use netcontrol_core::util::normalize_mac;
use netcontrol_core::{Error, Result};
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::{Client, Method};
use serde_json::{json, Value};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub struct UniFiAdapter {
    config: GatewayConfig,
    username: String,
    secret: Option<AdapterSecret>,
}

struct Session {
    http: Client,
    api: String,
    site: String,
}

impl UniFiAdapter {
    pub fn new(config: GatewayConfig, secret: Option<AdapterSecret>) -> Result<Self> {
        let username = config
            .username
            .clone()
            .filter(|u| !u.trim().is_empty())
            .ok_or_else(|| Error::Validation("UniFi requires a username".into()))?;
        if secret.is_none() {
            return Err(Error::Validation("UniFi requires a password".into()));
        }
        Ok(Self {
            config,
            username,
            secret,
        })
    }

    fn root_url(&self) -> String {
        format!(
            "{}://{}:{}",
            if self.config.tls { "https" } else { "http" },
            self.config.host,
            self.config.port
        )
    }

    async fn login(&self) -> Result<Session> {
        let mut headers = HeaderMap::new();
        headers.insert("X-CSRF-Token", HeaderValue::from_static("none"));
        headers.insert("Accept", HeaderValue::from_static("application/json"));
        let http = Client::builder()
            .cookie_store(true)
            .danger_accept_invalid_certs(self.config.tls_insecure)
            .timeout(Duration::from_secs(15))
            .default_headers(headers)
            .build()
            .map_err(|e| Error::Internal(format!("HTTP client: {e}")))?;
        let root = self.root_url();
        let secret = self
            .secret
            .as_ref()
            .ok_or_else(|| Error::Validation("missing UniFi password".into()))?;
        let body = json!({
            "username": self.username,
            "password": secret.value.as_str(),
            "remember": true
        });
        // UniFi OS uses /api/auth/login + /proxy/network; legacy controllers
        // use /api/login and expose the API at the root.
        let mut api = None;
        for (path, proxy) in [("/api/auth/login", true), ("/api/login", false)] {
            let response = http
                .post(format!("{root}{path}"))
                .json(&body)
                .send()
                .await
                .map_err(|e| Error::Gateway(format!("UniFi controller unreachable: {e}")))?;
            if response.status().is_success() {
                api = Some(if proxy {
                    format!("{root}/proxy/network")
                } else {
                    root.clone()
                });
                break;
            }
            if response.status().as_u16() == 401 || response.status().as_u16() == 403 {
                return Err(Error::Forbidden(
                    "UniFi rejected the administrator credentials".into(),
                ));
            }
        }
        let api = api.ok_or_else(|| {
            Error::Gateway(
                "UniFi login failed: neither the UniFi OS nor legacy login endpoint accepted the request"
                    .into(),
            )
        })?;
        // Discover the site.
        let sites = self
            .get_json(&http, &format!("{api}/api/self/sites"))
            .await?;
        let site = self
            .config
            .site
            .clone()
            .filter(|s| !s.trim().is_empty())
            .or_else(|| {
                sites
                    .get("data")
                    .and_then(Value::as_array)
                    .and_then(|arr| arr.first())
                    .and_then(|v| v.get("name"))
                    .and_then(Value::as_str)
                    .map(str::to_string)
            })
            .unwrap_or_else(|| "default".into());
        Ok(Session { http, api, site })
    }

    async fn get_json(&self, http: &Client, url: &str) -> Result<Value> {
        let response = http
            .get(url)
            .send()
            .await
            .map_err(|e| Error::Gateway(format!("UniFi request failed: {e}")))?;
        parse_response(response).await
    }

    async fn post_json(&self, session: &Session, path: &str, body: Value) -> Result<Value> {
        let url = format!("{}/api/s/{}{}", session.api, session.site, path);
        let response = session
            .http
            .request(Method::POST, url)
            .json(&body)
            .send()
            .await
            .map_err(|e| Error::Gateway(format!("UniFi request failed: {e}")))?;
        parse_response(response).await
    }

    async fn clients_raw(&self, session: &Session) -> Result<Vec<Value>> {
        let url = format!("{}/api/s/{}/stat/sta", session.api, session.site);
        let value = self.get_json(&session.http, &url).await?;
        Ok(value
            .get("data")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default())
    }

    async fn find_client(&self, session: &Session, target: &Target) -> Option<Value> {
        let mac = target.mac.as_deref().and_then(normalize_mac);
        let clients = self.clients_raw(session).await.ok()?;
        clients.into_iter().find(|client| {
            let client_mac = client
                .get("mac")
                .and_then(Value::as_str)
                .and_then(normalize_mac);
            let client_ip = client.get("ip").and_then(Value::as_str);
            match (&mac, &target.ip) {
                (Some(mac), _) => client_mac.as_deref() == Some(mac.as_str()),
                (None, Some(ip)) => client_ip == Some(ip.as_str()),
                _ => false,
            }
        })
    }

    async fn usergroup_id_by_name(&self, session: &Session, name: &str) -> Result<Option<String>> {
        let url = format!("{}/api/s/{}/rest/usergroup", session.api, session.site);
        let value = self.get_json(&session.http, &url).await?;
        Ok(value
            .get("data")
            .and_then(Value::as_array)
            .and_then(|arr| {
                arr.iter()
                    .find(|group| group.get("name").and_then(Value::as_str) == Some(name))
            })
            .and_then(|group| group.get("_id"))
            .and_then(Value::as_str)
            .map(str::to_string))
    }
}

async fn parse_response(response: reqwest::Response) -> Result<Value> {
    let status = response.status();
    let text = response.text().await.unwrap_or_default();
    if !status.is_success() {
        let snippet: String = text.chars().take(300).collect();
        return Err(match status.as_u16() {
            401 => Error::Forbidden("UniFi authentication failed".into()),
            403 => Error::Forbidden("UniFi denied the operation".into()),
            _ => Error::Gateway(format!(
                "UniFi returned HTTP {}: {}",
                status.as_u16(),
                netcontrol_core::util::redact_for_log(&snippet)
            )),
        });
    }
    if text.trim().is_empty() {
        return Ok(Value::Null);
    }
    serde_json::from_str(&text)
        .map_err(|e| Error::Gateway(format!("UniFi returned invalid JSON: {e}")))
}

fn online_from(last_seen: Option<i64>) -> bool {
    match last_seen {
        Some(ts) => {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            now.saturating_sub(ts) < 300
        }
        None => true,
    }
}

#[async_trait]
impl GatewayAdapter for UniFiAdapter {
    fn kind(&self) -> GatewayKind {
        GatewayKind::UniFi
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
            bandwidth: true,
            priority: false,
            schedules: true,
            traffic_stats: true,
        }
    }

    async fn probe(&self) -> Result<GatewayProbe> {
        let started = Instant::now();
        match self.login().await {
            Ok(session) => {
                let version = self
                    .get_json(&session.http, &format!("{}/status", self.root_url()))
                    .await
                    .ok()
                    .and_then(|v| {
                        v.get("meta")
                            .and_then(|m| m.get("up"))
                            .and_then(Value::as_bool)
                            .map(|up| {
                                if up {
                                    "controller up".to_string()
                                } else {
                                    "controller degraded".to_string()
                                }
                            })
                    });
                Ok(GatewayProbe {
                    ok: true,
                    kind: GatewayKind::UniFi,
                    name: self.config.name.clone(),
                    version,
                    model: Some("UniFi Network".into()),
                    capabilities: self.capabilities(),
                    latency_ms: started.elapsed().as_millis() as u64,
                    message: format!("UniFi controller authenticated; site {}", session.site),
                })
            }
            Err(err) => Ok(GatewayProbe {
                ok: false,
                kind: GatewayKind::UniFi,
                name: self.config.name.clone(),
                version: None,
                model: None,
                capabilities: self.capabilities(),
                latency_ms: started.elapsed().as_millis() as u64,
                message: err.to_string(),
            }),
        }
    }

    async fn clients(&self) -> Result<Vec<GatewayClient>> {
        let session = self.login().await?;
        let clients = self.clients_raw(&session).await?;
        let mut out = Vec::new();
        for client in clients {
            let mac = client
                .get("mac")
                .and_then(Value::as_str)
                .and_then(normalize_mac);
            let hostname = client
                .get("name")
                .and_then(Value::as_str)
                .or_else(|| client.get("hostname").and_then(Value::as_str))
                .map(str::to_string)
                .filter(|s| !s.is_empty());
            out.push(GatewayClient {
                mac: mac.clone(),
                ip: client.get("ip").and_then(Value::as_str).map(str::to_string),
                hostname,
                vendor: client
                    .get("oui")
                    .and_then(Value::as_str)
                    .map(str::to_string)
                    .or_else(|| mac.as_deref().and_then(netcontrol_core::oui::lookup)),
                interface: if client
                    .get("is_wired")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
                {
                    Some("wired".into())
                } else {
                    Some("wifi".into())
                },
                ssid: client
                    .get("essid")
                    .and_then(Value::as_str)
                    .map(str::to_string),
                online: online_from(client.get("last_seen").and_then(Value::as_i64)),
                rx_bytes: client.get("rx_bytes").and_then(Value::as_u64),
                tx_bytes: client.get("tx_bytes").and_then(Value::as_u64),
                rx_bps: client
                    .get("rx_bytes-r")
                    .and_then(Value::as_u64)
                    .map(|v| v * 8),
                tx_bps: client
                    .get("tx_bytes-r")
                    .and_then(Value::as_u64)
                    .map(|v| v * 8),
                blocked: client.get("blocked").and_then(Value::as_bool),
            });
        }
        out.sort_by(|a, b| a.ip.cmp(&b.ip));
        Ok(out)
    }

    async fn block(&self, target: &Target, _expires_at: Option<&str>) -> Result<EnforcementResult> {
        let session = self.login().await?;
        let client = self.find_client(&session, target).await.ok_or_else(|| {
            Error::Unsupported(
                "device is not currently known to the UniFi controller; a MAC address is required"
                    .into(),
            )
        })?;
        let mac = client
            .get("mac")
            .and_then(Value::as_str)
            .and_then(normalize_mac)
            .ok_or_else(|| Error::Validation("UniFi client has no MAC address".into()))?;
        self.post_json(
            &session,
            "/cmd/stamgr",
            json!({"cmd": "block-sta", "mac": mac}),
        )
        .await?;
        let verified = self
            .find_client(&session, target)
            .await
            .and_then(|c| c.get("blocked").and_then(Value::as_bool))
            .unwrap_or(false);
        Ok(verify_result(
            "unifi",
            "block",
            target,
            verified,
            Some(mac.clone()),
            if verified {
                format!("UniFi reports {mac} as blocked")
            } else {
                "UniFi accepted block-sta but the client does not report blocked=true".into()
            },
        ))
    }

    async fn unblock(&self, target: &Target) -> Result<EnforcementResult> {
        let session = self.login().await?;
        let client = self.find_client(&session, target).await.ok_or_else(|| {
            Error::Unsupported("device is not currently known to the UniFi controller".into())
        })?;
        let mac = client
            .get("mac")
            .and_then(Value::as_str)
            .and_then(normalize_mac)
            .ok_or_else(|| Error::Validation("UniFi client has no MAC address".into()))?;
        self.post_json(
            &session,
            "/cmd/stamgr",
            json!({"cmd": "unblock-sta", "mac": mac}),
        )
        .await?;
        let verified = self
            .find_client(&session, target)
            .await
            .and_then(|c| c.get("blocked").and_then(Value::as_bool))
            .map(|blocked| !blocked)
            .unwrap_or(false);
        Ok(verify_result(
            "unifi",
            "unblock",
            target,
            verified,
            Some(mac.clone()),
            if verified {
                format!("UniFi reports {mac} as unblocked")
            } else {
                "UniFi accepted unblock-sta but the client still reports blocked".into()
            },
        ))
    }

    async fn set_bandwidth(
        &self,
        target: &Target,
        limit: &BandwidthLimit,
    ) -> Result<EnforcementResult> {
        if limit.download_kbps.unwrap_or(0) <= 0 && limit.upload_kbps.unwrap_or(0) <= 0 {
            return Ok(EnforcementResult::unsupported(
                "unifi",
                &target.label,
                "a download or upload limit is required",
            ));
        }
        let session = self.login().await?;
        let client = self.find_client(&session, target).await.ok_or_else(|| {
            Error::Unsupported("device is not currently known to the UniFi controller".into())
        })?;
        let mac = client
            .get("mac")
            .and_then(Value::as_str)
            .and_then(normalize_mac)
            .ok_or_else(|| Error::Validation("UniFi client has no MAC address".into()))?;
        let name = format!("netcontrol-{}", mac.replace(':', ""));
        let down = limit.download_kbps.unwrap_or(0).max(0);
        let up = limit.upload_kbps.unwrap_or(0).max(0);
        let group_id = if let Some(id) = self.usergroup_id_by_name(&session, &name).await? {
            let url = format!(
                "{}/api/s/{}/rest/usergroup/{}",
                session.api, session.site, id
            );
            let response = session
                .http
                .put(url)
                .json(&json!({
                    "name": name,
                    "qos_rate_max_down": down,
                    "qos_rate_max_up": up
                }))
                .send()
                .await
                .map_err(|e| Error::Gateway(format!("UniFi usergroup update failed: {e}")))?;
            parse_response(response).await?;
            id
        } else {
            let value = self
                .post_json(
                    &session,
                    "/rest/usergroup",
                    json!({
                        "name": name,
                        "qos_rate_max_down": down,
                        "qos_rate_max_up": up
                    }),
                )
                .await?;
            value
                .get("data")
                .and_then(Value::as_array)
                .and_then(|a| a.first())
                .and_then(|v| v.get("_id"))
                .and_then(Value::as_str)
                .map(str::to_string)
                .ok_or_else(|| Error::Gateway("UniFi did not return the new usergroup id".into()))?
        };
        self.post_json(
            &session,
            "/cmd/stamgr",
            json!({"cmd": "set-usergroup", "mac": mac, "usergroup_id": group_id}),
        )
        .await?;
        let verified = self
            .find_client(&session, target)
            .await
            .and_then(|c| {
                c.get("usergroup_id")
                    .and_then(Value::as_str)
                    .map(|v| v == group_id)
            })
            .unwrap_or(false);
        Ok(verify_result(
            "unifi",
            "limit",
            target,
            verified,
            Some(group_id.clone()),
            if verified {
                format!("UniFi applied usergroup {name} ({up} Kbps up / {down} Kbps down)")
            } else {
                "UniFi did not confirm the client's usergroup assignment".into()
            },
        ))
    }

    async fn clear_bandwidth(&self, target: &Target) -> Result<EnforcementResult> {
        let session = self.login().await?;
        let client = self.find_client(&session, target).await.ok_or_else(|| {
            Error::Unsupported("device is not currently known to the UniFi controller".into())
        })?;
        let mac = client
            .get("mac")
            .and_then(Value::as_str)
            .and_then(normalize_mac)
            .ok_or_else(|| Error::Validation("UniFi client has no MAC address".into()))?;
        self.post_json(
            &session,
            "/cmd/stamgr",
            json!({"cmd": "set-usergroup", "mac": mac, "usergroup_id": ""}),
        )
        .await?;
        let name = format!("netcontrol-{}", mac.replace(':', ""));
        if let Some(id) = self.usergroup_id_by_name(&session, &name).await? {
            let url = format!(
                "{}/api/s/{}/rest/usergroup/{}",
                session.api, session.site, id
            );
            let response = session
                .http
                .delete(url)
                .send()
                .await
                .map_err(|e| Error::Gateway(format!("UniFi usergroup delete failed: {e}")))?;
            parse_response(response).await.ok();
        }
        let assigned = self
            .find_client(&session, target)
            .await
            .and_then(|c| {
                c.get("usergroup_id")
                    .and_then(Value::as_str)
                    .map(str::to_string)
            })
            .unwrap_or_default();
        let verified = assigned.is_empty();
        Ok(verify_result(
            "unifi",
            "clear_limit",
            target,
            verified,
            None,
            if verified {
                "removed the NetControl user group".to_string()
            } else {
                "client still reports a usergroup assignment".to_string()
            },
        ))
    }

    async fn list_enforced(&self) -> Result<Vec<EnforcedRule>> {
        let session = self.login().await?;
        let clients = self.clients_raw(&session).await?;
        Ok(clients
            .into_iter()
            .filter(|c| c.get("blocked").and_then(Value::as_bool).unwrap_or(false))
            .filter_map(|c| {
                c.get("mac")
                    .and_then(Value::as_str)
                    .map(|mac| EnforcedRule {
                        kind: "block".into(),
                        target: mac.to_string(),
                        rule_id: Some(mac.to_string()),
                        detail: "UniFi blocked client (controller-reported)".into(),
                    })
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_online_state() {
        assert!(online_from(None));
        assert!(!online_from(Some(0)));
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        assert!(online_from(Some(now - 5)));
        assert!(!online_from(Some(now - 3600)));
    }

    #[test]
    fn requires_credentials() {
        let config = GatewayConfig {
            id: "x".into(),
            name: "unifi".into(),
            kind: GatewayKind::UniFi,
            host: "unifi.local".into(),
            port: 443,
            username: None,
            site: None,
            interface_hint: None,
            tls: true,
            tls_insecure: true,
            enabled: true,
            created_at: String::new(),
            updated_at: String::new(),
        };
        assert!(UniFiAdapter::new(config, Some(AdapterSecret::new("pw".into()))).is_err());
    }
}
