//! Common gateway adapter contract.
//!
//! Every adapter is responsible for verifying the state it applied. A
//! successful HTTP response is not enough: the adapter must read the
//! resulting rule back before reporting `verified = true`.

use async_trait::async_trait;
use netcontrol_core::models::{
    BandwidthLimit, EnforcementResult, GatewayCapabilities, GatewayClient, GatewayConfig,
    GatewayKind, GatewayProbe,
};
use netcontrol_core::Result;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

#[derive(Debug, Clone)]
pub struct Target {
    pub ip: Option<String>,
    pub mac: Option<String>,
    pub label: String,
}

impl Target {
    pub fn new(ip: Option<String>, mac: Option<String>) -> Self {
        let label = ip
            .clone()
            .or_else(|| mac.clone())
            .unwrap_or_else(|| "unknown target".into());
        Self { ip, mac, label }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnforcedRule {
    pub kind: String,
    pub target: String,
    pub rule_id: Option<String>,
    pub detail: String,
}

#[derive(Debug, Clone)]
pub struct AdapterSecret {
    pub value: Zeroizing<String>,
}

impl AdapterSecret {
    pub fn new(value: String) -> Self {
        Self {
            value: Zeroizing::new(value),
        }
    }
}

#[async_trait]
pub trait GatewayAdapter: Send + Sync {
    fn kind(&self) -> GatewayKind;
    fn name(&self) -> String;
    fn config(&self) -> &GatewayConfig;
    fn capabilities(&self) -> GatewayCapabilities;
    async fn probe(&self) -> Result<GatewayProbe>;
    async fn clients(&self) -> Result<Vec<GatewayClient>>;
    async fn block(&self, target: &Target, expires_at: Option<&str>) -> Result<EnforcementResult>;
    async fn unblock(&self, target: &Target) -> Result<EnforcementResult>;
    async fn set_bandwidth(
        &self,
        target: &Target,
        limit: &BandwidthLimit,
    ) -> Result<EnforcementResult>;
    async fn clear_bandwidth(&self, target: &Target) -> Result<EnforcementResult>;
    async fn list_enforced(&self) -> Result<Vec<EnforcedRule>>;
}

pub fn verify_result(
    adapter: &str,
    action: &str,
    target: &Target,
    verified: bool,
    rule_id: Option<String>,
    detail: impl Into<String>,
) -> EnforcementResult {
    EnforcementResult {
        success: verified,
        verified,
        action: action.into(),
        target: target.label.clone(),
        adapter: adapter.into(),
        detail: detail.into(),
        applied_at: netcontrol_core::util::now_ts(),
        rule_id,
    }
}
