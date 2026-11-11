use crate::events::{notification, ServerEvent};
use crate::state::AppState;
use netcontrol_core::db::UpsertOutcome;
use netcontrol_core::models::{
    AccessAction, AccessRule, BandwidthLimit, BandwidthRule, DashboardSummary, Device,
    DeviceFilter, DevicePatch, EnforcementResult, EnforcementState, GatewayClient, GatewayConfig,
    GatewayProbe, HostObservation, ScanMethod, ScanOptions, ScanReport,
};
use netcontrol_core::util::{now_ts, parse_ts};
use netcontrol_core::{Error, Result};
use netcontrol_discovery::InterfaceManager;
use netcontrol_gateway::{build_adapter, GatewayAdapter, Target};
use serde::Serialize;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Serialize)]
pub struct ScanOutcome {
    pub report: ScanReport,
    pub devices: Vec<Device>,
    pub new_devices: u32,
}

#[derive(Serialize)]
pub struct ActionResult {
    pub result: EnforcementResult,
    pub device: Device,
}

#[derive(Serialize)]
pub struct LimitOutcome {
    pub result: EnforcementResult,
    pub device: Device,
}

fn compute_expiry(duration_seconds: Option<u64>, until: Option<&str>) -> Result<Option<String>> {
    let now = chrono::Utc::now();
    let max = now + chrono::Duration::days(365);
    if let Some(duration) = duration_seconds {
        if !(15..=31_536_000).contains(&duration) {
            return Err(Error::Validation(
                "duration_seconds must be between 15 seconds and 365 days".into(),
            ));
        }
        return Ok(Some(
            (now + chrono::Duration::seconds(duration as i64))
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        ));
    }
    if let Some(value) = until.filter(|v| !v.trim().is_empty()) {
        let parsed = parse_ts(value)
            .ok_or_else(|| Error::Validation("until must be an RFC3339 timestamp".into()))?;
        if parsed <= now {
            return Err(Error::Validation("until must be in the future".into()));
        }
        if parsed > max {
            return Err(Error::Validation(
                "temporary restrictions cannot exceed 365 days".into(),
            ));
        }
        return Ok(Some(
            parsed.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        ));
    }
    Ok(None)
}

pub async fn active_gateway(
    state: &Arc<AppState>,
) -> Result<Option<(GatewayConfig, Box<dyn GatewayAdapter>)>> {
    let gateways = state.db.list_gateways()?;
    let selected_id = state.active_gateway_id.read().await.clone();
    let config = match selected_id {
        Some(id) => gateways.iter().find(|g| g.id == id).cloned(),
        None => gateways.iter().find(|g| g.enabled).cloned(),
    };
    let Some(config) = config else {
        return Ok(None);
    };
    if !config.enabled {
        return Err(Error::Validation(format!(
            "gateway {:?} is disabled",
            config.name
        )));
    }
    let secret = match state.db.gateway_secret_encrypted(&config.id)? {
        Some(sealed) => Some(state.key.decrypt(&sealed)?.as_str().to_string()),
        None => None,
    };
    let adapter = build_adapter(&config, secret)?;
    Ok(Some((config, adapter)))
}

pub async fn set_active_gateway(state: &Arc<AppState>, id: &str) -> Result<()> {
    let gateway = state
        .db
        .get_gateway(id)?
        .ok_or_else(|| Error::NotFound(format!("gateway {id}")))?;
    if !gateway.enabled {
        return Err(Error::Validation(
            "cannot activate a disabled gateway".into(),
        ));
    }
    state.db.set_setting("active_gateway_id", id)?;
    *state.active_gateway_id.write().await = Some(id.to_string());
    *state.gateway_cache.write().await = None;
    Ok(())
}

pub async fn probe_active(state: &Arc<AppState>, force: bool) -> Option<GatewayProbe> {
    if !force {
        if let Some((at, probe)) = state.gateway_cache.read().await.clone() {
            if at.elapsed() < Duration::from_secs(45) {
                return Some(probe);
            }
        }
    }
    let (config, adapter) = match active_gateway(state).await {
        Ok(Some(value)) => value,
        Ok(None) => return None,
        Err(err) => {
            return Some(GatewayProbe {
                ok: false,
                kind: netcontrol_core::models::GatewayKind::Linux,
                name: "gateway".into(),
                version: None,
                model: None,
                capabilities: Default::default(),
                latency_ms: 0,
                message: err.to_string(),
            })
        }
    };
    let probe = match adapter.probe().await {
        Ok(probe) => probe,
        Err(err) => GatewayProbe {
            ok: false,
            kind: config.kind,
            name: config.name.clone(),
            version: None,
            model: None,
            capabilities: Default::default(),
            latency_ms: 0,
            message: err.to_string(),
        },
    };
    *state.gateway_cache.write().await = Some((Instant::now(), probe.clone()));
    Some(probe)
}

pub async fn test_gateway(state: &Arc<AppState>, id: &str) -> Result<GatewayProbe> {
    let config = state
        .db
        .get_gateway(id)?
        .ok_or_else(|| Error::NotFound(format!("gateway {id}")))?;
    let secret = match state.db.gateway_secret_encrypted(id)? {
        Some(sealed) => Some(state.key.decrypt(&sealed)?.as_str().to_string()),
        None => None,
    };
    let adapter = build_adapter(&config, secret)?;
    let probe = adapter.probe().await?;
    if state.active_gateway_id.read().await.as_deref() == Some(id) {
        *state.gateway_cache.write().await = Some((Instant::now(), probe.clone()));
    }
    Ok(probe)
}

pub async fn dashboard_summary(state: &Arc<AppState>) -> Result<DashboardSummary> {
    let settings = state.settings.read().await.clone();
    let ifaces = tokio::task::spawn_blocking(InterfaceManager::list)
        .await
        .map_err(|e| Error::Internal(format!("interface enumeration failed: {e}")))??;
    let chosen = ifaces
        .iter()
        .find(|i| settings.preferred_interface.as_deref() == Some(i.name.as_str()))
        .or_else(|| {
            ifaces
                .iter()
                .find(|i| i.is_default && i.primary_ipv4().is_some())
        })
        .or_else(|| {
            ifaces
                .iter()
                .find(|i| i.is_up && i.primary_ipv4().is_some() && !i.is_loopback)
        })
        .cloned();
    let mut network = None;
    if let Some(iface) = &chosen {
        if let Ok(net) = InterfaceManager::network_for(iface) {
            network = Some(match state.db.get_network(&iface.name, &net.cidr)? {
                Some(saved) => netcontrol_core::models::NetworkInfo {
                    id: saved.id,
                    first_seen: saved.first_seen,
                    last_seen: saved.last_seen,
                    ..net
                },
                None => net,
            });
        }
    }
    let counts = state.db.counts()?;
    let probe = probe_active(state, false).await;
    let enforcement_available = probe
        .as_ref()
        .map(|p| p.ok && p.capabilities.block)
        .unwrap_or(false);
    let traffic = crate::monitor::traffic_overview(state).await.or_else(|| {
        Some(crate::monitor::unavailable_overview(
            network.as_ref().map(|n| n.interface.clone()),
        ))
    });
    Ok(DashboardSummary {
        network,
        interfaces: ifaces,
        total_devices: counts.total,
        online_devices: counts.online,
        offline_devices: counts.offline,
        blocked_devices: counts.blocked,
        trusted_devices: counts.trusted,
        unknown_devices: counts.unknown,
        gateway: probe,
        traffic,
        last_scan: state.db.last_scan()?,
        enforcement_available,
        generated_at: now_ts(),
    })
}

pub async fn gateway_clients(state: &Arc<AppState>) -> Result<Vec<GatewayClient>> {
    match active_gateway(state).await? {
        Some((_, adapter)) => adapter.clients().await,
        None => Err(Error::Unsupported(
            "no authorized gateway is configured; discovery and monitoring only".into(),
        )),
    }
}

pub async fn run_scan(
    state: &Arc<AppState>,
    mut opts: ScanOptions,
    actor: &str,
    remote: Option<&str>,
) -> Result<ScanOutcome> {
    let settings = state.settings.read().await.clone();
    if opts.methods.is_empty() {
        opts.methods = settings.default_scan_methods.clone();
    }
    if opts.max_hosts == 0 {
        opts.max_hosts = settings.max_hosts;
    }
    if opts.interface.is_none() {
        opts.interface = settings.preferred_interface.clone();
    }
    if !settings.enable_mdns {
        opts.mdns = false;
        opts.methods.retain(|m| *m != ScanMethod::Mdns);
    }
    if settings.enable_nmap {
        opts.nmap = true;
    }
    let _guard = match state.scan_lock.try_lock() {
        Ok(guard) => guard,
        Err(_) => {
            return Err(Error::Unsupported(
                "a network scan is already running".into(),
            ))
        }
    };
    let (iface, mut net) = InterfaceManager::detect_active(opts.interface.as_deref())?;
    // Remember the operator's interface so the dashboard and traffic monitor
    // stay on the network that was actually scanned.
    if state.settings.read().await.preferred_interface.is_none() {
        let mut settings = state.settings.read().await.clone();
        settings.preferred_interface = Some(iface.name.clone());
        state.db.save_settings(&settings)?;
        *state.settings.write().await = settings;
    }
    let session_id = uuid::Uuid::new_v4().to_string();
    net.id = state
        .db
        .upsert_network(&iface, &net)
        .ok()
        .and_then(|n| n.id);
    state.db.record_interface(&iface)?;
    state.db.start_scan(
        &session_id,
        &iface.name,
        &net.cidr,
        &opts.methods,
        state.engine.tools.privileged_scan(),
    )?;
    state.emit(ServerEvent::ScanStarted {
        session_id: session_id.clone(),
        interface: iface.name.clone(),
        cidr: net.cidr.clone(),
        started_at: now_ts(),
    });
    tracing::info!(
        interface = %iface.name,
        cidr = %net.cidr,
        methods = ?opts.methods,
        "starting network scan"
    );

    let report = match state
        .engine
        .scan_with_session(&iface, &net, &opts, session_id.clone())
        .await
    {
        Ok(report) => report,
        Err(err) => {
            state
                .db
                .finish_scan(&session_id, "failed", 0, Some(&err.to_string()))?;
            state.db.audit(
                actor,
                "scan",
                Some(&iface.name),
                "failed",
                Some(&err.to_string()),
                remote,
            )?;
            state.emit(ServerEvent::Notification {
                notification: notification("error", "Scan failed", err.to_string(), None),
            });
            return Err(err);
        }
    };

    let db = state.db.clone();
    let hosts = report.hosts.clone();
    let interface = iface.name.clone();
    let ssid = net.ssid.clone();
    let sid = session_id.clone();
    let outcomes: Vec<UpsertOutcome> = tokio::task::spawn_blocking(move || {
        let mut out = Vec::with_capacity(hosts.len());
        for host in &hosts {
            out.push(db.upsert_observation(host, Some(&interface), ssid.as_deref(), &sid)?);
        }
        Ok::<_, Error>(out)
    })
    .await
    .map_err(|e| Error::Internal(format!("device persistence task failed: {e}")))??;

    let seen_ids: Vec<String> = outcomes.iter().map(|o| o.device.id.clone()).collect();
    let mut new_devices = outcomes.iter().filter(|o| o.is_new).count() as u32;
    if !report.methods_used.is_empty() {
        let db = state.db.clone();
        let interface = iface.name.clone();
        let ts = now_ts();
        let _ =
            tokio::task::spawn_blocking(move || db.mark_offline_except(&interface, &seen_ids, &ts))
                .await;
    }

    // Merge DHCP/controller client data when an authorized gateway is present.
    // A gateway failure never invalidates the scan itself.
    let mut gateway_devices: Vec<Device> = Vec::new();
    if let Ok(Some((_, adapter))) = active_gateway(state).await {
        match adapter.clients().await {
            Ok(clients) => {
                let db = state.db.clone();
                let interface = iface.name.clone();
                let sid = session_id.clone();
                let observations: Vec<HostObservation> = clients
                    .iter()
                    .filter_map(|client| {
                        if client.ip.is_none() && client.mac.is_none() {
                            return None;
                        }
                        Some(HostObservation {
                            ip: client.ip.clone(),
                            ipv6: None,
                            mac: client.mac.clone(),
                            hostname: client.hostname.clone(),
                            vendor: client.vendor.clone(),
                            category: netcontrol_core::models::DeviceCategory::Unknown,
                            rtt_ms: None,
                            open_ports: Vec::new(),
                            services: Vec::new(),
                            sources: vec!["gateway".into()],
                        })
                    })
                    .collect();
                if let Ok(Ok(extra)) = tokio::task::spawn_blocking(move || {
                    let mut out = Vec::new();
                    for obs in &observations {
                        out.push(db.upsert_observation(obs, Some(&interface), None, &sid)?);
                    }
                    Ok::<_, Error>(out)
                })
                .await
                {
                    for item in extra {
                        if item.is_new {
                            new_devices += 1;
                        }
                        gateway_devices.push(item.device);
                    }
                }
            }
            Err(err) => tracing::debug!(error = %err, "gateway client enrichment failed"),
        }
    }

    state
        .db
        .finish_scan(&session_id, "completed", report.hosts.len() as u32, None)?;
    state.db.audit(
        actor,
        "scan",
        Some(&format!("{} {}", iface.name, net.cidr)),
        "success",
        Some(&format!(
            "{} hosts, {} new, methods {:?}",
            report.hosts.len(),
            new_devices,
            report.methods_used
        )),
        remote,
    )?;

    let discovered: Vec<Device> = outcomes
        .iter()
        .filter(|o| o.is_new)
        .map(|o| o.device.clone())
        .collect();
    let mut devices: Vec<Device> = outcomes.into_iter().map(|o| o.device).collect();
    devices.extend(gateway_devices);
    for device in discovered {
        state.emit(ServerEvent::DeviceDiscovered { device });
    }
    state.emit(ServerEvent::ScanCompleted {
        session_id: session_id.clone(),
        interface: iface.name.clone(),
        cidr: net.cidr.clone(),
        hosts_found: report.hosts.len() as u32,
        new_devices,
        finished_at: report.finished_at.clone(),
        warnings: report.warnings.clone(),
    });
    if new_devices > 0 {
        state.emit(ServerEvent::Notification {
            notification: notification(
                "info",
                "Scan complete",
                format!(
                    "{new_devices} new device{} found on {}",
                    if new_devices == 1 { "" } else { "s" },
                    iface.name
                ),
                None,
            ),
        });
    }
    let mut report = report;
    report.new_devices = new_devices;
    Ok(ScanOutcome {
        report,
        devices,
        new_devices,
    })
}

pub async fn block_device(
    state: &Arc<AppState>,
    device_id: &str,
    action: AccessAction,
    apply: bool,
    until: Option<&str>,
    duration_seconds: Option<u64>,
    reason: Option<&str>,
    confirm: bool,
    actor: &str,
    remote: Option<&str>,
) -> Result<ActionResult> {
    if !confirm {
        return Err(Error::Forbidden(
            "explicit confirmation is required before changing access".into(),
        ));
    }
    let device = state
        .db
        .get_device(device_id)?
        .ok_or_else(|| Error::NotFound(format!("device {device_id}")))?;
    if device.is_trusted && apply {
        tracing::warn!(device = %device.display_name(), "blocking a trusted device by explicit request");
    }
    let target = Target::new(device.ip.clone(), device.mac.clone());
    if target.ip.is_none() && target.mac.is_none() {
        return Err(Error::Validation(
            "device has neither an IP nor MAC address".into(),
        ));
    }
    let expires_at = if apply {
        compute_expiry(duration_seconds, until)?
    } else {
        None
    };
    let rule_id = uuid::Uuid::new_v4().to_string();
    let (adapter_name, gateway_id, result) = match active_gateway(state).await? {
        None => (
            "none".to_string(),
            None,
            EnforcementResult::unsupported(
                "none",
                &target.label,
                "No authorized gateway is configured. NetControl can discover and monitor this network but cannot enforce access control on it.",
            ),
        ),
        Some((config, adapter)) => {
            let result = if apply {
                adapter.block(&target, expires_at.as_deref()).await
            } else {
                adapter.unblock(&target).await
            }
            .unwrap_or_else(|err| {
                EnforcementResult::failed(
                    config.kind.as_str(),
                    &target.label,
                    err.to_string(),
                )
            });
            (config.kind.as_str().to_string(), Some(config.id), result)
        }
    };

    let state_enum = if result.success && result.verified {
        EnforcementState::Applied
    } else if result.action == "unsupported" {
        EnforcementState::Unsupported
    } else {
        EnforcementState::Failed
    };
    let access = AccessRule {
        id: rule_id.clone(),
        device_id: Some(device.id.clone()),
        mac: device.mac.clone(),
        ip: device.ip.clone(),
        action,
        reason: reason.map(str::to_string),
        gateway_config_id: gateway_id,
        state: state_enum,
        created_by: Some(actor.to_string()),
        created_at: now_ts(),
        expires_at: expires_at.clone(),
        last_error: if result.verified {
            None
        } else {
            Some(result.detail.clone())
        },
    };
    state.db.insert_access_rule(&access)?;

    let device = if result.success && result.verified {
        state.db.set_block_state(
            &device.id,
            apply,
            expires_at.as_deref(),
            Some(&adapter_name),
            EnforcementState::Applied,
            Some(&result.detail),
        )?
    } else {
        state.db.set_enforcement(&device.id, state_enum)?;
        state
            .db
            .get_device(&device.id)?
            .ok_or_else(|| Error::NotFound(format!("device {device_id}")))?
    };
    state.db.audit(
        actor,
        if apply { action.as_str() } else { "unblock" },
        Some(&device.id),
        if result.success {
            "success"
        } else if result.action == "unsupported" {
            "unsupported"
        } else {
            "failed"
        },
        Some(&result.detail),
        remote,
    )?;
    state.emit(ServerEvent::Enforcement {
        result: result.clone(),
        device: device.clone(),
    });
    state.emit(ServerEvent::Notification {
        notification: notification(
            if result.success { "success" } else { "warning" },
            if apply {
                "Access restricted"
            } else {
                "Access restored"
            },
            format!("{}: {}", device.display_name(), result.detail),
            Some(device.id.clone()),
        ),
    });
    Ok(ActionResult { result, device })
}

pub async fn trust_device(
    state: &Arc<AppState>,
    device_id: &str,
    trusted: bool,
    actor: &str,
    remote: Option<&str>,
) -> Result<Device> {
    let patch = DevicePatch {
        custom_name: None,
        category: None,
        notes: None,
        is_trusted: Some(trusted),
    };
    let device = state.db.update_device(device_id, &patch)?;
    state.db.audit(
        actor,
        if trusted {
            "trust_device"
        } else {
            "untrust_device"
        },
        Some(device_id),
        "success",
        Some(&device.display_name()),
        remote,
    )?;
    state.emit(ServerEvent::DeviceUpdated {
        device: device.clone(),
    });
    Ok(device)
}

pub async fn patch_device(
    state: &Arc<AppState>,
    device_id: &str,
    patch: &DevicePatch,
    actor: &str,
    remote: Option<&str>,
) -> Result<Device> {
    let device = state.db.update_device(device_id, patch)?;
    state.db.audit(
        actor,
        "update_device",
        Some(device_id),
        "success",
        Some(&device.display_name()),
        remote,
    )?;
    state.emit(ServerEvent::DeviceUpdated {
        device: device.clone(),
    });
    Ok(device)
}

pub async fn set_bandwidth(
    state: &Arc<AppState>,
    device_id: &str,
    download_kbps: Option<i64>,
    upload_kbps: Option<i64>,
    priority: Option<i32>,
    expires_at: Option<&str>,
    confirm: bool,
    actor: &str,
    remote: Option<&str>,
) -> Result<LimitOutcome> {
    if !confirm {
        return Err(Error::Forbidden(
            "explicit confirmation is required before changing bandwidth".into(),
        ));
    }
    let device = state
        .db
        .get_device(device_id)?
        .ok_or_else(|| Error::NotFound(format!("device {device_id}")))?;
    for rate in [download_kbps, upload_kbps].into_iter().flatten() {
        if rate < 1 || rate > 10_000_000 {
            return Err(Error::Validation(
                "bandwidth must be between 1 Kbps and 10 Gbps".into(),
            ));
        }
    }
    if let Some(priority) = priority {
        if !(0..=7).contains(&priority) {
            return Err(Error::Validation("priority must be between 0 and 7".into()));
        }
    }
    if download_kbps.is_none() && upload_kbps.is_none() {
        return Err(Error::Validation(
            "at least one of download_kbps or upload_kbps is required".into(),
        ));
    }
    let expiry = match expires_at.filter(|v| !v.trim().is_empty()) {
        Some(value) => compute_expiry(None, Some(value))?,
        None => None,
    };
    let target = Target::new(device.ip.clone(), device.mac.clone());
    let limit = BandwidthLimit {
        download_kbps,
        upload_kbps,
        priority,
        expires_at: expiry.clone(),
    };
    let (gateway_id, result) = match active_gateway(state).await? {
        None => (
            None,
            EnforcementResult::unsupported(
                "none",
                &target.label,
                "No authorized gateway is configured; bandwidth limits cannot be enforced.",
            ),
        ),
        Some((config, adapter)) => {
            let result = adapter
                .set_bandwidth(&target, &limit)
                .await
                .unwrap_or_else(|err| {
                    EnforcementResult::failed(config.kind.as_str(), &target.label, err.to_string())
                });
            (Some(config.id), result)
        }
    };
    let rule_state = if result.verified {
        EnforcementState::Applied
    } else if result.action == "unsupported" {
        EnforcementState::Unsupported
    } else {
        EnforcementState::Failed
    };
    state.db.insert_bandwidth_rule(&BandwidthRule {
        id: uuid::Uuid::new_v4().to_string(),
        device_id: Some(device.id.clone()),
        mac: device.mac.clone(),
        ip: device.ip.clone(),
        download_kbps,
        upload_kbps,
        priority,
        gateway_config_id: gateway_id,
        state: rule_state,
        created_at: now_ts(),
        expires_at: expiry.clone(),
        last_error: if result.verified {
            None
        } else {
            Some(result.detail.clone())
        },
    })?;
    let device = if result.verified {
        state.db.set_limit_state(
            &device.id,
            download_kbps,
            upload_kbps,
            priority,
            expiry.as_deref(),
            EnforcementState::Applied,
        )?
    } else {
        state.db.set_enforcement(&device.id, rule_state)?;
        state.db.get_device(&device.id)?.unwrap_or(device)
    };
    state.db.audit(
        actor,
        "set_bandwidth",
        Some(&device.id),
        if result.verified {
            "success"
        } else if result.action == "unsupported" {
            "unsupported"
        } else {
            "failed"
        },
        Some(&result.detail),
        remote,
    )?;
    state.emit(ServerEvent::Enforcement {
        result: result.clone(),
        device: device.clone(),
    });
    Ok(LimitOutcome { result, device })
}

pub async fn clear_bandwidth(
    state: &Arc<AppState>,
    device_id: &str,
    confirm: bool,
    actor: &str,
    remote: Option<&str>,
) -> Result<LimitOutcome> {
    if !confirm {
        return Err(Error::Forbidden(
            "explicit confirmation is required before changing bandwidth".into(),
        ));
    }
    let device = state
        .db
        .get_device(device_id)?
        .ok_or_else(|| Error::NotFound(format!("device {device_id}")))?;
    let target = Target::new(device.ip.clone(), device.mac.clone());
    let result = match active_gateway(state).await? {
        None => EnforcementResult::unsupported(
            "none",
            &target.label,
            "No authorized gateway is configured; there is no enforced limit to clear.",
        ),
        Some((config, adapter)) => adapter
            .clear_bandwidth(&target)
            .await
            .unwrap_or_else(|err| {
                EnforcementResult::failed(config.kind.as_str(), &target.label, err.to_string())
            }),
    };
    let device = if result.verified {
        state.db.set_limit_state(
            &device.id,
            None,
            None,
            None,
            None,
            EnforcementState::Applied,
        )?
    } else {
        device
    };
    state.db.audit(
        actor,
        "clear_bandwidth",
        Some(&device.id),
        if result.verified { "success" } else { "failed" },
        Some(&result.detail),
        remote,
    )?;
    state.emit(ServerEvent::Enforcement {
        result: result.clone(),
        device: device.clone(),
    });
    Ok(LimitOutcome { result, device })
}

pub async fn auto_unblock(state: &Arc<AppState>, device: &Device) -> Result<bool> {
    let target = Target::new(device.ip.clone(), device.mac.clone());
    match active_gateway(state).await? {
        Some((_, adapter)) => {
            let result = adapter.unblock(&target).await?;
            if result.verified {
                state.db.set_block_state(
                    &device.id,
                    false,
                    None,
                    None,
                    EnforcementState::Applied,
                    Some("temporary restriction expired"),
                )?;
            }
            Ok(result.verified)
        }
        None => Ok(false),
    }
}

pub async fn auto_clear_limit(state: &Arc<AppState>, device: &Device) -> Result<bool> {
    let target = Target::new(device.ip.clone(), device.mac.clone());
    match active_gateway(state).await? {
        Some((_, adapter)) => {
            let result = adapter.clear_bandwidth(&target).await?;
            if result.verified {
                state.db.set_limit_state(
                    &device.id,
                    None,
                    None,
                    None,
                    None,
                    EnforcementState::Applied,
                )?;
            }
            Ok(result.verified)
        }
        None => Ok(false),
    }
}

pub fn blocked_devices_due(state: &Arc<AppState>, now: &str) -> Result<Vec<Device>> {
    let page = state.db.list_devices(&DeviceFilter {
        blocked: Some(true),
        limit: 500,
        ..Default::default()
    })?;
    Ok(page
        .items
        .into_iter()
        .filter(|d| {
            d.blocked_until
                .as_deref()
                .map(|until| until <= now)
                .unwrap_or(false)
        })
        .collect())
}

pub fn limited_devices_due(state: &Arc<AppState>, now: &str) -> Result<Vec<Device>> {
    let page = state.db.list_devices(&DeviceFilter {
        limit: 500,
        ..Default::default()
    })?;
    Ok(page
        .items
        .into_iter()
        .filter(|d| {
            d.limit_expires_at
                .as_deref()
                .map(|until| until <= now)
                .unwrap_or(false)
        })
        .collect())
}
