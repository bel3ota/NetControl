#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use netcontrol_core::config::{Config, Paths};
use netcontrol_core::models::{
    AccessAction, AccessRule, AppSettings, AuditLog, BandwidthRule, DashboardSummary, Device,
    DeviceCategory, DeviceFilter, DeviceHistory, DevicePatch, GatewayConfigInput, GatewayProbe,
    MonitoringSample, NetworkInterface, ScanMethod, ScanOptions, SystemStatus, TrafficOverview,
};
use netcontrol_service::api::GatewayView;
use netcontrol_service::orchestration;
use netcontrol_service::AppState;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tauri::{Manager, State};

struct LocalState {
    app: Arc<AppState>,
}

fn err(error: impl std::fmt::Display) -> String {
    error.to_string()
}

#[derive(Debug, Deserialize)]
struct DeviceQueryInput {
    query: Option<String>,
    online: Option<bool>,
    blocked: Option<bool>,
    trusted: Option<bool>,
    category: Option<String>,
    interface: Option<String>,
    sort: Option<String>,
    order: Option<String>,
    limit: Option<u32>,
    offset: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct ScanInput {
    interface: Option<String>,
    #[serde(default)]
    methods: Vec<String>,
    #[serde(default)]
    nmap: bool,
    #[serde(default)]
    ports: bool,
    mdns: Option<bool>,
    timeout_ms: Option<u64>,
    max_hosts: Option<u32>,
    #[serde(default)]
    allow_public: bool,
    #[serde(default)]
    confirm: bool,
}

#[derive(Debug, Deserialize)]
struct RestrictionInput {
    duration_seconds: Option<u64>,
    until: Option<String>,
    reason: Option<String>,
    #[serde(default)]
    confirm: bool,
}

#[derive(Debug, Deserialize)]
struct BandwidthInput {
    download_kbps: Option<i64>,
    upload_kbps: Option<i64>,
    priority: Option<i32>,
    expires_at: Option<String>,
    #[serde(default)]
    confirm: bool,
}

#[derive(Debug, Serialize)]
struct DeviceDetailOutput {
    device: Device,
    history: Vec<DeviceHistory>,
    traffic: Option<MonitoringSample>,
    access_rules: Vec<AccessRule>,
    bandwidth_rules: Vec<BandwidthRule>,
}

#[tauri::command]
async fn local_dashboard(state: State<'_, LocalState>) -> Result<DashboardSummary, String> {
    let app = state.app.clone();
    orchestration::dashboard_summary(&app).await.map_err(err)
}

#[tauri::command]
async fn local_interfaces() -> Result<Vec<NetworkInterface>, String> {
    tokio::task::spawn_blocking(netcontrol_discovery::InterfaceManager::list)
        .await
        .map_err(err)?
        .map_err(err)
}

#[tauri::command]
async fn local_devices(
    state: State<'_, LocalState>,
    filter: DeviceQueryInput,
) -> Result<netcontrol_core::models::Paged<Device>, String> {
    let category = match filter.category.as_deref().filter(|value| !value.is_empty()) {
        Some(value) => Some(value.parse::<DeviceCategory>().map_err(err)?),
        None => None,
    };
    let filter = DeviceFilter {
        query: filter.query,
        online: filter.online,
        blocked: filter.blocked,
        trusted: filter.trusted,
        category,
        interface: filter.interface,
        sort: filter.sort,
        descending: filter.order.as_deref() == Some("desc"),
        limit: filter.limit.unwrap_or(100).clamp(1, 500),
        offset: filter.offset.unwrap_or(0),
    };
    state.app.db.list_devices(&filter).map_err(err)
}

#[tauri::command]
async fn local_device_detail(
    state: State<'_, LocalState>,
    id: String,
) -> Result<DeviceDetailOutput, String> {
    let device = state
        .app
        .db
        .get_device(&id)
        .map_err(err)?
        .ok_or_else(|| format!("device {id} not found"))?;
    let history = state.app.db.list_history(&id, 200).map_err(err)?;
    let traffic = state.app.db.latest_device_traffic(&id).map_err(err)?;
    let access_rules = state
        .app
        .db
        .list_access_rules(false, 500)
        .map_err(err)?
        .into_iter()
        .filter(|rule| rule.device_id.as_deref() == Some(id.as_str()))
        .collect();
    let bandwidth_rules = state
        .app
        .db
        .list_bandwidth_rules(false, 500)
        .map_err(err)?
        .into_iter()
        .filter(|rule| rule.device_id.as_deref() == Some(id.as_str()))
        .collect();
    Ok(DeviceDetailOutput {
        device,
        history,
        traffic,
        access_rules,
        bandwidth_rules,
    })
}

#[tauri::command]
async fn local_scan(
    state: State<'_, LocalState>,
    request: ScanInput,
) -> Result<orchestration::ScanOutcome, String> {
    if !request.confirm {
        return Err("scan confirmation is required".into());
    }
    let methods = request
        .methods
        .iter()
        .map(|method| method.parse::<ScanMethod>().map_err(err))
        .collect::<Result<Vec<_>, _>>()?;
    let opts = ScanOptions {
        interface: request.interface,
        methods,
        nmap: request.nmap,
        ports: request.ports,
        timeout_ms: request.timeout_ms.unwrap_or(1200),
        max_hosts: request.max_hosts.unwrap_or(0),
        mdns: request.mdns.unwrap_or(true),
        allow_public: request.allow_public,
        confirmed: true,
    };
    let app = state.app.clone();
    orchestration::run_scan(&app, opts, "desktop", None)
        .await
        .map_err(err)
}

#[tauri::command]
async fn local_update_device(
    state: State<'_, LocalState>,
    id: String,
    patch: DevicePatch,
) -> Result<Device, String> {
    let app = state.app.clone();
    orchestration::patch_device(&app, &id, &patch, "desktop", None)
        .await
        .map_err(err)
}

#[tauri::command]
async fn local_trust_device(
    state: State<'_, LocalState>,
    id: String,
    trusted: bool,
) -> Result<Device, String> {
    let app = state.app.clone();
    orchestration::trust_device(&app, &id, trusted, "desktop", None)
        .await
        .map_err(err)
}

#[tauri::command]
async fn local_block_device(
    state: State<'_, LocalState>,
    id: String,
    request: RestrictionInput,
) -> Result<orchestration::ActionResult, String> {
    let app = state.app.clone();
    orchestration::block_device(
        &app,
        &id,
        AccessAction::Block,
        true,
        request.until.as_deref(),
        request.duration_seconds,
        request.reason.as_deref(),
        request.confirm,
        "desktop",
        None,
    )
    .await
    .map_err(err)
}

#[tauri::command]
async fn local_pause_device(
    state: State<'_, LocalState>,
    id: String,
    request: RestrictionInput,
) -> Result<orchestration::ActionResult, String> {
    if request.duration_seconds.is_none() && request.until.is_none() {
        return Err("pause requires a duration".into());
    }
    let app = state.app.clone();
    orchestration::block_device(
        &app,
        &id,
        AccessAction::Pause,
        true,
        request.until.as_deref(),
        request.duration_seconds,
        request.reason.as_deref(),
        request.confirm,
        "desktop",
        None,
    )
    .await
    .map_err(err)
}

#[tauri::command]
async fn local_unblock_device(
    state: State<'_, LocalState>,
    id: String,
) -> Result<orchestration::ActionResult, String> {
    let app = state.app.clone();
    orchestration::block_device(
        &app,
        &id,
        AccessAction::Allow,
        false,
        None,
        None,
        None,
        true,
        "desktop",
        None,
    )
    .await
    .map_err(err)
}

#[tauri::command]
async fn local_set_limit(
    state: State<'_, LocalState>,
    id: String,
    request: BandwidthInput,
) -> Result<orchestration::LimitOutcome, String> {
    let app = state.app.clone();
    orchestration::set_bandwidth(
        &app,
        &id,
        request.download_kbps,
        request.upload_kbps,
        request.priority,
        request.expires_at.as_deref(),
        request.confirm,
        "desktop",
        None,
    )
    .await
    .map_err(err)
}

#[tauri::command]
async fn local_clear_limit(
    state: State<'_, LocalState>,
    id: String,
) -> Result<orchestration::LimitOutcome, String> {
    let app = state.app.clone();
    orchestration::clear_bandwidth(&app, &id, true, "desktop", None)
        .await
        .map_err(err)
}

#[tauri::command]
async fn local_access_rules(state: State<'_, LocalState>) -> Result<Vec<AccessRule>, String> {
    state.app.db.list_access_rules(false, 500).map_err(err)
}

#[tauri::command]
async fn local_bandwidth_rules(state: State<'_, LocalState>) -> Result<Vec<BandwidthRule>, String> {
    state.app.db.list_bandwidth_rules(false, 500).map_err(err)
}

#[tauri::command]
async fn local_monitoring_overview(
    state: State<'_, LocalState>,
) -> Result<TrafficOverview, String> {
    Ok(netcontrol_service::monitor::traffic_overview(&state.app)
        .await
        .unwrap_or_else(|| netcontrol_service::monitor::unavailable_overview(None)))
}

#[tauri::command]
async fn local_monitoring_history(
    state: State<'_, LocalState>,
    minutes: Option<u32>,
    limit: Option<u32>,
    iface: Option<String>,
) -> Result<Vec<MonitoringSample>, String> {
    state
        .app
        .db
        .monitoring_history(
            iface.as_deref(),
            minutes.unwrap_or(60),
            limit.unwrap_or(1000),
        )
        .map_err(err)
}

#[tauri::command]
async fn local_gateways(state: State<'_, LocalState>) -> Result<Vec<GatewayView>, String> {
    let active = state.app.active_gateway_id.read().await.clone();
    let cached = state
        .app
        .gateway_cache
        .read()
        .await
        .as_ref()
        .map(|(_, probe)| probe.capabilities.clone());
    let mut out = Vec::new();
    for config in state.app.db.list_gateways().map_err(err)? {
        let has_secret = state
            .app
            .db
            .gateway_secret_encrypted(&config.id)
            .map_err(err)?
            .is_some();
        let is_active = active.as_deref() == Some(config.id.as_str());
        out.push(GatewayView {
            active: is_active,
            has_secret,
            capabilities: if is_active {
                cached.clone().unwrap_or_default()
            } else {
                Default::default()
            },
            config,
        });
    }
    Ok(out)
}

#[tauri::command]
async fn local_gateway_status(
    state: State<'_, LocalState>,
) -> Result<Option<GatewayProbe>, String> {
    Ok(orchestration::probe_active(&state.app, true).await)
}

fn view_for(state: &Arc<AppState>, config: netcontrol_core::models::GatewayConfig) -> GatewayView {
    let has_secret = state
        .db
        .gateway_secret_encrypted(&config.id)
        .ok()
        .flatten()
        .is_some();
    GatewayView {
        active: state
            .active_gateway_id
            .try_read()
            .map(|id| id.as_deref() == Some(config.id.as_str()))
            .unwrap_or(false),
        has_secret,
        capabilities: Default::default(),
        config,
    }
}

#[tauri::command]
async fn local_create_gateway(
    state: State<'_, LocalState>,
    input: GatewayConfigInput,
) -> Result<GatewayView, String> {
    netcontrol_gateway::validate_host(&input.host).map_err(err)?;
    if netcontrol_gateway::require_secret(input.kind)
        && input.secret.as_deref().unwrap_or("").is_empty()
    {
        return Err(format!("{} requires a password or API secret", input.kind));
    }
    let sealed = match input.secret.as_deref().filter(|secret| !secret.is_empty()) {
        Some(secret) => Some(state.app.key.encrypt(secret).map_err(err)?),
        None => None,
    };
    let config = state
        .app
        .db
        .create_gateway(&input, sealed.as_deref())
        .map_err(err)?;
    let is_first = state.app.db.list_gateways().map_err(err)?.len() == 1;
    if is_first {
        state
            .app
            .db
            .set_setting("active_gateway_id", &config.id)
            .map_err(err)?;
        *state.app.active_gateway_id.write().await = Some(config.id.clone());
    }
    state
        .app
        .db
        .audit(
            "desktop",
            "create_gateway",
            Some(&config.id),
            "success",
            Some(&config.name),
            None,
        )
        .ok();
    Ok(view_for(&state.app, config))
}

#[tauri::command]
async fn local_update_gateway(
    state: State<'_, LocalState>,
    id: String,
    input: GatewayConfigInput,
) -> Result<GatewayView, String> {
    netcontrol_gateway::validate_host(&input.host).map_err(err)?;
    let sealed = match input.secret.as_deref().filter(|secret| !secret.is_empty()) {
        Some(secret) => Some(state.app.key.encrypt(secret).map_err(err)?),
        None => None,
    };
    let config = state
        .app
        .db
        .update_gateway(&id, &input, sealed.as_deref())
        .map_err(err)?;
    *state.app.gateway_cache.write().await = None;
    state
        .app
        .db
        .audit(
            "desktop",
            "update_gateway",
            Some(&id),
            "success",
            Some(&config.name),
            None,
        )
        .ok();
    Ok(view_for(&state.app, config))
}

#[tauri::command]
async fn local_delete_gateway(state: State<'_, LocalState>, id: String) -> Result<(), String> {
    state.app.db.delete_gateway(&id).map_err(err)?;
    if state.app.active_gateway_id.read().await.as_deref() == Some(id.as_str()) {
        let next = state
            .app
            .db
            .list_gateways()
            .map_err(err)?
            .into_iter()
            .find(|gateway| gateway.enabled)
            .map(|gateway| gateway.id);
        *state.app.active_gateway_id.write().await = next.clone();
        state
            .app
            .db
            .set_setting("active_gateway_id", next.as_deref().unwrap_or(""))
            .map_err(err)?;
        *state.app.gateway_cache.write().await = None;
    }
    Ok(())
}

#[tauri::command]
async fn local_test_gateway(
    state: State<'_, LocalState>,
    id: String,
) -> Result<GatewayProbe, String> {
    orchestration::test_gateway(&state.app, &id)
        .await
        .map_err(err)
}

#[tauri::command]
async fn local_activate_gateway(state: State<'_, LocalState>, id: String) -> Result<(), String> {
    orchestration::set_active_gateway(&state.app, &id)
        .await
        .map_err(err)
}

#[tauri::command]
async fn local_settings(state: State<'_, LocalState>) -> Result<AppSettings, String> {
    Ok(state.app.settings.read().await.clone())
}

#[tauri::command]
async fn local_save_settings(
    state: State<'_, LocalState>,
    settings: AppSettings,
) -> Result<AppSettings, String> {
    if settings.scan_interval_seconds < 15
        || settings.max_hosts == 0
        || settings.max_hosts > 65_534
        || settings.retention_days == 0
    {
        return Err("invalid settings range".into());
    }
    state.app.db.save_settings(&settings).map_err(err)?;
    *state.app.settings.write().await = settings.clone();
    state
        .app
        .db
        .audit(
            "desktop",
            "update_settings",
            None,
            "success",
            Some("settings updated"),
            None,
        )
        .ok();
    Ok(settings)
}

#[tauri::command]
async fn local_audit(
    state: State<'_, LocalState>,
    limit: Option<u32>,
) -> Result<Vec<AuditLog>, String> {
    state
        .app
        .db
        .list_audit(limit.unwrap_or(100).clamp(1, 1000), 0)
        .map_err(err)
}

#[tauri::command]
async fn local_system_status(state: State<'_, LocalState>) -> Result<SystemStatus, String> {
    Ok(state.app.status())
}

pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            let paths = Paths::discover().map_err(|error| {
                Box::<dyn std::error::Error>::from(std::io::Error::other(error.to_string()))
            })?;
            let config = Config::load_or_create(&paths).map_err(|error| {
                Box::<dyn std::error::Error>::from(std::io::Error::other(error.to_string()))
            })?;
            let state = AppState::load(paths, config).map_err(|error| {
                Box::<dyn std::error::Error>::from(std::io::Error::other(error.to_string()))
            })?;
            tauri::async_runtime::spawn(netcontrol_service::monitor::monitor_loop(state.clone()));
            tauri::async_runtime::spawn(netcontrol_service::scheduler::scheduler_loop(
                state.clone(),
            ));
            app.manage(LocalState { app: state });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            local_dashboard,
            local_interfaces,
            local_devices,
            local_device_detail,
            local_scan,
            local_update_device,
            local_trust_device,
            local_block_device,
            local_pause_device,
            local_unblock_device,
            local_set_limit,
            local_clear_limit,
            local_access_rules,
            local_bandwidth_rules,
            local_monitoring_overview,
            local_monitoring_history,
            local_gateways,
            local_gateway_status,
            local_create_gateway,
            local_update_gateway,
            local_delete_gateway,
            local_test_gateway,
            local_activate_gateway,
            local_settings,
            local_save_settings,
            local_audit,
            local_system_status,
        ])
        .run(tauri::generate_context!())
        .expect("error while running NetControl");
}
