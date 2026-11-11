use crate::auth::{self, AuthUser};
use crate::error::ApiError;
use crate::events::ServerEvent;
use crate::monitor::{traffic_overview, unavailable_overview};
use crate::orchestration::{
    self, block_device, clear_bandwidth, patch_device, probe_active, run_scan, set_active_gateway,
    set_bandwidth, test_gateway, trust_device,
};
use crate::state::AppState;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderName, HeaderValue, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::IntoResponse;
use axum::routing::{get, post, put};
use axum::{Extension, Json, Router};
use futures::StreamExt;
use netcontrol_core::models::{
    AccessAction, AccessRule, AppSettings, AuditLog, AuthSession, BandwidthRule, DashboardSummary,
    Device, DeviceCategory, DeviceFilter, DeviceHistory, DevicePatch, EnforcementResult,
    GatewayClient, GatewayConfig, GatewayConfigInput, GatewayProbe, MonitoringSample, NetworkInfo,
    NetworkInterface, Paged, Role, ScanMethod, ScanOptions, ScanSession, SystemStatus,
    TrafficOverview, UserSummary,
};
use netcontrol_core::security;
use netcontrol_core::Result as CoreResult;
use netcontrol_discovery::InterfaceManager;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio_stream::wrappers::BroadcastStream;
use tower_http::cors::CorsLayer;
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::trace::TraceLayer;

#[derive(Clone)]
pub struct RemoteAddr(pub String);

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct DeviceQuery {
    pub query: Option<String>,
    pub online: Option<bool>,
    pub blocked: Option<bool>,
    pub trusted: Option<bool>,
    pub category: Option<String>,
    pub interface: Option<String>,
    pub sort: Option<String>,
    pub order: Option<String>,
    pub limit: Option<u32>,
    pub offset: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct ScanRequest {
    pub interface: Option<String>,
    #[serde(default)]
    pub methods: Vec<String>,
    #[serde(default)]
    pub nmap: bool,
    #[serde(default)]
    pub ports: bool,
    #[serde(default)]
    pub mdns: Option<bool>,
    pub timeout_ms: Option<u64>,
    pub max_hosts: Option<u32>,
    #[serde(default)]
    pub allow_public: bool,
    #[serde(default)]
    pub confirm: bool,
}

#[derive(Debug, Deserialize)]
pub struct BlockRequest {
    pub duration_seconds: Option<u64>,
    pub until: Option<String>,
    pub reason: Option<String>,
    #[serde(default)]
    pub confirm: bool,
}

#[derive(Debug, Deserialize)]
pub struct UnblockRequest {
    #[serde(default)]
    pub confirm: bool,
}

#[derive(Debug, Deserialize)]
pub struct TrustRequest {
    pub trusted: bool,
}

#[derive(Debug, Deserialize)]
pub struct BandwidthRequest {
    pub download_kbps: Option<i64>,
    pub upload_kbps: Option<i64>,
    pub priority: Option<i32>,
    pub expires_at: Option<String>,
    #[serde(default)]
    pub confirm: bool,
}

#[derive(Debug, Deserialize)]
pub struct HistoryQuery {
    pub minutes: Option<u32>,
    pub limit: Option<u32>,
    pub interface: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct PageQuery {
    pub limit: Option<u32>,
    pub offset: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct EventQuery {
    pub token: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub password: String,
    pub role: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

#[derive(Debug, Serialize)]
pub struct ActionResultResponse {
    pub result: EnforcementResult,
    pub device: Device,
}

#[derive(Debug, Serialize)]
pub struct ScanResponse {
    pub report: netcontrol_core::models::ScanReport,
    pub devices: Vec<Device>,
    pub new_devices: u32,
}

#[derive(Debug, Serialize)]
pub struct DeviceDetail {
    pub device: Device,
    pub history: Vec<DeviceHistory>,
    pub traffic: Option<MonitoringSample>,
    pub access_rules: Vec<AccessRule>,
    pub bandwidth_rules: Vec<BandwidthRule>,
}

#[derive(Debug, Serialize)]
pub struct GatewayView {
    #[serde(flatten)]
    pub config: GatewayConfig,
    pub active: bool,
    pub has_secret: bool,
    pub capabilities: netcontrol_core::models::GatewayCapabilities,
}

pub fn router(state: Arc<AppState>) -> Router {
    let origins = [
        "tauri://localhost",
        "http://tauri.localhost",
        "https://tauri.localhost",
        "http://localhost:1420",
        "http://127.0.0.1:1420",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:8787",
        "http://127.0.0.1:4173",
        "http://localhost:4173",
    ]
    .iter()
    .filter_map(|value| HeaderValue::from_str(value).ok())
    .collect::<Vec<_>>();
    let cors = CorsLayer::new()
        .allow_origin(origins)
        .allow_methods([
            axum::http::Method::GET,
            axum::http::Method::POST,
            axum::http::Method::PUT,
            axum::http::Method::PATCH,
            axum::http::Method::DELETE,
            axum::http::Method::OPTIONS,
        ])
        .allow_headers([
            axum::http::header::AUTHORIZATION,
            axum::http::header::CONTENT_TYPE,
            axum::http::header::ACCEPT,
            HeaderName::from_static("x-api-token"),
            HeaderName::from_static("x-csrf-token"),
        ])
        .allow_credentials(true);

    Router::new()
        .route("/health", get(health))
        .route("/api/v1/openapi.json", get(openapi))
        .route("/api/v1/auth/login", post(login))
        .route("/api/v1/auth/logout", post(logout))
        .route("/api/v1/auth/me", get(me))
        .route("/api/v1/auth/password", post(change_password))
        .route("/api/v1/system/status", get(system_status))
        .route("/api/v1/dashboard", get(dashboard))
        .route("/api/v1/interfaces", get(interfaces))
        .route("/api/v1/networks", get(networks))
        .route("/api/v1/scans", post(scan).get(scans))
        .route("/api/v1/devices", get(devices))
        .route(
            "/api/v1/devices/{id}",
            get(device_detail).patch(update_device),
        )
        .route("/api/v1/devices/{id}/trust", post(trust))
        .route("/api/v1/devices/{id}/block", post(block))
        .route("/api/v1/devices/{id}/unblock", post(unblock))
        .route("/api/v1/devices/{id}/pause", post(pause))
        .route(
            "/api/v1/devices/{id}/bandwidth",
            post(limit).delete(clear_limit),
        )
        .route("/api/v1/access-rules", get(access_rules))
        .route("/api/v1/bandwidth-rules", get(bandwidth_rules))
        .route("/api/v1/monitoring/overview", get(monitoring_overview))
        .route("/api/v1/monitoring/history", get(monitoring_history))
        .route("/api/v1/events", get(events))
        .route("/api/v1/audit", get(audit))
        .route("/api/v1/gateways", get(gateways).post(create_gateway))
        .route(
            "/api/v1/gateways/{id}",
            put(update_gateway).delete(delete_gateway),
        )
        .route("/api/v1/gateways/{id}/test", post(test_gateway_handler))
        .route(
            "/api/v1/gateways/{id}/activate",
            post(activate_gateway_handler),
        )
        .route(
            "/api/v1/gateways/{id}/clients",
            get(gateway_clients_handler),
        )
        .route("/api/v1/gateway/status", get(gateway_status))
        .route("/api/v1/settings", get(get_settings).put(put_settings))
        .route("/api/v1/users", get(list_users).post(create_user))
        .layer(axum::middleware::from_fn(add_remote_addr))
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("x-content-type-options"),
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("x-frame-options"),
            HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("referrer-policy"),
            HeaderValue::from_static("no-referrer"),
        ))
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .layer(axum::extract::DefaultBodyLimit::max(1024 * 1024))
        .with_state(state)
}

async fn add_remote_addr(
    mut request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let addr = request
        .extensions()
        .get::<axum::extract::ConnectInfo<SocketAddr>>()
        .map(|info| info.0.to_string())
        .unwrap_or_else(|| "local".to_string());
    request.extensions_mut().insert(RemoteAddr(addr));
    next.run(request).await
}

fn actor(auth: &AuthUser) -> &str {
    &auth.user.username
}

fn remote_string(remote: &RemoteAddr) -> Option<&str> {
    Some(remote.0.as_str())
}

async fn health(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    Json(json!({
        "status": "ok",
        "product": netcontrol_core::PRODUCT_NAME,
        "version": netcontrol_core::VERSION,
        "uptime_seconds": state.started_at.elapsed().as_secs()
    }))
}

async fn openapi() -> impl IntoResponse {
    const SPEC: &str = include_str!("../../../docs/openapi.json");
    match serde_json::from_str::<Value>(SPEC) {
        Ok(value) => Json(value).into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "OpenAPI specification is invalid",
        )
            .into_response(),
    }
}

async fn login(
    State(state): State<Arc<AppState>>,
    Extension(remote): Extension<RemoteAddr>,
    Json(body): Json<LoginRequest>,
) -> Result<Json<AuthSession>, ApiError> {
    if body.username.trim().is_empty() || body.password.is_empty() {
        return Err(ApiError::bad_request("username and password are required"));
    }
    let ip = remote.0.parse::<SocketAddr>().ok().map(|addr| addr.ip());
    let session = auth::login(&state, body.username.trim(), &body.password, ip, None).await?;
    Ok(Json(session))
}

async fn logout(
    State(state): State<Arc<AppState>>,
    auth: AuthUser,
) -> Result<StatusCode, ApiError> {
    auth::logout(&state, &auth)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn me(auth: AuthUser) -> Json<UserSummary> {
    Json(auth.user.into())
}

async fn change_password(
    State(state): State<Arc<AppState>>,
    Extension(remote): Extension<RemoteAddr>,
    auth: AuthUser,
    Json(body): Json<ChangePasswordRequest>,
) -> Result<StatusCode, ApiError> {
    if body.new_password == body.current_password {
        return Err(ApiError::bad_request("new password must be different"));
    }
    let password = body.current_password.clone();
    let hash = auth.user.password_hash.clone();
    let valid = tokio::task::spawn_blocking(move || security::verify_password(&password, &hash))
        .await
        .unwrap_or(false);
    if !valid {
        state
            .db
            .audit(
                actor(&auth),
                "change_password",
                Some(&auth.user.id),
                "failed",
                Some("current password incorrect"),
                Some(&remote.0),
            )
            .ok();
        return Err(ApiError::bad_request("current password is incorrect"));
    }
    let new_password = body.new_password.clone();
    let new_hash = tokio::task::spawn_blocking(move || security::hash_password(&new_password))
        .await
        .map_err(|_| ApiError::internal("password hashing failed"))??;
    state.db.update_password(&auth.user.id, &new_hash)?;
    state.db.revoke_user_sessions(&auth.user.id)?;
    state.db.audit(
        actor(&auth),
        "change_password",
        Some(&auth.user.id),
        "success",
        Some("all sessions revoked"),
        Some(&remote.0),
    )?;
    Ok(StatusCode::NO_CONTENT)
}

async fn system_status(auth: AuthUser, State(state): State<Arc<AppState>>) -> Json<SystemStatus> {
    let _ = auth;
    Json(state.status())
}

async fn dashboard(
    _auth: AuthUser,
    State(state): State<Arc<AppState>>,
) -> Result<Json<DashboardSummary>, ApiError> {
    Ok(Json(orchestration::dashboard_summary(&state).await?))
}

async fn interfaces(_auth: AuthUser) -> Result<Json<Vec<NetworkInterface>>, ApiError> {
    let list = tokio::task::spawn_blocking(InterfaceManager::list)
        .await
        .map_err(|_| ApiError::internal("interface enumeration failed"))??;
    Ok(Json(list))
}

async fn networks(
    _auth: AuthUser,
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<NetworkInfo>>, ApiError> {
    Ok(Json(state.db.list_networks()?))
}

async fn scan(
    auth: AuthUser,
    State(state): State<Arc<AppState>>,
    Extension(remote): Extension<RemoteAddr>,
    Json(body): Json<ScanRequest>,
) -> Result<Json<ScanResponse>, ApiError> {
    auth.admin()?;
    if !body.confirm {
        return Err(ApiError::bad_request(
            "confirm must be true: scanning must be explicitly authorized",
        ));
    }
    let methods = if body.methods.is_empty() {
        Vec::new()
    } else {
        body.methods
            .iter()
            .map(|m| m.parse::<ScanMethod>())
            .collect::<CoreResult<Vec<_>>>()?
    };
    let opts = ScanOptions {
        interface: body.interface,
        methods,
        nmap: body.nmap,
        ports: body.ports,
        timeout_ms: body.timeout_ms.unwrap_or(1200),
        max_hosts: body.max_hosts.unwrap_or(0),
        mdns: body.mdns.unwrap_or(true),
        allow_public: body.allow_public,
        confirmed: true,
    };
    let outcome = run_scan(&state, opts, actor(&auth), remote_string(&remote)).await?;
    state
        .db
        .audit(
            actor(&auth),
            "scan_completed",
            None,
            "success",
            Some(&format!("{} hosts", outcome.report.hosts.len())),
            remote_string(&remote),
        )
        .ok();
    Ok(Json(ScanResponse {
        report: outcome.report,
        devices: outcome.devices,
        new_devices: outcome.new_devices,
    }))
}

async fn scans(
    _auth: AuthUser,
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<ScanSession>>, ApiError> {
    Ok(Json(state.db.list_scans(50)?))
}

async fn devices(
    _auth: AuthUser,
    State(state): State<Arc<AppState>>,
    Query(query): Query<DeviceQuery>,
) -> Result<Json<Paged<Device>>, ApiError> {
    let category = match query.category.as_deref().filter(|c| !c.is_empty()) {
        Some(category) => Some(category.parse::<DeviceCategory>().map_err(ApiError::from)?),
        None => None,
    };
    let filter = DeviceFilter {
        query: query.query,
        online: query.online,
        blocked: query.blocked,
        trusted: query.trusted,
        category,
        interface: query.interface,
        sort: query.sort,
        descending: query.order.as_deref() == Some("desc"),
        limit: query.limit.unwrap_or(100).clamp(1, 500),
        offset: query.offset.unwrap_or(0),
    };
    Ok(Json(state.db.list_devices(&filter)?))
}

async fn device_detail(
    _auth: AuthUser,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<DeviceDetail>, ApiError> {
    let device = state
        .db
        .get_device(&id)?
        .ok_or_else(|| ApiError::not_found(format!("device {id}")))?;
    let history = state.db.list_history(&id, 200)?;
    let traffic = state.db.latest_device_traffic(&id)?;
    let access_rules = state
        .db
        .list_access_rules(false, 500)?
        .into_iter()
        .filter(|r| r.device_id.as_deref() == Some(id.as_str()))
        .collect();
    let bandwidth_rules = state
        .db
        .list_bandwidth_rules(false, 500)?
        .into_iter()
        .filter(|r| r.device_id.as_deref() == Some(id.as_str()))
        .collect();
    Ok(Json(DeviceDetail {
        device,
        history,
        traffic,
        access_rules,
        bandwidth_rules,
    }))
}

async fn update_device(
    auth: AuthUser,
    State(state): State<Arc<AppState>>,
    Extension(remote): Extension<RemoteAddr>,
    Path(id): Path<String>,
    Json(body): Json<DevicePatch>,
) -> Result<Json<Device>, ApiError> {
    auth.admin()?;
    if let Some(name) = &body.custom_name {
        if name.chars().count() > 80 {
            return Err(ApiError::bad_request("device name is too long"));
        }
    }
    let device = patch_device(&state, &id, &body, actor(&auth), remote_string(&remote)).await?;
    Ok(Json(device))
}

async fn trust(
    auth: AuthUser,
    State(state): State<Arc<AppState>>,
    Extension(remote): Extension<RemoteAddr>,
    Path(id): Path<String>,
    Json(body): Json<TrustRequest>,
) -> Result<Json<Device>, ApiError> {
    auth.admin()?;
    let device = trust_device(
        &state,
        &id,
        body.trusted,
        actor(&auth),
        remote_string(&remote),
    )
    .await?;
    Ok(Json(device))
}

async fn block(
    auth: AuthUser,
    State(state): State<Arc<AppState>>,
    Extension(remote): Extension<RemoteAddr>,
    Path(id): Path<String>,
    Json(body): Json<BlockRequest>,
) -> Result<Json<ActionResultResponse>, ApiError> {
    auth.admin()?;
    let outcome = block_device(
        &state,
        &id,
        AccessAction::Block,
        true,
        body.until.as_deref(),
        body.duration_seconds,
        body.reason.as_deref(),
        body.confirm,
        actor(&auth),
        remote_string(&remote),
    )
    .await?;
    Ok(Json(ActionResultResponse {
        result: outcome.result,
        device: outcome.device,
    }))
}

async fn pause(
    auth: AuthUser,
    State(state): State<Arc<AppState>>,
    Extension(remote): Extension<RemoteAddr>,
    Path(id): Path<String>,
    Json(body): Json<BlockRequest>,
) -> Result<Json<ActionResultResponse>, ApiError> {
    auth.admin()?;
    if body.duration_seconds.is_none() && body.until.is_none() {
        return Err(ApiError::bad_request(
            "pause requires duration_seconds or until",
        ));
    }
    let outcome = block_device(
        &state,
        &id,
        AccessAction::Pause,
        true,
        body.until.as_deref(),
        body.duration_seconds,
        body.reason.as_deref(),
        body.confirm,
        actor(&auth),
        remote_string(&remote),
    )
    .await?;
    Ok(Json(ActionResultResponse {
        result: outcome.result,
        device: outcome.device,
    }))
}

async fn unblock(
    auth: AuthUser,
    State(state): State<Arc<AppState>>,
    Extension(remote): Extension<RemoteAddr>,
    Path(id): Path<String>,
    Json(body): Json<UnblockRequest>,
) -> Result<Json<ActionResultResponse>, ApiError> {
    auth.admin()?;
    let outcome = block_device(
        &state,
        &id,
        AccessAction::Allow,
        false,
        None,
        None,
        None,
        body.confirm,
        actor(&auth),
        remote_string(&remote),
    )
    .await?;
    Ok(Json(ActionResultResponse {
        result: outcome.result,
        device: outcome.device,
    }))
}

async fn limit(
    auth: AuthUser,
    State(state): State<Arc<AppState>>,
    Extension(remote): Extension<RemoteAddr>,
    Path(id): Path<String>,
    Json(body): Json<BandwidthRequest>,
) -> Result<Json<ActionResultResponse>, ApiError> {
    auth.admin()?;
    let outcome = set_bandwidth(
        &state,
        &id,
        body.download_kbps,
        body.upload_kbps,
        body.priority,
        body.expires_at.as_deref(),
        body.confirm,
        actor(&auth),
        remote_string(&remote),
    )
    .await?;
    Ok(Json(ActionResultResponse {
        result: outcome.result,
        device: outcome.device,
    }))
}

async fn clear_limit(
    auth: AuthUser,
    State(state): State<Arc<AppState>>,
    Extension(remote): Extension<RemoteAddr>,
    Path(id): Path<String>,
    Json(body): Json<UnblockRequest>,
) -> Result<Json<ActionResultResponse>, ApiError> {
    auth.admin()?;
    let outcome = clear_bandwidth(
        &state,
        &id,
        body.confirm,
        actor(&auth),
        remote_string(&remote),
    )
    .await?;
    Ok(Json(ActionResultResponse {
        result: outcome.result,
        device: outcome.device,
    }))
}

async fn access_rules(
    _auth: AuthUser,
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<AccessRule>>, ApiError> {
    Ok(Json(state.db.list_access_rules(false, 500)?))
}

async fn bandwidth_rules(
    _auth: AuthUser,
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<BandwidthRule>>, ApiError> {
    Ok(Json(state.db.list_bandwidth_rules(false, 500)?))
}

async fn monitoring_overview(
    _auth: AuthUser,
    State(state): State<Arc<AppState>>,
) -> Json<TrafficOverview> {
    Json(
        traffic_overview(&state)
            .await
            .unwrap_or_else(|| unavailable_overview(None)),
    )
}

async fn monitoring_history(
    _auth: AuthUser,
    State(state): State<Arc<AppState>>,
    Query(query): Query<HistoryQuery>,
) -> Result<Json<Vec<MonitoringSample>>, ApiError> {
    let interface = query.interface;
    Ok(Json(state.db.monitoring_history(
        interface.as_deref(),
        query.minutes.unwrap_or(60).clamp(1, 10080),
        query.limit.unwrap_or(1000).clamp(1, 5000),
    )?))
}

async fn events(
    State(state): State<Arc<AppState>>,
    Query(query): Query<EventQuery>,
) -> Result<
    Sse<impl futures::Stream<Item = std::result::Result<Event, std::convert::Infallible>>>,
    ApiError,
> {
    let token = query.token.ok_or_else(ApiError::unauthorized)?;
    let digest = security::token_digest(&token);
    state
        .db
        .validate_session(&digest)?
        .ok_or_else(ApiError::unauthorized)?;
    let receiver = state.events.subscribe();
    let stream = BroadcastStream::new(receiver).filter_map(|item| async move {
        let event = item.ok()?;
        let json = serde_json::to_string(&event).ok()?;
        Some(Ok(Event::default().event("netcontrol").data(json)))
    });
    Ok(Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(std::time::Duration::from_secs(20))
            .text("keep-alive"),
    ))
}

async fn audit(
    auth: AuthUser,
    State(state): State<Arc<AppState>>,
    Query(query): Query<PageQuery>,
) -> Result<Json<Vec<AuditLog>>, ApiError> {
    auth.admin()?;
    Ok(Json(state.db.list_audit(
        query.limit.unwrap_or(100).clamp(1, 1000),
        query.offset.unwrap_or(0),
    )?))
}

async fn gateways(
    _auth: AuthUser,
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<GatewayView>>, ApiError> {
    let active = state.active_gateway_id.read().await.clone();
    let list = state.db.list_gateways()?;
    let mut out = Vec::new();
    for config in list {
        let has_secret = state.db.gateway_secret_encrypted(&config.id)?.is_some();
        out.push(GatewayView {
            active: active.as_deref() == Some(config.id.as_str()),
            has_secret,
            capabilities: netcontrol_core::models::GatewayCapabilities::default(),
            config,
        });
    }
    Ok(Json(out))
}

fn validate_gateway_input(body: &GatewayConfigInput) -> Result<(), ApiError> {
    if body.name.trim().is_empty() || body.name.len() > 80 {
        return Err(ApiError::bad_request(
            "gateway name is required (max 80 characters)",
        ));
    }
    netcontrol_gateway::validate_host(&body.host).map_err(ApiError::from)?;
    if let Some(port) = body.port {
        if port == 0 {
            return Err(ApiError::bad_request("port must be greater than zero"));
        }
    }
    if netcontrol_gateway::require_secret(body.kind)
        && body.secret.as_deref().unwrap_or("").is_empty()
    {
        return Err(ApiError::bad_request(format!(
            "{} requires an API password/secret",
            body.kind
        )));
    }
    Ok(())
}

async fn create_gateway(
    auth: AuthUser,
    State(state): State<Arc<AppState>>,
    Extension(remote): Extension<RemoteAddr>,
    Json(body): Json<GatewayConfigInput>,
) -> Result<Json<GatewayView>, ApiError> {
    auth.admin()?;
    validate_gateway_input(&body)?;
    let sealed = match body.secret.as_deref().filter(|s| !s.is_empty()) {
        Some(secret) => Some(state.key.encrypt(secret)?),
        None => None,
    };
    let config = state.db.create_gateway(&body, sealed.as_deref())?;
    let is_first = state.db.list_gateways()?.len() == 1;
    if is_first {
        state.db.set_setting("active_gateway_id", &config.id)?;
        *state.active_gateway_id.write().await = Some(config.id.clone());
    }
    state.db.audit(
        actor(&auth),
        "create_gateway",
        Some(&config.id),
        "success",
        Some(&format!("{} ({})", config.name, config.kind)),
        remote_string(&remote),
    )?;
    state.emit(ServerEvent::Notification {
        notification: crate::events::notification(
            "info",
            "Gateway added",
            format!("{} is ready to be tested", config.name),
            None,
        ),
    });
    Ok(Json(GatewayView {
        active: is_first,
        has_secret: sealed.is_some(),
        capabilities: Default::default(),
        config,
    }))
}

async fn update_gateway(
    auth: AuthUser,
    State(state): State<Arc<AppState>>,
    Extension(remote): Extension<RemoteAddr>,
    Path(id): Path<String>,
    Json(body): Json<GatewayConfigInput>,
) -> Result<Json<GatewayView>, ApiError> {
    auth.admin()?;
    validate_gateway_input(&body)?;
    let sealed = match body.secret.as_deref().filter(|s| !s.is_empty()) {
        Some(secret) => Some(state.key.encrypt(secret)?),
        None => None,
    };
    let config = state.db.update_gateway(&id, &body, sealed.as_deref())?;
    *state.gateway_cache.write().await = None;
    state.db.audit(
        actor(&auth),
        "update_gateway",
        Some(&id),
        "success",
        Some(&config.name),
        remote_string(&remote),
    )?;
    let active = state.active_gateway_id.read().await.as_deref() == Some(id.as_str());
    let has_secret = state.db.gateway_secret_encrypted(&id)?.is_some();
    Ok(Json(GatewayView {
        active,
        has_secret,
        capabilities: Default::default(),
        config,
    }))
}

async fn delete_gateway(
    auth: AuthUser,
    State(state): State<Arc<AppState>>,
    Extension(remote): Extension<RemoteAddr>,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    auth.admin()?;
    state.db.delete_gateway(&id)?;
    if state.active_gateway_id.read().await.as_deref() == Some(id.as_str()) {
        let next = state
            .db
            .list_gateways()?
            .into_iter()
            .find(|g| g.enabled)
            .map(|g| g.id);
        match next {
            Some(next_id) => {
                state.db.set_setting("active_gateway_id", &next_id)?;
                *state.active_gateway_id.write().await = Some(next_id);
            }
            None => {
                state.db.set_setting("active_gateway_id", "")?;
                *state.active_gateway_id.write().await = None;
            }
        }
        *state.gateway_cache.write().await = None;
    }
    state.db.audit(
        actor(&auth),
        "delete_gateway",
        Some(&id),
        "success",
        None,
        remote_string(&remote),
    )?;
    Ok(StatusCode::NO_CONTENT)
}

async fn test_gateway_handler(
    auth: AuthUser,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<GatewayProbe>, ApiError> {
    auth.admin()?;
    Ok(Json(test_gateway(&state, &id).await?))
}

async fn activate_gateway_handler(
    auth: AuthUser,
    State(state): State<Arc<AppState>>,
    Extension(remote): Extension<RemoteAddr>,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    auth.admin()?;
    set_active_gateway(&state, &id).await?;
    state.db.audit(
        actor(&auth),
        "activate_gateway",
        Some(&id),
        "success",
        None,
        remote_string(&remote),
    )?;
    Ok(StatusCode::NO_CONTENT)
}

async fn gateway_clients_handler(
    _auth: AuthUser,
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<GatewayClient>>, ApiError> {
    Ok(Json(orchestration::gateway_clients(&state).await?))
}

async fn gateway_status(
    _auth: AuthUser,
    State(state): State<Arc<AppState>>,
) -> Result<Json<Option<GatewayProbe>>, ApiError> {
    Ok(Json(probe_active(&state, true).await))
}

async fn get_settings(_auth: AuthUser, State(state): State<Arc<AppState>>) -> Json<AppSettings> {
    let settings = state.settings.read().await.clone();
    Json(settings)
}

fn validate_settings(settings: &AppSettings) -> Result<(), ApiError> {
    if settings.scan_interval_seconds < 15 || settings.scan_interval_seconds > 86_400 {
        return Err(ApiError::bad_request(
            "scan_interval_seconds must be between 15 and 86400",
        ));
    }
    if settings.max_hosts == 0 || settings.max_hosts > 65_534 {
        return Err(ApiError::bad_request(
            "max_hosts must be between 1 and 65534",
        ));
    }
    if settings.retention_days == 0 || settings.retention_days > 3650 {
        return Err(ApiError::bad_request(
            "retention_days must be between 1 and 3650",
        ));
    }
    if !matches!(settings.theme.as_str(), "dark" | "light" | "system") {
        return Err(ApiError::bad_request("theme must be dark, light or system"));
    }
    Ok(())
}

async fn put_settings(
    auth: AuthUser,
    State(state): State<Arc<AppState>>,
    Extension(remote): Extension<RemoteAddr>,
    Json(body): Json<AppSettings>,
) -> Result<Json<AppSettings>, ApiError> {
    auth.admin()?;
    validate_settings(&body)?;
    state.db.save_settings(&body)?;
    *state.settings.write().await = body.clone();
    state.db.audit(
        actor(&auth),
        "update_settings",
        None,
        "success",
        Some("application settings updated"),
        remote_string(&remote),
    )?;
    Ok(Json(body))
}

async fn list_users(
    auth: AuthUser,
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<UserSummary>>, ApiError> {
    auth.admin()?;
    Ok(Json(state.db.list_users()?))
}

async fn create_user(
    auth: AuthUser,
    State(state): State<Arc<AppState>>,
    Extension(remote): Extension<RemoteAddr>,
    Json(body): Json<CreateUserRequest>,
) -> Result<Json<UserSummary>, ApiError> {
    auth.admin()?;
    let role: Role = body
        .role
        .as_deref()
        .unwrap_or("viewer")
        .parse()
        .map_err(ApiError::from)?;
    let password = body.password.clone();
    let hash = tokio::task::spawn_blocking(move || security::hash_password(&password))
        .await
        .map_err(|_| ApiError::internal("password hashing failed"))??;
    let user = state.db.create_user(&body.username, &hash, role)?;
    state.db.audit(
        actor(&auth),
        "create_user",
        Some(&user.id),
        "success",
        Some(&format!(
            "username={} role={}",
            user.username,
            role.as_str()
        )),
        remote_string(&remote),
    )?;
    Ok(Json(user.into()))
}
