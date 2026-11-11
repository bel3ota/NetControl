use crate::orchestration::{
    auto_clear_limit, auto_unblock, blocked_devices_due, limited_devices_due, run_scan,
};
use crate::state::AppState;
use netcontrol_core::models::ScanOptions;
use netcontrol_core::util::{now_ts, parse_ts};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Background housekeeping: temporary restriction expiry, configurable
/// automatic scanning and retention pruning.
pub async fn scheduler_loop(state: Arc<AppState>) {
    let mut ticker = tokio::time::interval(Duration::from_secs(15));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut last_prune = Instant::now() - Duration::from_secs(3600);
    loop {
        ticker.tick().await;
        expire_restrictions(&state).await;
        maybe_auto_scan(&state).await;
        if last_prune.elapsed() >= Duration::from_secs(3600) {
            let settings = state.settings.read().await.clone();
            let db = state.db.clone();
            let _ = tokio::task::spawn_blocking(move || db.prune_history(settings.retention_days))
                .await;
            let _ = state.db.prune_expired_sessions();
            last_prune = Instant::now();
        }
    }
}

async fn expire_restrictions(state: &Arc<AppState>) {
    let now = now_ts();
    let blocked = match blocked_devices_due(state, &now) {
        Ok(devices) => devices,
        Err(err) => {
            tracing::debug!(error = %err, "could not query expiring blocks");
            return;
        }
    };
    for device in blocked {
        match auto_unblock(state, &device).await {
            Ok(true) => {
                state
                    .db
                    .audit(
                        "system",
                        "expire_block",
                        Some(&device.id),
                        "success",
                        Some("temporary block expired and gateway rule removed"),
                        None,
                    )
                    .ok();
                tracing::info!(device = %device.display_name(), "temporary block expired");
            }
            Ok(false) => {
                tracing::warn!(device = %device.display_name(), "temporary block expired but gateway did not confirm removal; will retry");
            }
            Err(err) => {
                tracing::warn!(device = %device.display_name(), error = %err, "failed to remove expired block");
            }
        }
    }
    let limited = match limited_devices_due(state, &now) {
        Ok(devices) => devices,
        Err(err) => {
            tracing::debug!(error = %err, "could not query expiring limits");
            return;
        }
    };
    for device in limited {
        match auto_clear_limit(state, &device).await {
            Ok(true) => {
                state
                    .db
                    .audit(
                        "system",
                        "expire_limit",
                        Some(&device.id),
                        "success",
                        Some("temporary bandwidth limit expired"),
                        None,
                    )
                    .ok();
            }
            Ok(false) => {
                tracing::warn!(device = %device.display_name(), "temporary limit expired but gateway did not confirm removal");
            }
            Err(err) => {
                tracing::warn!(device = %device.display_name(), error = %err, "failed to remove expired limit");
            }
        }
    }
}

async fn maybe_auto_scan(state: &Arc<AppState>) {
    let settings = state.settings.read().await.clone();
    if !settings.auto_scan {
        return;
    }
    let interval = settings.scan_interval_seconds.max(15);
    let last = state.db.last_scan().ok().flatten();
    let due = match last {
        None => true,
        Some(session) => parse_ts(&session.started_at)
            .map(|started| (chrono::Utc::now() - started).num_seconds() >= interval as i64)
            .unwrap_or(true),
    };
    if !due {
        return;
    }
    let opts = ScanOptions {
        interface: settings.preferred_interface.clone(),
        methods: settings.default_scan_methods.clone(),
        nmap: settings.enable_nmap,
        ports: false,
        mdns: settings.enable_mdns,
        max_hosts: settings.max_hosts,
        confirmed: true,
        ..Default::default()
    };
    match run_scan(state, opts, "scheduler", None).await {
        Ok(outcome) => {
            tracing::info!(
                hosts = outcome.report.hosts.len(),
                new_devices = outcome.new_devices,
                "automatic scan complete"
            );
        }
        Err(err) => tracing::warn!(error = %err, "automatic scan failed"),
    }
}
