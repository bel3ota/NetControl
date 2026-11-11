use crate::events::ServerEvent;
use crate::orchestration::gateway_clients;
use crate::state::AppState;
use netcontrol_core::models::{MonitoringSample, TrafficOverview};
use netcontrol_core::util::{normalize_mac, now_ts};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

#[derive(Debug)]
struct Counter {
    rx_bytes: u64,
    tx_bytes: u64,
    at: Instant,
}

#[derive(Debug, Clone, Copy)]
pub struct RawSample {
    pub rx_bps: u64,
    pub tx_bps: u64,
    pub rx_total: u64,
    pub tx_total: u64,
}

pub struct Monitor {
    counters: Mutex<HashMap<String, Counter>>,
    latest: RwLock<Option<TrafficOverview>>,
    gateway_rates: Mutex<HashMap<String, (u64, u64, Instant)>>,
}

impl Monitor {
    pub fn new() -> Self {
        Self {
            counters: Mutex::new(HashMap::new()),
            latest: RwLock::new(None),
            gateway_rates: Mutex::new(HashMap::new()),
        }
    }

    /// Sample real interface counters from /proc/net/dev.
    pub fn sample(&self, interface: &str) -> Option<RawSample> {
        let (rx_total, tx_total) = read_proc_net_dev(interface)?;
        let now = Instant::now();
        let mut counters = self.counters.lock().ok()?;
        let previous = counters.get(interface);
        let sample = match previous {
            Some(prev) if now.duration_since(prev.at) >= Duration::from_millis(200) => {
                let elapsed = now.duration_since(prev.at).as_secs_f64();
                let rx_delta = rx_total.saturating_sub(prev.rx_bytes);
                let tx_delta = tx_total.saturating_sub(prev.tx_bytes);
                RawSample {
                    rx_bps: (rx_delta as f64 * 8.0 / elapsed) as u64,
                    tx_bps: (tx_delta as f64 * 8.0 / elapsed) as u64,
                    rx_total,
                    tx_total,
                }
            }
            _ => RawSample {
                rx_bps: 0,
                tx_bps: 0,
                rx_total,
                tx_total,
            },
        };
        counters.insert(
            interface.to_string(),
            Counter {
                rx_bytes: rx_total,
                tx_bytes: tx_total,
                at: now,
            },
        );
        Some(sample)
    }

    pub async fn set_latest(&self, overview: TrafficOverview) {
        *self.latest.write().await = Some(overview);
    }

    pub async fn latest(&self) -> Option<TrafficOverview> {
        self.latest.read().await.clone()
    }

    pub fn compute_gateway_rate(
        &self,
        key: &str,
        rx: Option<u64>,
        tx: Option<u64>,
    ) -> Option<(u64, u64)> {
        let (rx, tx) = (rx?, tx?);
        let now = Instant::now();
        let mut rates = self.gateway_rates.lock().ok()?;
        let result = rates.get(key).and_then(|(prev_rx, prev_tx, at)| {
            let elapsed = now.duration_since(*at).as_secs_f64();
            if elapsed < 0.5 {
                return None;
            }
            Some((
                ((rx.saturating_sub(*prev_rx)) as f64 * 8.0 / elapsed) as u64,
                ((tx.saturating_sub(*prev_tx)) as f64 * 8.0 / elapsed) as u64,
            ))
        });
        rates.insert(key.to_string(), (rx, tx, now));
        result
    }
}

impl Default for Monitor {
    fn default() -> Self {
        Self::new()
    }
}

fn read_proc_net_dev(interface: &str) -> Option<(u64, u64)> {
    let raw = std::fs::read_to_string("/proc/net/dev").ok()?;
    for line in raw.lines().skip(2) {
        let (name, data) = line.split_once(':')?;
        if name.trim() != interface {
            continue;
        }
        let fields: Vec<&str> = data.split_whitespace().collect();
        if fields.len() < 9 {
            return None;
        }
        let rx: u64 = fields[0].parse().ok()?;
        let tx: u64 = fields[8].parse().ok()?;
        return Some((rx, tx));
    }
    None
}

pub async fn monitor_loop(state: Arc<AppState>) {
    let mut ticker = tokio::time::interval(Duration::from_secs(3));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut tick: u64 = 0;
    let mut interface: Option<String> = None;
    let mut gateway_enabled = false;
    loop {
        ticker.tick().await;
        tick = tick.wrapping_add(1);
        if tick % 20 == 1 {
            let settings = state.settings.read().await.clone();
            interface = match settings.preferred_interface {
                Some(preferred) => Some(preferred),
                None => match netcontrol_discovery::InterfaceManager::choose(None) {
                    Ok(iface) => Some(iface.name),
                    Err(_) => None,
                },
            };
            gateway_enabled = state
                .db
                .list_gateways()
                .map(|g| g.iter().any(|g| g.enabled))
                .unwrap_or(false);
        }
        let Some(iface) = interface.clone() else {
            continue;
        };
        let Some(raw) = state.monitor.sample(&iface) else {
            continue;
        };
        let now = now_ts();
        let sample = MonitoringSample {
            ts: now.clone(),
            interface: Some(iface.clone()),
            device_id: None,
            rx_bps: raw.rx_bps,
            tx_bps: raw.tx_bps,
            rx_bytes: Some(raw.rx_total),
            tx_bytes: Some(raw.tx_total),
            source: "measured".into(),
        };
        let db = state.db.clone();
        let write = sample.clone();
        if let Ok(Err(err)) =
            tokio::task::spawn_blocking(move || db.insert_monitoring(&write)).await
        {
            tracing::debug!(error = %err, "monitoring sample could not be stored");
            continue;
        }
        let per_device_supported = state
            .gateway_cache
            .read()
            .await
            .as_ref()
            .map(|(_, probe)| probe.capabilities.traffic_stats)
            .unwrap_or(false);
        let overview = TrafficOverview {
            interface: Some(iface.clone()),
            sampled_at: now,
            rx_bps: raw.rx_bps,
            tx_bps: raw.tx_bps,
            rx_total_bytes: raw.rx_total,
            tx_total_bytes: raw.tx_total,
            source: "measured".into(),
            per_device_supported,
            per_device_source: per_device_supported.then(|| "gateway".to_string()),
        };
        state.monitor.set_latest(overview.clone()).await;
        state.emit(ServerEvent::Monitoring { sample, overview });

        if gateway_enabled && tick % 5 == 0 {
            sample_gateway_traffic(&state).await;
        }
    }
}

async fn sample_gateway_traffic(state: &Arc<AppState>) {
    let clients = match gateway_clients(state).await {
        Ok(clients) => clients,
        Err(err) => {
            tracing::debug!(error = %err, "gateway traffic sampling failed");
            return;
        }
    };
    let now = now_ts();
    let mut samples = Vec::new();
    for client in clients {
        let key = client
            .mac
            .as_deref()
            .and_then(normalize_mac)
            .or_else(|| client.ip.clone());
        let Some(key) = key else { continue };
        let device = if let Some(mac) = client.mac.as_deref() {
            state.db.find_device_by_mac(mac).ok().flatten()
        } else {
            None
        }
        .or_else(|| {
            client
                .ip
                .as_deref()
                .and_then(|ip| state.db.find_device_by_ip(ip).ok().flatten())
        });
        let Some(device) = device else { continue };
        let (rx_bps, tx_bps) = if let (Some(rx), Some(tx)) = (client.rx_bps, client.tx_bps) {
            (Some(rx), Some(tx))
        } else {
            state
                .monitor
                .compute_gateway_rate(&key, client.rx_bytes, client.tx_bytes)
                .map(|(rx, tx)| (Some(rx), Some(tx)))
                .unwrap_or((None, None))
        };
        if rx_bps.is_none() && tx_bps.is_none() {
            continue;
        }
        samples.push(MonitoringSample {
            ts: now.clone(),
            interface: client.interface.clone(),
            device_id: Some(device.id),
            rx_bps: rx_bps.unwrap_or(0),
            tx_bps: tx_bps.unwrap_or(0),
            rx_bytes: client.rx_bytes,
            tx_bytes: client.tx_bytes,
            source: "gateway".into(),
        });
    }
    if !samples.is_empty() {
        let db = state.db.clone();
        let _ = tokio::task::spawn_blocking(move || db.insert_monitoring_batch(&samples)).await;
    }
}

pub async fn traffic_overview(state: &Arc<AppState>) -> Option<TrafficOverview> {
    if let Some(latest) = state.monitor.latest().await {
        return Some(latest);
    }
    let settings = state.settings.read().await.clone();
    let interface = match settings.preferred_interface {
        Some(value) => Some(value),
        None => netcontrol_discovery::InterfaceManager::choose(None)
            .ok()
            .map(|i| i.name),
    };
    let iface = interface.clone()?;
    let stored = state.db.latest_aggregate(&iface).ok().flatten()?;
    Some(TrafficOverview {
        interface,
        sampled_at: stored.ts,
        rx_bps: stored.rx_bps,
        tx_bps: stored.tx_bps,
        rx_total_bytes: stored.rx_bytes.unwrap_or(0),
        tx_total_bytes: stored.tx_bytes.unwrap_or(0),
        source: stored.source,
        per_device_supported: false,
        per_device_source: None,
    })
}

pub fn unavailable_overview(interface: Option<String>) -> TrafficOverview {
    TrafficOverview {
        interface,
        sampled_at: now_ts(),
        rx_bps: 0,
        tx_bps: 0,
        rx_total_bytes: 0,
        tx_total_bytes: 0,
        source: "unavailable".into(),
        per_device_supported: false,
        per_device_source: None,
    }
}
