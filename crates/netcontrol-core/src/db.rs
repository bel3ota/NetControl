//! SQLite persistence with versioned migrations.
//!
//! A single connection guarded by a mutex is deliberate: every transaction is
//! short, SQLite is configured in WAL mode, and this keeps the desktop app, CLI
//! and service semantics identical without a connection-pool dependency.

use crate::config::Paths;
use crate::error::{Error, Result};
use crate::models::*;
use crate::util::{normalize_mac, now_ts, safe_hostname};
use rusqlite::types::Value;
use rusqlite::{params, params_from_iter, Connection, OptionalExtension, Row};
use std::path::Path;
use std::sync::Mutex;

const MIGRATIONS: &[(i64, &str)] = &[(1, include_str!("../migrations/0001_init.sql"))];

#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct DeviceCounts {
    pub total: u64,
    pub online: u64,
    pub offline: u64,
    pub blocked: u64,
    pub trusted: u64,
    pub unknown: u64,
}

pub struct UpsertOutcome {
    pub device: Device,
    pub is_new: bool,
    pub came_online: bool,
}

pub struct Db {
    conn: Mutex<Connection>,
    location: String,
}

impl Db {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path)?;
        Self::init(conn, path.display().to_string())
    }

    pub fn open_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        Self::init(conn, "sqlite::memory:".into())
    }

    fn init(conn: Connection, location: String) -> Result<Self> {
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        let db = Self {
            conn: Mutex::new(conn),
            location,
        };
        db.migrate()?;
        Ok(db)
    }

    pub fn location(&self) -> &str {
        &self.location
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Connection>> {
        self.conn
            .lock()
            .map_err(|_| Error::Database("database mutex poisoned".into()))
    }

    pub fn migrate(&self) -> Result<()> {
        let mut conn = self.lock()?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL
            );",
        )?;
        for (version, sql) in MIGRATIONS {
            let applied: Option<i64> = conn
                .query_row(
                    "SELECT version FROM schema_migrations WHERE version=?1",
                    params![version],
                    |row| row.get(0),
                )
                .optional()?;
            if applied.is_some() {
                continue;
            }
            let tx = conn.transaction()?;
            tx.execute_batch(sql)?;
            tx.execute(
                "INSERT INTO schema_migrations(version, applied_at) VALUES (?1, ?2)",
                params![version, now_ts()],
            )?;
            tx.commit()?;
            tracing::info!(version, "applied database migration");
        }
        Ok(())
    }

    pub fn health(&self) -> Result<()> {
        let conn = self.lock()?;
        conn.query_row("SELECT 1", [], |_| Ok(()))?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Networks and interfaces
    // ------------------------------------------------------------------

    pub fn upsert_network(
        &self,
        iface: &NetworkInterface,
        net: &NetworkInfo,
    ) -> Result<NetworkInfo> {
        let conn = self.lock()?;
        let now = now_ts();
        let id = net
            .id
            .clone()
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let dns = serde_json::to_string(&net.dns)?;
        conn.execute(
            "INSERT INTO networks (id, interface, kind, ssid, cidr, local_ip, gateway, dns, first_seen, last_seen)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?9)
             ON CONFLICT(interface, cidr) DO UPDATE SET
               kind=excluded.kind, ssid=excluded.ssid, local_ip=excluded.local_ip,
               gateway=excluded.gateway, dns=excluded.dns, last_seen=excluded.last_seen",
            params![
                id,
                iface.name,
                net.kind.as_str(),
                net.ssid,
                net.cidr,
                net.local_ip,
                net.gateway,
                dns,
                now
            ],
        )?;
        drop(conn);
        self.get_network(&iface.name, &net.cidr)?
            .ok_or_else(|| Error::Internal("network upsert failed".into()))
    }

    pub fn get_network(&self, interface: &str, cidr: &str) -> Result<Option<NetworkInfo>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare(
            "SELECT id, interface, kind, ssid, cidr, local_ip, gateway, dns, first_seen, last_seen
             FROM networks WHERE interface=?1 AND cidr=?2",
        )?;
        let row = stmt
            .query_row(params![interface, cidr], network_from_row)
            .optional()?;
        Ok(row)
    }

    pub fn list_networks(&self) -> Result<Vec<NetworkInfo>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare(
            "SELECT id, interface, kind, ssid, cidr, local_ip, gateway, dns, first_seen, last_seen
             FROM networks ORDER BY last_seen DESC",
        )?;
        let rows = stmt
            .query_map([], network_from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn record_interface(&self, iface: &NetworkInterface) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO network_interfaces(name, kind, mac, is_up, details, last_seen)
             VALUES (?1,?2,?3,?4,?5,?6)
             ON CONFLICT(name) DO UPDATE SET kind=excluded.kind, mac=excluded.mac,
               is_up=excluded.is_up, details=excluded.details, last_seen=excluded.last_seen",
            params![
                iface.name,
                iface.kind.as_str(),
                iface.mac,
                iface.is_up as i32,
                serde_json::to_string(iface)?,
                now_ts()
            ],
        )?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Devices
    // ------------------------------------------------------------------

    pub fn upsert_observation(
        &self,
        obs: &HostObservation,
        interface: Option<&str>,
        ssid: Option<&str>,
        scan_id: &str,
    ) -> Result<UpsertOutcome> {
        let normalized_mac = obs.mac.as_deref().and_then(normalize_mac);
        let hostname = obs.hostname.as_deref().and_then(safe_hostname);
        let vendor = obs
            .vendor
            .clone()
            .or_else(|| normalized_mac.as_deref().and_then(crate::oui::lookup));
        let mut conn = self.lock()?;
        let now = now_ts();

        let existing: Option<Device> = if let Some(mac) = &normalized_mac {
            query_device(&conn, "mac = ?1", params![mac])?
        } else if let Some(ip) = &obs.ip {
            query_device(
                &conn,
                "ip = ?1 AND (interface = ?2 OR interface IS NULL)",
                params![ip, interface],
            )?
        } else if let Some(ip6) = &obs.ipv6 {
            query_device(&conn, "ipv6 = ?1", params![ip6])?
        } else {
            None
        };

        if let Some(existing) = existing {
            let was_online = existing.online;
            let mut ports = existing.open_ports.clone();
            for p in &obs.open_ports {
                if !ports.contains(p) {
                    ports.push(*p);
                }
            }
            ports.sort_unstable();
            let mut services = existing.services.clone();
            for s in &obs.services {
                if !services.iter().any(|e| e.eq_ignore_ascii_case(s)) {
                    services.push(s.clone());
                }
            }
            let mut sources = existing.sources.clone();
            for s in &obs.sources {
                if !sources.iter().any(|e| e.eq_ignore_ascii_case(s)) {
                    sources.push(s.clone());
                }
            }
            let category = if existing.category_source == CategorySource::Manual
                || existing.category != DeviceCategory::Unknown
            {
                existing.category
            } else {
                obs.category
            };
            let ip = obs.ip.clone().or(existing.ip.clone());
            let ipv6 = obs.ipv6.clone().or(existing.ipv6.clone());
            let hostname = hostname.or(existing.hostname.clone());
            let vendor = vendor.or(existing.vendor.clone());
            let interface = interface.map(str::to_string).or(existing.interface.clone());
            let ssid = ssid.map(str::to_string).or(existing.ssid.clone());

            let tx = conn.transaction()?;
            tx.execute(
                "UPDATE devices SET mac=COALESCE(?2,mac), ip=?3, ipv6=?4, hostname=?5, vendor=?6,
                   category=?7, interface=?8, ssid=?9, online=1, last_seen=?10, last_scan_id=?11,
                   open_ports=?12, services=?13, sources=?14, updated_at=?10
                 WHERE id=?1",
                params![
                    existing.id,
                    normalized_mac,
                    ip,
                    ipv6,
                    hostname,
                    vendor,
                    category.as_str(),
                    interface,
                    ssid,
                    now,
                    scan_id,
                    serde_json::to_string(&ports)?,
                    serde_json::to_string(&services)?,
                    serde_json::to_string(&sources)?,
                ],
            )?;
            if existing.ip != ip {
                insert_history_tx(
                    &tx,
                    &existing.id,
                    &now,
                    "ip_changed",
                    Some(&format!(
                        "{} -> {}",
                        existing.ip.as_deref().unwrap_or("unknown"),
                        ip.as_deref().unwrap_or("unknown")
                    )),
                    Some(scan_id),
                )?;
            }
            if !was_online {
                insert_history_tx(
                    &tx,
                    &existing.id,
                    &now,
                    "online",
                    Some("device responded to a scan"),
                    Some(scan_id),
                )?;
            }
            tx.commit()?;
            drop(conn);
            let device = self
                .get_device(&existing.id)?
                .ok_or_else(|| Error::Internal("device disappeared after update".into()))?;
            Ok(UpsertOutcome {
                device,
                is_new: false,
                came_online: !was_online,
            })
        } else {
            let id = uuid::Uuid::new_v4().to_string();
            let tx = conn.transaction()?;
            tx.execute(
                "INSERT INTO devices (id, mac, ip, ipv6, hostname, vendor, category, category_source,
                   interface, ssid, online, first_seen, last_seen, last_scan_id, open_ports, services,
                   sources, created_at, updated_at)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,'auto',?8,?9,1,?10,?10,?11,?12,?13,?14,?10,?10)",
                params![
                    id,
                    normalized_mac,
                    obs.ip,
                    obs.ipv6,
                    hostname,
                    vendor,
                    obs.category.as_str(),
                    interface,
                    ssid,
                    now,
                    scan_id,
                    serde_json::to_string(&obs.open_ports)?,
                    serde_json::to_string(&obs.services)?,
                    serde_json::to_string(&obs.sources)?,
                ],
            )?;
            insert_history_tx(
                &tx,
                &id,
                &now,
                "discovered",
                obs.sources
                    .first()
                    .map(|s| format!("first seen via {s}"))
                    .as_deref(),
                Some(scan_id),
            )?;
            tx.commit()?;
            drop(conn);
            let device = self
                .get_device(&id)?
                .ok_or_else(|| Error::Internal("device disappeared after insert".into()))?;
            Ok(UpsertOutcome {
                device,
                is_new: true,
                came_online: true,
            })
        }
    }

    pub fn get_device(&self, id: &str) -> Result<Option<Device>> {
        let conn = self.lock()?;
        query_device(&conn, "id = ?1", params![id])
    }

    pub fn find_device_by_ip(&self, ip: &str) -> Result<Option<Device>> {
        let conn = self.lock()?;
        query_device(&conn, "ip = ?1", params![ip])
    }

    pub fn find_device_by_mac(&self, mac: &str) -> Result<Option<Device>> {
        let normalized = normalize_mac(mac)
            .ok_or_else(|| Error::Validation(format!("invalid MAC address: {mac}")))?;
        let conn = self.lock()?;
        query_device(&conn, "mac = ?1", params![normalized])
    }

    pub fn list_devices(&self, filter: &DeviceFilter) -> Result<Paged<Device>> {
        let conn = self.lock()?;
        let mut clauses = vec!["1=1".to_string()];
        let mut values: Vec<Value> = Vec::new();
        if let Some(q) = filter
            .query
            .as_deref()
            .map(str::trim)
            .filter(|q| !q.is_empty())
        {
            clauses.push(
                "(LOWER(COALESCE(custom_name,'')) LIKE ? OR LOWER(COALESCE(hostname,'')) LIKE ?
                  OR COALESCE(ip,'') LIKE ? OR LOWER(COALESCE(mac,'')) LIKE ?
                  OR LOWER(COALESCE(vendor,'')) LIKE ? OR LOWER(COALESCE(notes,'')) LIKE ?)"
                    .into(),
            );
            let needle = format!("%{}%", q.to_ascii_lowercase());
            for _ in 0..6 {
                values.push(Value::Text(needle.clone()));
            }
        }
        if let Some(online) = filter.online {
            clauses.push("online = ?".into());
            values.push(Value::Integer(online as i64));
        }
        if let Some(blocked) = filter.blocked {
            clauses.push("blocked = ?".into());
            values.push(Value::Integer(blocked as i64));
        }
        if let Some(trusted) = filter.trusted {
            clauses.push("is_trusted = ?".into());
            values.push(Value::Integer(trusted as i64));
        }
        if let Some(category) = filter.category {
            clauses.push("category = ?".into());
            values.push(Value::Text(category.as_str().into()));
        }
        if let Some(interface) = &filter.interface {
            clauses.push("interface = ?".into());
            values.push(Value::Text(interface.clone()));
        }
        let where_sql = clauses.join(" AND ");
        let total: i64 = conn.query_row(
            &format!("SELECT COUNT(*) FROM devices WHERE {where_sql}"),
            params_from_iter(values.iter()),
            |row| row.get(0),
        )?;

        let order = match filter.sort.as_deref().unwrap_or("name") {
            "ip" => "ip",
            "last_seen" => "last_seen",
            "first_seen" => "first_seen",
            "category" => "category",
            "vendor" => "vendor",
            "status" => "online",
            _ => "LOWER(COALESCE(custom_name, hostname, ip, mac, ''))",
        };
        let direction = if filter.descending { "DESC" } else { "ASC" };
        let limit = filter.limit.clamp(1, 500);
        let offset = filter.offset;
        values.push(Value::Integer(limit as i64));
        values.push(Value::Integer(offset as i64));
        let mut stmt = conn.prepare(&format!(
            "SELECT {} FROM devices WHERE {where_sql} ORDER BY {order} {direction} LIMIT ? OFFSET ?",
            DEVICE_COLUMNS
        ))?;
        let items = stmt
            .query_map(params_from_iter(values.iter()), row_to_device)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(Paged {
            items,
            total: total as u64,
            limit,
            offset,
        })
    }

    pub fn update_device(&self, id: &str, patch: &DevicePatch) -> Result<Device> {
        let mut conn = self.lock()?;
        let existing = query_device(&conn, "id = ?1", params![id])?
            .ok_or_else(|| Error::NotFound(format!("device {id}")))?;
        let custom_name = match &patch.custom_name {
            Some(v) if v.trim().is_empty() => None,
            Some(v) => Some(v.trim().chars().take(80).collect::<String>()),
            None => existing.custom_name.clone(),
        };
        let notes = match &patch.notes {
            Some(v) if v.trim().is_empty() => None,
            Some(v) => Some(v.trim().chars().take(1000).collect::<String>()),
            None => existing.notes.clone(),
        };
        let (category, category_source) = match patch.category {
            Some(cat) => (cat, CategorySource::Manual),
            None => (existing.category, existing.category_source),
        };
        let trusted = patch.is_trusted.unwrap_or(existing.is_trusted);
        let now = now_ts();
        let tx = conn.transaction()?;
        tx.execute(
            "UPDATE devices SET custom_name=?2, notes=?3, category=?4, category_source=?5,
               is_trusted=?6, updated_at=?7 WHERE id=?1",
            params![
                id,
                custom_name,
                notes,
                category.as_str(),
                category_source.as_str(),
                trusted as i32,
                now
            ],
        )?;
        if trusted {
            tx.execute(
                "INSERT INTO trusted_devices(device_id, added_at) VALUES (?1,?2)
                 ON CONFLICT(device_id) DO UPDATE SET added_at=excluded.added_at",
                params![id, now],
            )?;
        } else {
            tx.execute(
                "DELETE FROM trusted_devices WHERE device_id=?1",
                params![id],
            )?;
        }
        if patch.is_trusted == Some(true) && existing.is_trusted != true {
            insert_history_tx(
                &tx,
                id,
                &now,
                "trusted",
                Some("added to trusted devices"),
                None,
            )?;
        } else if patch.is_trusted == Some(false) && existing.is_trusted {
            insert_history_tx(
                &tx,
                id,
                &now,
                "untrusted",
                Some("removed from trusted devices"),
                None,
            )?;
        }
        tx.commit()?;
        drop(conn);
        self.get_device(id)?
            .ok_or_else(|| Error::Internal("device disappeared after patch".into()))
    }

    pub fn set_block_state(
        &self,
        id: &str,
        blocked: bool,
        until: Option<&str>,
        source: Option<&str>,
        state: EnforcementState,
        detail: Option<&str>,
    ) -> Result<Device> {
        let mut conn = self.lock()?;
        let existing = query_device(&conn, "id = ?1", params![id])?
            .ok_or_else(|| Error::NotFound(format!("device {id}")))?;
        let now = now_ts();
        let tx = conn.transaction()?;
        tx.execute(
            "UPDATE devices SET blocked=?2, blocked_until=?3, block_source=?4, enforcement=?5, updated_at=?6
             WHERE id=?1",
            params![
                id,
                blocked as i32,
                if blocked { until } else { None },
                if blocked { source } else { None },
                state.as_str(),
                now
            ],
        )?;
        let event = if blocked { "blocked" } else { "unblocked" };
        let detail = detail.map(str::to_string).unwrap_or_else(|| {
            if blocked {
                "access blocked".into()
            } else {
                "access restored".into()
            }
        });
        insert_history_tx(&tx, id, &now, event, Some(&detail), None)?;
        if existing.is_trusted && blocked {
            insert_history_tx(
                &tx,
                id,
                &now,
                "warning",
                Some("a trusted device was blocked by an explicit administrative action"),
                None,
            )?;
        }
        tx.commit()?;
        drop(conn);
        self.get_device(id)?
            .ok_or_else(|| Error::Internal("device disappeared after block".into()))
    }

    pub fn set_limit_state(
        &self,
        id: &str,
        download_kbps: Option<i64>,
        upload_kbps: Option<i64>,
        priority: Option<i32>,
        expires_at: Option<&str>,
        state: EnforcementState,
    ) -> Result<Device> {
        let conn = self.lock()?;
        conn.execute(
            "UPDATE devices SET limit_download_kbps=?2, limit_upload_kbps=?3, priority=?4,
               limit_expires_at=?5, enforcement=?6, updated_at=?7 WHERE id=?1",
            params![
                id,
                download_kbps,
                upload_kbps,
                priority,
                expires_at,
                state.as_str(),
                now_ts()
            ],
        )?;
        drop(conn);
        self.get_device(id)?
            .ok_or_else(|| Error::NotFound(format!("device {id}")))
    }

    /// Update only the enforcement marker. Used when an operation failed so we
    /// never set `blocked = true` on an unverified gateway action.
    pub fn set_enforcement(&self, id: &str, state: EnforcementState) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "UPDATE devices SET enforcement=?2, updated_at=?3 WHERE id=?1",
            params![id, state.as_str(), now_ts()],
        )?;
        Ok(())
    }

    pub fn mark_offline_except(
        &self,
        interface: &str,
        seen_ids: &[String],
        ts: &str,
    ) -> Result<u64> {
        let mut conn = self.lock()?;
        let mut sql = "SELECT id FROM devices WHERE online=1 AND interface=?1".to_string();
        if !seen_ids.is_empty() {
            let placeholders = (0..seen_ids.len())
                .map(|i| format!("?{}", i + 2))
                .collect::<Vec<_>>()
                .join(",");
            sql.push_str(&format!(" AND id NOT IN ({placeholders})"));
        }
        let mut values: Vec<Value> = vec![Value::Text(interface.to_string())];
        values.extend(seen_ids.iter().cloned().map(Value::Text));
        let tx = conn.transaction()?;
        let ids = {
            let mut stmt = tx.prepare(&sql)?;
            let rows = stmt
                .query_map(params_from_iter(values.iter()), |row| {
                    row.get::<_, String>(0)
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            rows
        };
        for id in &ids {
            tx.execute(
                "UPDATE devices SET online=0, enforcement=CASE WHEN blocked=1 THEN enforcement ELSE 'none' END,
                   updated_at=?2 WHERE id=?1",
                params![id, ts],
            )?;
            insert_history_tx(
                &tx,
                id,
                ts,
                "offline",
                Some("not present in the latest scan"),
                None,
            )?;
        }
        tx.commit()?;
        Ok(ids.len() as u64)
    }

    pub fn expire_temporary_access(&self, now: &str) -> Result<u64> {
        let mut conn = self.lock()?;
        let tx = conn.transaction()?;
        let ids: Vec<(String, String)> = {
            let mut stmt = tx.prepare(
                "SELECT id, COALESCE(block_source,'temporary') FROM devices
                 WHERE blocked=1 AND blocked_until IS NOT NULL AND blocked_until <= ?1",
            )?;
            let rows = stmt
                .query_map(params![now], |row| Ok((row.get(0)?, row.get(1)?)))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            rows
        };
        for (id, _) in &ids {
            tx.execute(
                "UPDATE devices SET blocked=0, blocked_until=NULL, block_source=NULL,
                   enforcement='expired', updated_at=?2 WHERE id=?1",
                params![id, now],
            )?;
            insert_history_tx(
                &tx,
                id,
                now,
                "expired",
                Some("temporary block expired; gateway rule must be reconciled"),
                None,
            )?;
        }
        tx.execute(
            "UPDATE devices SET limit_download_kbps=NULL, limit_upload_kbps=NULL,
               limit_expires_at=NULL, enforcement='expired', updated_at=?1
             WHERE limit_expires_at IS NOT NULL AND limit_expires_at <= ?1",
            params![now],
        )?;
        tx.commit()?;
        Ok(ids.len() as u64)
    }

    pub fn counts(&self) -> Result<DeviceCounts> {
        let conn = self.lock()?;
        let row = conn.query_row(
            "SELECT COUNT(*),
                COALESCE(SUM(CASE WHEN online=1 THEN 1 ELSE 0 END),0),
                COALESCE(SUM(CASE WHEN online=0 THEN 1 ELSE 0 END),0),
                COALESCE(SUM(CASE WHEN blocked=1 THEN 1 ELSE 0 END),0),
                COALESCE(SUM(CASE WHEN is_trusted=1 THEN 1 ELSE 0 END),0),
                COALESCE(SUM(CASE WHEN category='unknown' THEN 1 ELSE 0 END),0)
             FROM devices",
            [],
            |row| {
                Ok(DeviceCounts {
                    total: row.get::<_, i64>(0)? as u64,
                    online: row.get::<_, i64>(1)? as u64,
                    offline: row.get::<_, i64>(2)? as u64,
                    blocked: row.get::<_, i64>(3)? as u64,
                    trusted: row.get::<_, i64>(4)? as u64,
                    unknown: row.get::<_, i64>(5)? as u64,
                })
            },
        )?;
        Ok(row)
    }

    // ------------------------------------------------------------------
    // History & scans
    // ------------------------------------------------------------------

    pub fn add_history(
        &self,
        device_id: &str,
        event: &str,
        detail: Option<&str>,
        scan_id: Option<&str>,
    ) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO device_history(device_id, ts, event, detail, scan_id) VALUES (?1,?2,?3,?4,?5)",
            params![device_id, now_ts(), event, detail, scan_id],
        )?;
        Ok(())
    }

    pub fn list_history(&self, device_id: &str, limit: u32) -> Result<Vec<DeviceHistory>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare(
            "SELECT id, device_id, ts, event, detail, scan_id FROM device_history
             WHERE device_id=?1 ORDER BY ts DESC LIMIT ?2",
        )?;
        let rows = stmt
            .query_map(params![device_id, limit.clamp(1, 500)], |row| {
                Ok(DeviceHistory {
                    id: row.get(0)?,
                    device_id: row.get(1)?,
                    ts: row.get(2)?,
                    event: row.get(3)?,
                    detail: row.get(4)?,
                    scan_id: row.get(5)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn start_scan(
        &self,
        id: &str,
        interface: &str,
        cidr: &str,
        methods: &[ScanMethod],
        privileged: bool,
    ) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO scanning_sessions(id, interface, cidr, methods, started_at, status, privileged)
             VALUES (?1,?2,?3,?4,?5,'running',?6)",
            params![
                id,
                interface,
                cidr,
                serde_json::to_string(methods)?,
                now_ts(),
                privileged as i32
            ],
        )?;
        Ok(())
    }

    pub fn finish_scan(
        &self,
        id: &str,
        status: &str,
        hosts_found: u32,
        error: Option<&str>,
    ) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "UPDATE scanning_sessions SET finished_at=?2, status=?3, hosts_found=?4, error=?5 WHERE id=?1",
            params![id, now_ts(), status, hosts_found, error],
        )?;
        Ok(())
    }

    pub fn last_scan(&self) -> Result<Option<ScanSession>> {
        let conn = self.lock()?;
        let row = conn
            .query_row(
                "SELECT id, interface, cidr, methods, started_at, finished_at, status, hosts_found, error, privileged
                 FROM scanning_sessions ORDER BY started_at DESC LIMIT 1",
                [],
                scan_session_from_row,
            )
            .optional()?;
        Ok(row)
    }

    pub fn list_scans(&self, limit: u32) -> Result<Vec<ScanSession>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare(
            "SELECT id, interface, cidr, methods, started_at, finished_at, status, hosts_found, error, privileged
             FROM scanning_sessions ORDER BY started_at DESC LIMIT ?1",
        )?;
        let rows = stmt
            .query_map(params![limit.clamp(1, 200)], scan_session_from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    // ------------------------------------------------------------------
    // Access control and bandwidth rules
    // ------------------------------------------------------------------

    pub fn insert_access_rule(&self, rule: &AccessRule) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO access_rules(id, device_id, mac, ip, action, reason, gateway_config_id, state,
               created_by, created_at, expires_at, last_error)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
            params![
                rule.id,
                rule.device_id,
                rule.mac,
                rule.ip,
                rule.action.as_str(),
                rule.reason,
                rule.gateway_config_id,
                rule.state.as_str(),
                rule.created_by,
                rule.created_at,
                rule.expires_at,
                rule.last_error
            ],
        )?;
        Ok(())
    }

    pub fn update_access_rule_state(
        &self,
        id: &str,
        state: EnforcementState,
        error: Option<&str>,
    ) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "UPDATE access_rules SET state=?2, last_error=?3 WHERE id=?1",
            params![id, state.as_str(), error],
        )?;
        Ok(())
    }

    pub fn list_access_rules(&self, active_only: bool, limit: u32) -> Result<Vec<AccessRule>> {
        let conn = self.lock()?;
        let sql = if active_only {
            "SELECT id, device_id, mac, ip, action, reason, gateway_config_id, state, created_by,
                    created_at, expires_at, last_error
             FROM access_rules WHERE state IN ('pending','applied') ORDER BY created_at DESC LIMIT ?1"
        } else {
            "SELECT id, device_id, mac, ip, action, reason, gateway_config_id, state, created_by,
                    created_at, expires_at, last_error
             FROM access_rules ORDER BY created_at DESC LIMIT ?1"
        };
        let mut stmt = conn.prepare(sql)?;
        let rows = stmt
            .query_map(params![limit.clamp(1, 1000)], |row| {
                let action: String = row.get(4)?;
                let state: String = row.get(7)?;
                Ok(AccessRule {
                    id: row.get(0)?,
                    device_id: row.get(1)?,
                    mac: row.get(2)?,
                    ip: row.get(3)?,
                    action: match action.as_str() {
                        "block" => AccessAction::Block,
                        "pause" => AccessAction::Pause,
                        _ => AccessAction::Allow,
                    },
                    reason: row.get(5)?,
                    gateway_config_id: row.get(6)?,
                    state: parse_enforcement(&state),
                    created_by: row.get(8)?,
                    created_at: row.get(9)?,
                    expires_at: row.get(10)?,
                    last_error: row.get(11)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn insert_bandwidth_rule(&self, rule: &BandwidthRule) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO bandwidth_rules(id, device_id, mac, ip, download_kbps, upload_kbps, priority,
               gateway_config_id, state, created_at, expires_at, last_error)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
            params![
                rule.id,
                rule.device_id,
                rule.mac,
                rule.ip,
                rule.download_kbps,
                rule.upload_kbps,
                rule.priority,
                rule.gateway_config_id,
                rule.state.as_str(),
                rule.created_at,
                rule.expires_at,
                rule.last_error
            ],
        )?;
        Ok(())
    }

    pub fn update_bandwidth_rule_state(
        &self,
        id: &str,
        state: EnforcementState,
        error: Option<&str>,
    ) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "UPDATE bandwidth_rules SET state=?2, last_error=?3 WHERE id=?1",
            params![id, state.as_str(), error],
        )?;
        Ok(())
    }

    pub fn list_bandwidth_rules(
        &self,
        active_only: bool,
        limit: u32,
    ) -> Result<Vec<BandwidthRule>> {
        let conn = self.lock()?;
        let sql = if active_only {
            "SELECT id, device_id, mac, ip, download_kbps, upload_kbps, priority, gateway_config_id,
                    state, created_at, expires_at, last_error FROM bandwidth_rules
             WHERE state IN ('pending','applied') ORDER BY created_at DESC LIMIT ?1"
        } else {
            "SELECT id, device_id, mac, ip, download_kbps, upload_kbps, priority, gateway_config_id,
                    state, created_at, expires_at, last_error FROM bandwidth_rules
             ORDER BY created_at DESC LIMIT ?1"
        };
        let mut stmt = conn.prepare(sql)?;
        let rows = stmt
            .query_map(params![limit.clamp(1, 1000)], |row| {
                let state: String = row.get(8)?;
                Ok(BandwidthRule {
                    id: row.get(0)?,
                    device_id: row.get(1)?,
                    mac: row.get(2)?,
                    ip: row.get(3)?,
                    download_kbps: row.get(4)?,
                    upload_kbps: row.get(5)?,
                    priority: row.get(6)?,
                    gateway_config_id: row.get(7)?,
                    state: parse_enforcement(&state),
                    created_at: row.get(9)?,
                    expires_at: row.get(10)?,
                    last_error: row.get(11)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    // ------------------------------------------------------------------
    // Monitoring
    // ------------------------------------------------------------------

    pub fn insert_monitoring(&self, sample: &MonitoringSample) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO monitoring_records(ts, interface, device_id, rx_bps, tx_bps, rx_bytes, tx_bytes, source, gateway_config_id)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,NULL)",
            params![
                sample.ts,
                sample.interface,
                sample.device_id,
                sample.rx_bps as i64,
                sample.tx_bps as i64,
                sample.rx_bytes.map(|v| v as i64),
                sample.tx_bytes.map(|v| v as i64),
                sample.source
            ],
        )?;
        Ok(())
    }

    pub fn insert_monitoring_batch(&self, samples: &[MonitoringSample]) -> Result<()> {
        if samples.is_empty() {
            return Ok(());
        }
        let mut conn = self.lock()?;
        let tx = conn.transaction()?;
        for sample in samples {
            tx.execute(
                "INSERT INTO monitoring_records(ts, interface, device_id, rx_bps, tx_bps, rx_bytes, tx_bytes, source, gateway_config_id)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,NULL)",
                params![
                    sample.ts,
                    sample.interface,
                    sample.device_id,
                    sample.rx_bps as i64,
                    sample.tx_bps as i64,
                    sample.rx_bytes.map(|v| v as i64),
                    sample.tx_bytes.map(|v| v as i64),
                    sample.source
                ],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn latest_aggregate(&self, interface: &str) -> Result<Option<MonitoringSample>> {
        let conn = self.lock()?;
        let row = conn
            .query_row(
                "SELECT ts, interface, NULL, rx_bps, tx_bps, rx_bytes, tx_bytes, source
             FROM monitoring_records WHERE interface=?1 AND device_id IS NULL
             ORDER BY ts DESC LIMIT 1",
                params![interface],
                |row| {
                    Ok(MonitoringSample {
                        ts: row.get(0)?,
                        interface: row.get(1)?,
                        device_id: row.get(2)?,
                        rx_bps: row.get::<_, i64>(3)? as u64,
                        tx_bps: row.get::<_, i64>(4)? as u64,
                        rx_bytes: row.get::<_, Option<i64>>(5)?.map(|v| v as u64),
                        tx_bytes: row.get::<_, Option<i64>>(6)?.map(|v| v as u64),
                        source: row.get(7)?,
                    })
                },
            )
            .optional()?;
        Ok(row)
    }

    pub fn monitoring_history(
        &self,
        interface: Option<&str>,
        minutes: u32,
        limit: u32,
    ) -> Result<Vec<MonitoringSample>> {
        let conn = self.lock()?;
        let cutoff = chrono::Utc::now() - chrono::Duration::minutes(minutes as i64);
        let cutoff = cutoff.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let sql = if interface.is_some() {
            "SELECT substr(ts,1,16)||':00Z' AS bucket, interface, NULL,
                    CAST(AVG(rx_bps) AS INTEGER), CAST(AVG(tx_bps) AS INTEGER),
                    MAX(rx_bytes), MAX(tx_bytes), source
             FROM monitoring_records
             WHERE device_id IS NULL AND interface=?1 AND ts>=?2
             GROUP BY bucket, interface ORDER BY bucket ASC LIMIT ?3"
        } else {
            "SELECT substr(ts,1,16)||':00Z' AS bucket, interface, NULL,
                    CAST(AVG(rx_bps) AS INTEGER), CAST(AVG(tx_bps) AS INTEGER),
                    MAX(rx_bytes), MAX(tx_bytes), source
             FROM monitoring_records
             WHERE device_id IS NULL AND ts>=?1
             GROUP BY bucket, interface ORDER BY bucket ASC LIMIT ?2"
        };
        let map_row = |row: &Row<'_>| -> rusqlite::Result<MonitoringSample> {
            Ok(MonitoringSample {
                ts: row.get(0)?,
                interface: row.get(1)?,
                device_id: row.get(2)?,
                rx_bps: row.get::<_, i64>(3)? as u64,
                tx_bps: row.get::<_, i64>(4)? as u64,
                rx_bytes: row.get::<_, Option<i64>>(5)?.map(|v| v as u64),
                tx_bytes: row.get::<_, Option<i64>>(6)?.map(|v| v as u64),
                source: row.get(7)?,
            })
        };
        let mut stmt = conn.prepare(sql)?;
        let rows = if let Some(interface) = interface {
            stmt.query_map(params![interface, cutoff, limit.clamp(1, 5000)], map_row)?
                .collect::<rusqlite::Result<Vec<_>>>()?
        } else {
            stmt.query_map(params![cutoff, limit.clamp(1, 5000)], map_row)?
                .collect::<rusqlite::Result<Vec<_>>>()?
        };
        Ok(rows)
    }

    pub fn latest_device_traffic(&self, device_id: &str) -> Result<Option<MonitoringSample>> {
        let conn = self.lock()?;
        let row = conn
            .query_row(
                "SELECT ts, interface, device_id, rx_bps, tx_bps, rx_bytes, tx_bytes, source
             FROM monitoring_records WHERE device_id=?1 ORDER BY ts DESC LIMIT 1",
                params![device_id],
                |row| {
                    Ok(MonitoringSample {
                        ts: row.get(0)?,
                        interface: row.get(1)?,
                        device_id: row.get(2)?,
                        rx_bps: row.get::<_, i64>(3)? as u64,
                        tx_bps: row.get::<_, i64>(4)? as u64,
                        rx_bytes: row.get::<_, Option<i64>>(5)?.map(|v| v as u64),
                        tx_bytes: row.get::<_, Option<i64>>(6)?.map(|v| v as u64),
                        source: row.get(7)?,
                    })
                },
            )
            .optional()?;
        Ok(row)
    }

    // ------------------------------------------------------------------
    // Gateways
    // ------------------------------------------------------------------

    pub fn create_gateway(
        &self,
        input: &GatewayConfigInput,
        secret_encrypted: Option<&str>,
    ) -> Result<GatewayConfig> {
        let id = uuid::Uuid::new_v4().to_string();
        let now = now_ts();
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO router_configs(id, name, kind, host, port, username, secret_enc, site,
               interface_hint, tls, tls_insecure, enabled, created_at, updated_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?13)",
            params![
                id,
                input.name.trim(),
                input.kind.as_str(),
                input.host.trim(),
                input.port.unwrap_or_else(|| input.kind.default_port()) as i64,
                input.username,
                secret_encrypted,
                input.site,
                input.interface_hint,
                input.tls.unwrap_or(true) as i32,
                input.tls_insecure.unwrap_or(false) as i32,
                input.enabled.unwrap_or(true) as i32,
                now
            ],
        )?;
        drop(conn);
        self.get_gateway(&id)?
            .ok_or_else(|| Error::Internal("gateway insert failed".into()))
    }

    pub fn update_gateway(
        &self,
        id: &str,
        input: &GatewayConfigInput,
        secret_encrypted: Option<&str>,
    ) -> Result<GatewayConfig> {
        let existing = self
            .get_gateway(id)?
            .ok_or_else(|| Error::NotFound(format!("gateway {id}")))?;
        let conn = self.lock()?;
        conn.execute(
            "UPDATE router_configs SET name=?2, kind=?3, host=?4, port=?5, username=?6,
               secret_enc=COALESCE(?7,secret_enc), site=?8, interface_hint=?9, tls=?10,
               tls_insecure=?11, enabled=?12, updated_at=?13 WHERE id=?1",
            params![
                id,
                input.name.trim(),
                input.kind.as_str(),
                input.host.trim(),
                input.port.unwrap_or_else(|| input.kind.default_port()) as i64,
                input.username,
                secret_encrypted,
                input.site,
                input.interface_hint,
                input.tls.unwrap_or(existing.tls) as i32,
                input.tls_insecure.unwrap_or(existing.tls_insecure) as i32,
                input.enabled.unwrap_or(existing.enabled) as i32,
                now_ts()
            ],
        )?;
        drop(conn);
        self.get_gateway(id)?
            .ok_or_else(|| Error::Internal("gateway update failed".into()))
    }

    pub fn list_gateways(&self) -> Result<Vec<GatewayConfig>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare(
            "SELECT id, name, kind, host, port, username, site, interface_hint, tls, tls_insecure,
                    enabled, created_at, updated_at FROM router_configs ORDER BY name",
        )?;
        let rows = stmt
            .query_map([], gateway_from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn get_gateway(&self, id: &str) -> Result<Option<GatewayConfig>> {
        let conn = self.lock()?;
        let row = conn
            .query_row(
                "SELECT id, name, kind, host, port, username, site, interface_hint, tls, tls_insecure,
                        enabled, created_at, updated_at FROM router_configs WHERE id=?1",
                params![id],
                gateway_from_row,
            )
            .optional()?;
        Ok(row)
    }

    pub fn gateway_secret_encrypted(&self, id: &str) -> Result<Option<String>> {
        let conn = self.lock()?;
        let value: Option<Option<String>> = conn
            .query_row(
                "SELECT secret_enc FROM router_configs WHERE id=?1",
                params![id],
                |row| row.get(0),
            )
            .optional()?;
        Ok(value.flatten())
    }

    pub fn delete_gateway(&self, id: &str) -> Result<()> {
        let conn = self.lock()?;
        let changed = conn.execute("DELETE FROM router_configs WHERE id=?1", params![id])?;
        if changed == 0 {
            return Err(Error::NotFound(format!("gateway {id}")));
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    // Audit
    // ------------------------------------------------------------------

    pub fn audit(
        &self,
        actor: &str,
        action: &str,
        target: Option<&str>,
        outcome: &str,
        detail: Option<&str>,
        remote_addr: Option<&str>,
    ) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO audit_logs(ts, actor, action, target, outcome, detail, remote_addr)
             VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![
                now_ts(),
                actor,
                action,
                target,
                outcome,
                detail.map(crate::util::redact_for_log),
                remote_addr
            ],
        )?;
        Ok(())
    }

    pub fn list_audit(&self, limit: u32, offset: u32) -> Result<Vec<AuditLog>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare(
            "SELECT id, ts, actor, action, target, outcome, detail, remote_addr
             FROM audit_logs ORDER BY ts DESC, id DESC LIMIT ?1 OFFSET ?2",
        )?;
        let rows = stmt
            .query_map(params![limit.clamp(1, 1000), offset], |row| {
                Ok(AuditLog {
                    id: row.get(0)?,
                    ts: row.get(1)?,
                    actor: row.get(2)?,
                    action: row.get(3)?,
                    target: row.get(4)?,
                    outcome: row.get(5)?,
                    detail: row.get(6)?,
                    remote_addr: row.get(7)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    // ------------------------------------------------------------------
    // Users and sessions
    // ------------------------------------------------------------------

    pub fn user_count(&self) -> Result<u64> {
        let conn = self.lock()?;
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM users", [], |row| row.get(0))?;
        Ok(count as u64)
    }

    pub fn create_user(&self, username: &str, password_hash: &str, role: Role) -> Result<User> {
        let username = username.trim();
        if username.len() < 3
            || username.len() > 64
            || !username
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        {
            return Err(Error::Validation(
                "username must be 3-64 characters of letters, digits, dot, dash or underscore"
                    .into(),
            ));
        }
        let id = uuid::Uuid::new_v4().to_string();
        let created = now_ts();
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO users(id, username, password_hash, role, created_at) VALUES (?1,?2,?3,?4,?5)",
            params![id, username, password_hash, role.as_str(), created],
        )
        .map_err(|e| match e {
            rusqlite::Error::SqliteFailure(err, _)
                if err.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                Error::Validation("username already exists".into())
            }
            other => Error::Database(other.to_string()),
        })?;
        Ok(User {
            id,
            username: username.to_string(),
            role,
            created_at: created,
            disabled: false,
            password_hash: password_hash.to_string(),
        })
    }

    pub fn find_user(&self, username: &str) -> Result<Option<User>> {
        let conn = self.lock()?;
        let row = conn
            .query_row(
                "SELECT id, username, password_hash, role, created_at, disabled FROM users WHERE username=?1",
                params![username.trim()],
                user_from_row,
            )
            .optional()?;
        Ok(row)
    }

    pub fn get_user(&self, id: &str) -> Result<Option<User>> {
        let conn = self.lock()?;
        let row = conn
            .query_row(
                "SELECT id, username, password_hash, role, created_at, disabled FROM users WHERE id=?1",
                params![id],
                user_from_row,
            )
            .optional()?;
        Ok(row)
    }

    pub fn list_users(&self) -> Result<Vec<UserSummary>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare(
            "SELECT id, username, role, created_at, disabled FROM users ORDER BY username",
        )?;
        let rows = stmt
            .query_map([], |row| {
                let role: String = row.get(2)?;
                Ok(UserSummary {
                    id: row.get(0)?,
                    username: row.get(1)?,
                    role: role.parse().unwrap_or(Role::Viewer),
                    created_at: row.get(3)?,
                    disabled: row.get::<_, i32>(4)? != 0,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn update_password(&self, user_id: &str, password_hash: &str) -> Result<()> {
        let conn = self.lock()?;
        let changed = conn.execute(
            "UPDATE users SET password_hash=?2 WHERE id=?1",
            params![user_id, password_hash],
        )?;
        if changed == 0 {
            return Err(Error::NotFound(format!("user {user_id}")));
        }
        Ok(())
    }

    pub fn set_user_disabled(&self, user_id: &str, disabled: bool) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "UPDATE users SET disabled=?2 WHERE id=?1",
            params![user_id, disabled as i32],
        )?;
        Ok(())
    }

    pub fn create_session(
        &self,
        token_hash: &str,
        user_id: &str,
        expires_at: &str,
        user_agent: Option<&str>,
    ) -> Result<()> {
        let conn = self.lock()?;
        let now = now_ts();
        conn.execute(
            "INSERT INTO auth_sessions(token_hash, user_id, created_at, expires_at, last_used, user_agent)
             VALUES (?1,?2,?3,?4,?3,?5)",
            params![token_hash, user_id, now, expires_at, user_agent],
        )?;
        Ok(())
    }

    pub fn validate_session(&self, token_hash: &str) -> Result<Option<User>> {
        let conn = self.lock()?;
        let now = now_ts();
        let row = conn
            .query_row(
                "SELECT u.id, u.username, u.password_hash, u.role, u.created_at, u.disabled
                 FROM auth_sessions s JOIN users u ON u.id=s.user_id
                 WHERE s.token_hash=?1 AND s.expires_at>?2 AND u.disabled=0",
                params![token_hash, now],
                user_from_row,
            )
            .optional()?;
        if row.is_some() {
            conn.execute(
                "UPDATE auth_sessions SET last_used=?2 WHERE token_hash=?1",
                params![token_hash, now],
            )?;
        }
        Ok(row)
    }

    pub fn revoke_session(&self, token_hash: &str) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "DELETE FROM auth_sessions WHERE token_hash=?1",
            params![token_hash],
        )?;
        Ok(())
    }

    pub fn revoke_user_sessions(&self, user_id: &str) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "DELETE FROM auth_sessions WHERE user_id=?1",
            params![user_id],
        )?;
        Ok(())
    }

    pub fn prune_expired_sessions(&self) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "DELETE FROM auth_sessions WHERE expires_at<=?1",
            params![now_ts()],
        )?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Settings
    // ------------------------------------------------------------------

    pub fn get_setting(&self, key: &str) -> Result<Option<String>> {
        let conn = self.lock()?;
        let value = conn
            .query_row(
                "SELECT value FROM app_settings WHERE key=?1",
                params![key],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        Ok(value)
    }

    pub fn set_setting(&self, key: &str, value: &str) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO app_settings(key, value) VALUES (?1,?2)
             ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    pub fn load_settings(&self) -> Result<AppSettings> {
        match self.get_setting("app_settings")? {
            Some(raw) => Ok(serde_json::from_str(&raw).unwrap_or_default()),
            None => {
                let settings = AppSettings::default();
                self.save_settings(&settings)?;
                Ok(settings)
            }
        }
    }

    pub fn save_settings(&self, settings: &AppSettings) -> Result<()> {
        self.set_setting("app_settings", &serde_json::to_string(settings)?)
    }

    // ------------------------------------------------------------------
    // Retention
    // ------------------------------------------------------------------

    pub fn prune_history(&self, retention_days: u32) -> Result<()> {
        if retention_days == 0 {
            return Ok(());
        }
        let cutoff = (chrono::Utc::now() - chrono::Duration::days(retention_days as i64))
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let conn = self.lock()?;
        conn.execute(
            "DELETE FROM monitoring_records WHERE ts<?1",
            params![cutoff],
        )?;
        conn.execute(
            "DELETE FROM device_history WHERE ts<?1 AND event NOT IN ('discovered','blocked','unblocked','trusted')",
            params![cutoff],
        )?;
        conn.execute("DELETE FROM notifications WHERE ts<?1", params![cutoff])?;
        Ok(())
    }

    pub fn bootstrap_admin(&self, password: &str) -> Result<User> {
        if self.user_count()? > 0 {
            return Err(Error::Validation("an administrator already exists".into()));
        }
        let hash = crate::security::hash_password(password)?;
        self.create_user("admin", &hash, Role::Admin)
    }
}

// ----------------------------------------------------------------------
// Row helpers
// ----------------------------------------------------------------------

const DEVICE_COLUMNS: &str = "id, mac, ip, ipv6, hostname, vendor, category, category_source, custom_name,
    notes, interface, ssid, online, first_seen, last_seen, open_ports, services, sources, is_trusted,
    blocked, blocked_until, block_source, limit_download_kbps, limit_upload_kbps, limit_expires_at,
    priority, enforcement, created_at, updated_at";

fn query_device(
    conn: &Connection,
    clause: &str,
    params: impl rusqlite::Params,
) -> Result<Option<Device>> {
    let sql = format!(
        "SELECT {} FROM devices WHERE {clause} LIMIT 1",
        DEVICE_COLUMNS
    );
    let row = conn.query_row(&sql, params, row_to_device).optional()?;
    Ok(row)
}

fn row_to_device(row: &Row<'_>) -> rusqlite::Result<Device> {
    let category: String = row.get(6)?;
    let category_source: String = row.get(7)?;
    let open_ports: String = row.get(15)?;
    let services: String = row.get(16)?;
    let sources: String = row.get(17)?;
    let enforcement: String = row.get(26)?;
    Ok(Device {
        id: row.get(0)?,
        mac: row.get(1)?,
        ip: row.get(2)?,
        ipv6: row.get(3)?,
        hostname: row.get(4)?,
        vendor: row.get(5)?,
        category: category.parse().unwrap_or_default(),
        category_source: if category_source == "manual" {
            CategorySource::Manual
        } else {
            CategorySource::Auto
        },
        custom_name: row.get(8)?,
        notes: row.get(9)?,
        interface: row.get(10)?,
        ssid: row.get(11)?,
        online: row.get::<_, i32>(12)? != 0,
        first_seen: row.get(13)?,
        last_seen: row.get(14)?,
        open_ports: serde_json::from_str(&open_ports).unwrap_or_default(),
        services: serde_json::from_str(&services).unwrap_or_default(),
        sources: serde_json::from_str(&sources).unwrap_or_default(),
        is_trusted: row.get::<_, i32>(18)? != 0,
        is_blocked: row.get::<_, i32>(19)? != 0,
        blocked_until: row.get(20)?,
        block_source: row.get(21)?,
        limit_download_kbps: row.get(22)?,
        limit_upload_kbps: row.get(23)?,
        limit_expires_at: row.get(24)?,
        priority: row.get(25)?,
        enforcement: parse_enforcement(&enforcement),
        created_at: row.get(27)?,
        updated_at: row.get(28)?,
    })
}

fn parse_enforcement(value: &str) -> EnforcementState {
    match value {
        "pending" => EnforcementState::Pending,
        "applied" => EnforcementState::Applied,
        "failed" => EnforcementState::Failed,
        "unsupported" => EnforcementState::Unsupported,
        "expired" => EnforcementState::Expired,
        _ => EnforcementState::None,
    }
}

fn network_from_row(row: &Row<'_>) -> rusqlite::Result<NetworkInfo> {
    let kind: String = row.get(2)?;
    let dns: String = row.get(7)?;
    Ok(NetworkInfo {
        id: Some(row.get(0)?),
        interface: row.get(1)?,
        kind: parse_interface_kind(&kind),
        ssid: row.get(3)?,
        cidr: row.get(4)?,
        local_ip: row.get(5)?,
        gateway: row.get(6)?,
        dns: serde_json::from_str(&dns).unwrap_or_default(),
        mac: None,
        online: true,
        first_seen: row.get(8)?,
        last_seen: row.get(9)?,
    })
}

fn parse_interface_kind(value: &str) -> InterfaceKind {
    match value {
        "wifi" => InterfaceKind::Wifi,
        "ethernet" => InterfaceKind::Ethernet,
        "usb_ethernet" => InterfaceKind::UsbEthernet,
        "virtual" => InterfaceKind::Virtual,
        "loopback" => InterfaceKind::Loopback,
        _ => InterfaceKind::Other,
    }
}

fn scan_session_from_row(row: &Row<'_>) -> rusqlite::Result<ScanSession> {
    let methods: String = row.get(3)?;
    Ok(ScanSession {
        id: row.get(0)?,
        interface: row.get(1)?,
        cidr: row.get(2)?,
        methods: serde_json::from_str::<Vec<String>>(&methods)
            .unwrap_or_default()
            .into_iter()
            .filter_map(|m| m.parse().ok())
            .collect(),
        started_at: row.get(4)?,
        finished_at: row.get(5)?,
        status: row.get(6)?,
        hosts_found: row.get::<_, i64>(7)? as u32,
        error: row.get(8)?,
        privileged: row.get::<_, i32>(9)? != 0,
    })
}

fn gateway_from_row(row: &Row<'_>) -> rusqlite::Result<GatewayConfig> {
    let kind: String = row.get(2)?;
    Ok(GatewayConfig {
        id: row.get(0)?,
        name: row.get(1)?,
        kind: kind.parse().unwrap_or(GatewayKind::Linux),
        host: row.get(3)?,
        port: row.get::<_, i64>(4)? as u16,
        username: row.get(5)?,
        site: row.get(6)?,
        interface_hint: row.get(7)?,
        tls: row.get::<_, i32>(8)? != 0,
        tls_insecure: row.get::<_, i32>(9)? != 0,
        enabled: row.get::<_, i32>(10)? != 0,
        created_at: row.get(11)?,
        updated_at: row.get(12)?,
    })
}

fn user_from_row(row: &Row<'_>) -> rusqlite::Result<User> {
    let role: String = row.get(3)?;
    Ok(User {
        id: row.get(0)?,
        username: row.get(1)?,
        password_hash: row.get(2)?,
        role: role.parse().unwrap_or(Role::Viewer),
        created_at: row.get(4)?,
        disabled: row.get::<_, i32>(5)? != 0,
    })
}

fn insert_history_tx(
    tx: &rusqlite::Transaction<'_>,
    device_id: &str,
    ts: &str,
    event: &str,
    detail: Option<&str>,
    scan_id: Option<&str>,
) -> rusqlite::Result<()> {
    tx.execute(
        "INSERT INTO device_history(device_id, ts, event, detail, scan_id) VALUES (?1,?2,?3,?4,?5)",
        params![device_id, ts, event, detail, scan_id],
    )?;
    Ok(())
}

pub fn open_default(paths: &Paths) -> Result<Db> {
    paths.ensure()?;
    Db::open(&paths.database)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obs(ip: &str, mac: &str) -> HostObservation {
        let mut o = HostObservation::new(ip, "arp");
        o.mac = Some(mac.into());
        o.hostname = Some("test-host".into());
        o.open_ports = vec![80, 443];
        o
    }

    #[test]
    fn migration_and_upsert() {
        let db = Db::open_memory().unwrap();
        let first = db
            .upsert_observation(
                &obs("192.168.1.10", "aa:bb:cc:dd:ee:01"),
                Some("eth0"),
                None,
                "scan-1",
            )
            .unwrap();
        assert!(first.is_new);
        let second = db
            .upsert_observation(
                &obs("192.168.1.10", "aa:bb:cc:dd:ee:01"),
                Some("eth0"),
                None,
                "scan-2",
            )
            .unwrap();
        assert!(!second.is_new);
        assert_eq!(first.device.id, second.device.id);
        let counts = db.counts().unwrap();
        assert_eq!(counts.total, 1);
        assert_eq!(counts.online, 1);
        let history = db.list_history(&first.device.id, 10).unwrap();
        assert!(history.iter().any(|h| h.event == "discovered"));
    }

    #[test]
    fn offline_marking() {
        let db = Db::open_memory().unwrap();
        let a = db
            .upsert_observation(
                &obs("192.168.1.10", "aa:bb:cc:dd:ee:01"),
                Some("eth0"),
                None,
                "s1",
            )
            .unwrap();
        db.upsert_observation(
            &obs("192.168.1.11", "aa:bb:cc:dd:ee:02"),
            Some("eth0"),
            None,
            "s1",
        )
        .unwrap();
        let marked = db
            .mark_offline_except("eth0", &[a.device.id.clone()], &now_ts())
            .unwrap();
        assert_eq!(marked, 1);
        assert!(db.get_device(&a.device.id).unwrap().unwrap().online);
    }

    #[test]
    fn filters_and_patch() {
        let db = Db::open_memory().unwrap();
        let a = db
            .upsert_observation(
                &obs("192.168.1.10", "aa:bb:cc:dd:ee:01"),
                Some("eth0"),
                None,
                "s1",
            )
            .unwrap();
        db.update_device(
            &a.device.id,
            &DevicePatch {
                custom_name: Some("Living room TV".into()),
                category: Some(DeviceCategory::SmartTv),
                notes: None,
                is_trusted: Some(true),
            },
        )
        .unwrap();
        let page = db
            .list_devices(&DeviceFilter {
                query: Some("living".into()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(page.total, 1);
        assert_eq!(page.items[0].category, DeviceCategory::SmartTv);
        assert_eq!(page.items[0].category_source, CategorySource::Manual);
        let trusted = db
            .list_devices(&DeviceFilter {
                trusted: Some(true),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(trusted.total, 1);
    }

    #[test]
    fn users_and_sessions() {
        let db = Db::open_memory().unwrap();
        let user = db
            .create_user(
                "admin",
                &crate::security::hash_password("CorrectHorse1!").unwrap(),
                Role::Admin,
            )
            .unwrap();
        let (token, digest) = crate::security::generate_token();
        let expiry = (chrono::Utc::now() + chrono::Duration::hours(1))
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        db.create_session(&digest, &user.id, &expiry, Some("test"))
            .unwrap();
        let validated = db
            .validate_session(&crate::security::token_digest(&token))
            .unwrap();
        assert!(validated.is_some());
        db.revoke_session(&digest).unwrap();
        assert!(db.validate_session(&digest).unwrap().is_none());
    }

    #[test]
    fn settings_and_audit() {
        let db = Db::open_memory().unwrap();
        let mut settings = db.load_settings().unwrap();
        settings.scan_interval_seconds = 300;
        db.save_settings(&settings).unwrap();
        assert_eq!(db.load_settings().unwrap().scan_interval_seconds, 300);
        db.audit(
            "admin",
            "test",
            Some("x"),
            "success",
            Some("password=secret"),
            None,
        )
        .unwrap();
        let logs = db.list_audit(10, 0).unwrap();
        assert_eq!(logs.len(), 1);
        assert!(!logs[0].detail.as_deref().unwrap_or("").contains("secret"));
    }

    #[test]
    fn gateway_secret_is_not_in_summary() {
        let db = Db::open_memory().unwrap();
        let input = GatewayConfigInput {
            name: "Router".into(),
            kind: GatewayKind::OpenWrt,
            host: "192.168.1.1".into(),
            port: None,
            username: Some("root".into()),
            secret: Some("hunter2".into()),
            site: None,
            interface_hint: None,
            tls: None,
            tls_insecure: None,
            enabled: None,
        };
        let gateway = db.create_gateway(&input, Some("nc1:sealed")).unwrap();
        assert_eq!(gateway.port, 22);
        assert_eq!(
            db.gateway_secret_encrypted(&gateway.id).unwrap().as_deref(),
            Some("nc1:sealed")
        );
        let json = serde_json::to_string(&gateway).unwrap();
        assert!(!json.contains("hunter2"));
    }
}
