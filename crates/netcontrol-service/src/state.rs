use netcontrol_core::config::{Config, Paths};
use netcontrol_core::db::Db;
use netcontrol_core::models::{AppSettings, GatewayProbe, SystemStatus};
use netcontrol_core::security::MasterKey;
use netcontrol_core::Result;
use netcontrol_discovery::DiscoveryEngine;
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Instant;
use tokio::sync::{broadcast, Mutex as AsyncMutex, RwLock};

use crate::events::ServerEvent;
use crate::monitor::Monitor;

#[derive(Default)]
pub struct LoginLimiter {
    attempts: HashMap<IpAddr, Vec<Instant>>,
}

impl LoginLimiter {
    pub fn allowed(&mut self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let window = std::time::Duration::from_secs(300);
        let entry = self.attempts.entry(ip).or_default();
        entry.retain(|t| now.duration_since(*t) < window);
        entry.len() < 15
    }

    pub fn record_failure(&mut self, ip: IpAddr) {
        self.attempts.entry(ip).or_default().push(Instant::now());
    }

    pub fn clear(&mut self, ip: IpAddr) {
        self.attempts.remove(&ip);
    }
}

pub struct AppState {
    pub paths: Paths,
    pub config: Config,
    pub db: Arc<Db>,
    pub key: Arc<MasterKey>,
    pub engine: Arc<DiscoveryEngine>,
    pub settings: Arc<RwLock<AppSettings>>,
    pub events: broadcast::Sender<ServerEvent>,
    pub started_at: Instant,
    pub active_gateway_id: Arc<RwLock<Option<String>>>,
    pub scan_lock: Arc<AsyncMutex<()>>,
    pub gateway_cache: Arc<RwLock<Option<(Instant, GatewayProbe)>>>,
    pub monitor: Arc<Monitor>,
    pub login_limiter: Arc<Mutex<LoginLimiter>>,
}

impl AppState {
    pub fn load(paths: Paths, config: Config) -> Result<Arc<Self>> {
        paths.ensure()?;
        let key = MasterKey::load_or_create(&paths.master_key)?;
        let db = Arc::new(Db::open(&paths.database)?);
        let settings = db.load_settings()?;
        let active_gateway_id = db.get_setting("active_gateway_id")?;
        let (events, _) = broadcast::channel(512);
        Ok(Arc::new(Self {
            paths,
            config,
            db,
            key: Arc::new(key),
            engine: Arc::new(DiscoveryEngine::new()),
            settings: Arc::new(RwLock::new(settings)),
            events,
            started_at: Instant::now(),
            active_gateway_id: Arc::new(RwLock::new(active_gateway_id)),
            scan_lock: Arc::new(AsyncMutex::new(())),
            gateway_cache: Arc::new(RwLock::new(None)),
            monitor: Arc::new(Monitor::new()),
            login_limiter: Arc::new(Mutex::new(LoginLimiter::default())),
        }))
    }

    pub fn emit(&self, event: ServerEvent) {
        let _ = self.events.send(event);
    }

    pub fn status(&self) -> SystemStatus {
        let hostname = hostname();
        SystemStatus {
            version: netcontrol_core::VERSION.to_string(),
            hostname,
            platform: format!("{} {}", std::env::consts::OS, std::env::consts::ARCH),
            database: self.db.location().to_string(),
            uptime_seconds: self.started_at.elapsed().as_secs(),
            listening: Some(self.config.server.listen.clone()),
            tls: self.config.tls_enabled(),
            privileged: self.engine.tools.privileged_scan(),
            gateway_configured: self
                .db
                .list_gateways()
                .map(|g| g.iter().any(|g| g.enabled))
                .unwrap_or(false),
            device_count: self.db.counts().map(|c| c.total).unwrap_or(0),
        }
    }

    pub fn password_file(&self) -> PathBuf {
        self.paths
            .config_file
            .parent()
            .map(|p| p.join("initial-admin-password.txt"))
            .unwrap_or_else(|| self.paths.root.join("initial-admin-password.txt"))
    }

    /// First-run bootstrap. The password is either provided explicitly through
    /// NETCONTROL_ADMIN_PASSWORD or generated and written to a 0600 file. It is
    /// never written to logs.
    pub fn bootstrap_admin(&self) -> Result<Option<PathBuf>> {
        if self.db.user_count()? > 0 {
            return Ok(None);
        }
        let username = std::env::var("NETCONTROL_ADMIN_USER").unwrap_or_else(|_| "admin".into());
        let (password, generated) = match std::env::var("NETCONTROL_ADMIN_PASSWORD") {
            Ok(pw) if !pw.is_empty() => (pw, false),
            _ => (netcontrol_core::security::generate_password(), true),
        };
        let hash = netcontrol_core::security::hash_password(&password)?;
        self.db
            .create_user(&username, &hash, netcontrol_core::models::Role::Admin)?;
        self.db.audit(
            "system",
            "bootstrap_admin",
            Some(&username),
            "success",
            Some("initial administrator created"),
            None,
        )?;
        if generated {
            let path = self.password_file();
            write_private(&path, password.as_bytes())?;
            tracing::warn!(
                path = %path.display(),
                "created the initial NetControl administrator; read the one-time password from this 0600 file"
            );
            Ok(Some(path))
        } else {
            tracing::info!("initial administrator created from NETCONTROL_ADMIN_PASSWORD");
            Ok(None)
        }
    }

    pub fn remove_password_file(&self) {
        let path = self.password_file();
        if path.exists() {
            let _ = std::fs::remove_file(path);
        }
    }
}

pub fn hostname() -> String {
    #[cfg(unix)]
    {
        let mut buf = [0u8; 256];
        // SAFETY: buffer and length are valid for the duration of the call.
        let rc = unsafe { libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
        if rc == 0 {
            if let Some(end) = buf.iter().position(|b| *b == 0) {
                return String::from_utf8_lossy(&buf[..end]).to_string();
            }
        }
    }
    std::env::var("HOSTNAME").unwrap_or_else(|_| "netcontrol".into())
}

#[cfg(unix)]
fn write_private(path: &std::path::Path, contents: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(contents)?;
    file.sync_all()?;
    let mut perms = std::fs::metadata(path)?.permissions();
    perms.set_mode(0o600);
    std::fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private(path: &std::path::Path, contents: &[u8]) -> Result<()> {
    std::fs::write(path, contents)?;
    Ok(())
}
