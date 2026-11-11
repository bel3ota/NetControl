use crate::error::{Error, Result};
use crate::models::ScanMethod;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct Paths {
    pub root: PathBuf,
    pub config_file: PathBuf,
    pub database: PathBuf,
    pub master_key: PathBuf,
    pub audit_export: PathBuf,
    pub cache: PathBuf,
}

impl Paths {
    /// Resolve paths using XDG conventions. `NETCONTROL_HOME` overrides both
    /// config and data locations, which keeps integration tests isolated.
    pub fn discover() -> Result<Self> {
        if let Ok(root) = std::env::var("NETCONTROL_HOME") {
            let root = PathBuf::from(root);
            return Ok(Self::under_root(root));
        }
        let home = dirs::home_dir()
            .ok_or_else(|| Error::Config("cannot determine home directory".into()))?;
        let config_dir = std::env::var("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| home.join(".config"))
            .join("netcontrol");
        let data_dir = std::env::var("XDG_DATA_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| home.join(".local").join("share"))
            .join("netcontrol");
        let cache_dir = std::env::var("XDG_CACHE_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| home.join(".cache"))
            .join("netcontrol");
        Ok(Self {
            config_file: config_dir.join("config.toml"),
            database: data_dir.join("netcontrol.db"),
            master_key: config_dir.join("master.key"),
            audit_export: data_dir.join("audit"),
            cache: cache_dir,
            root: data_dir,
        })
    }

    pub fn under_root(root: PathBuf) -> Self {
        Self {
            config_file: root.join("config.toml"),
            database: root.join("netcontrol.db"),
            master_key: root.join("master.key"),
            audit_export: root.join("audit"),
            cache: root.join("cache"),
            root,
        }
    }

    pub fn ensure(&self) -> Result<()> {
        for dir in [
            self.root.clone(),
            self.cache.clone(),
            self.audit_export.clone(),
            self.config_file
                .parent()
                .map(PathBuf::from)
                .unwrap_or_else(|| self.root.clone()),
        ] {
            fs::create_dir_all(&dir)?;
            restrict_dir(&dir)?;
        }
        Ok(())
    }
}

#[cfg(unix)]
fn restrict_dir(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_mode(0o700);
    fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_dir(_path: &Path) -> Result<()> {
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    pub listen: String,
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
    pub session_hours: i64,
    pub allow_remote: bool,
    pub allow_public_scan: bool,
    pub trust_proxy: bool,
    pub scan_on_start: bool,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:8787".into(),
            tls_cert: None,
            tls_key: None,
            session_hours: 12,
            allow_remote: false,
            allow_public_scan: false,
            trust_proxy: false,
            scan_on_start: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ScanConfig {
    pub interval_seconds: u64,
    pub timeout_ms: u64,
    pub max_hosts: u32,
    pub methods: Vec<ScanMethod>,
    pub enable_nmap: bool,
    pub enable_mdns: bool,
    pub nmap_path: String,
    pub privilege_mode: PrivilegeMode,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            interval_seconds: 120,
            timeout_ms: 1200,
            max_hosts: 1024,
            methods: vec![ScanMethod::Neighbor, ScanMethod::Icmp, ScanMethod::Mdns],
            enable_nmap: false,
            enable_mdns: true,
            nmap_path: "nmap".into(),
            privilege_mode: PrivilegeMode::Auto,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum PrivilegeMode {
    #[default]
    Auto,
    Privileged,
    Unprivileged,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LoggingConfig {
    pub level: String,
    pub json: bool,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".into(),
            json: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Config {
    pub server: ServerConfig,
    pub scan: ScanConfig,
    pub logging: LoggingConfig,
}

impl Config {
    pub fn load_or_create(paths: &Paths) -> Result<Self> {
        paths.ensure()?;
        if paths.config_file.exists() {
            let raw = fs::read_to_string(&paths.config_file)?;
            let config: Config = toml::from_str(&raw)?;
            config.validate()?;
            Ok(config)
        } else {
            let config = Config::default();
            config.save(paths)?;
            Ok(config)
        }
    }

    pub fn save(&self, paths: &Paths) -> Result<()> {
        paths.ensure()?;
        let raw = toml::to_string_pretty(self)?;
        let tmp = paths.config_file.with_extension("toml.tmp");
        fs::write(&tmp, raw)?;
        fs::rename(&tmp, &paths.config_file)?;
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        if self.server.listen.parse::<std::net::SocketAddr>().is_err() {
            return Err(Error::Config(format!(
                "server.listen must be host:port, got {:?}",
                self.server.listen
            )));
        }
        if self.server.tls_cert.is_some() != self.server.tls_key.is_some() {
            return Err(Error::Config(
                "tls_cert and tls_key must both be set or both be omitted".into(),
            ));
        }
        if self.scan.interval_seconds < 15 {
            return Err(Error::Config(
                "scan.interval_seconds must be at least 15 seconds".into(),
            ));
        }
        if self.scan.max_hosts == 0 || self.scan.max_hosts > 65_534 {
            return Err(Error::Config(
                "scan.max_hosts must be between 1 and 65534".into(),
            ));
        }
        Ok(())
    }

    pub fn tls_enabled(&self) -> bool {
        self.server.tls_cert.is_some() && self.server.tls_key.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::under_root(dir.path().to_path_buf());
        let cfg = Config::load_or_create(&paths).unwrap();
        assert_eq!(cfg.server.listen, "127.0.0.1:8787");
        assert!(paths.config_file.exists());
        let loaded = Config::load_or_create(&paths).unwrap();
        assert_eq!(loaded.scan.interval_seconds, 120);
    }

    #[test]
    fn rejects_bad_listen() {
        let mut cfg = Config::default();
        cfg.server.listen = "not-an-address".into();
        assert!(cfg.validate().is_err());
    }
}
