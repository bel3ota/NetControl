//! SSH transport used by the OpenWrt and pfSense adapters.
//!
//! Password authentication goes through `sshpass -e` (the password is passed
//! in the environment, never argv). Key authentication is preferred: install
//! an SSH key on the gateway and leave the secret empty. Host keys use
//! `StrictHostKeyChecking=accept-new` (trust on first use); pin the key in
//! `~/.ssh/known_hosts` for strict verification.

use crate::traits::AdapterSecret;
use netcontrol_core::models::GatewayConfig;
use netcontrol_core::{Error, Result};
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;

pub struct SshClient {
    host: String,
    port: u16,
    username: String,
    secret: Option<AdapterSecret>,
    accept_invalid_host_key: bool,
}

impl SshClient {
    pub fn new(config: &GatewayConfig, secret: Option<AdapterSecret>) -> Result<Self> {
        let host = config.host.trim().to_string();
        if host.is_empty()
            || host.len() > 253
            || !host
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '_'))
        {
            return Err(Error::Validation(format!(
                "invalid SSH host: {:?}",
                config.host
            )));
        }
        let username = config
            .username
            .clone()
            .filter(|u| !u.trim().is_empty())
            .unwrap_or_else(|| "root".into());
        if !username
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        {
            return Err(Error::Validation("invalid SSH username".into()));
        }
        Ok(Self {
            host,
            port: config.port.max(1),
            username,
            secret,
            accept_invalid_host_key: config.tls_insecure,
        })
    }

    pub async fn run(&self, script: &str) -> Result<String> {
        self.run_with_timeout(script, Duration::from_secs(30)).await
    }

    pub async fn run_with_timeout(&self, script: &str, timeout: Duration) -> Result<String> {
        let destination = format!("{}@{}", self.username, self.host);
        let mut command = if self.secret.is_some() {
            if !which("sshpass") {
                return Err(Error::Unsupported(
                    "SSH password authentication requires the `sshpass` package; install it or configure an SSH key"
                        .into(),
                ));
            }
            let mut command = Command::new("sshpass");
            command.arg("-e").arg("ssh");
            command
        } else {
            Command::new("ssh")
        };
        command
            .args(["-p", &self.port.to_string()])
            .args(["-o", "ConnectTimeout=8"])
            .args(["-o", "ServerAliveInterval=5"])
            .args(["-o", "ServerAliveCountMax=2"])
            .arg(format!(
                "-oStrictHostKeyChecking={}",
                if self.accept_invalid_host_key {
                    "no"
                } else {
                    "accept-new"
                }
            ))
            .args(["-o", "LogLevel=ERROR"]);
        if self.secret.is_some() {
            command.args(["-o", "NumberOfPasswordPrompts=1"]).args([
                "-o",
                "PreferredAuthentications=password,keyboard-interactive",
            ]);
        } else {
            command.args(["-o", "BatchMode=yes"]);
        }
        command
            .arg(destination)
            .arg(script)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        if let Some(secret) = &self.secret {
            command.env("SSHPASS", secret.value.as_str());
        }
        let output = tokio::time::timeout(timeout, command.output())
            .await
            .map_err(|_| Error::Gateway("SSH command timed out".into()))??;
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::Gateway(format!(
                "SSH command failed ({}): {}",
                output.status.code().unwrap_or(-1),
                netcontrol_core::util::redact_for_log(stderr.trim())
            )));
        }
        Ok(stdout)
    }
}

/// POSIX shell single-quote escaping for values embedded in a remote script.
/// This is defense in depth: callers validate values first.
pub fn sh_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

pub fn which(tool: &str) -> bool {
    std::env::var_os("PATH")
        .map(|path| std::env::split_paths(&path).any(|dir| dir.join(tool).is_file()))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quotes_shell_values() {
        assert_eq!(sh_quote("lan"), "'lan'");
        assert_eq!(sh_quote("a'b"), "'a'\\''b'");
        let quoted = sh_quote("; rm -rf /");
        assert!(quoted.starts_with('\'') && quoted.ends_with('\''));
        assert!(quoted.contains("; rm -rf /"));
    }
}
