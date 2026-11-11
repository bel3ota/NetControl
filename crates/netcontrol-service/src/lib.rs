//! NetControl service: orchestration, authentication, REST API, monitoring and
//! scheduling. These functions are shared by the `netcontrol` CLI (local mode)
//! and the `netcontrold`/desktop service processes.

pub mod api;
pub mod auth;
pub mod error;
pub mod events;
pub mod monitor;
pub mod orchestration;
pub mod scheduler;
pub mod state;

pub use events::ServerEvent;
pub use orchestration::{
    active_gateway, auto_clear_limit, auto_unblock, block_device, clear_bandwidth, gateway_clients,
    probe_active, run_scan, set_active_gateway, set_bandwidth, test_gateway, trust_device,
    ActionResult, LimitOutcome, ScanOutcome,
};
pub use state::AppState;

use netcontrol_core::config::{Config, Paths};
use netcontrol_core::models::ScanOptions;
use netcontrol_core::{Error, Result};
use std::net::SocketAddr;

/// Load state and start the HTTP(S) API plus background monitoring and
/// scheduling. Refuses to expose an unencrypted listener beyond loopback.
pub async fn serve(paths: Paths, config: Config) -> Result<()> {
    let addr: SocketAddr =
        config.server.listen.parse().map_err(|_| {
            Error::Config(format!("invalid listen address: {}", config.server.listen))
        })?;
    let tls = config.tls_enabled();
    if !addr.ip().is_loopback() && !tls {
        let override_enabled = std::env::var("NETCONTROL_ALLOW_INSECURE_REMOTE")
            .map(|v| v == "1")
            .unwrap_or(false);
        if !override_enabled {
            return Err(Error::Config(
                "refusing to expose the management API on a non-loopback address without TLS. \
                 Configure server.tls_cert and server.tls_key, bind 127.0.0.1 and use a tunnel, \
                 or set NETCONTROL_ALLOW_INSECURE_REMOTE=1 only for an isolated lab."
                    .into(),
            ));
        }
        tracing::warn!(
            "serving the management API without TLS on a remote interface (explicit override)"
        );
    }
    if !addr.ip().is_loopback() && !config.server.allow_remote {
        return Err(Error::Config(
            "server.allow_remote is false; set it to true and configure TLS before exposing the API"
                .into(),
        ));
    }

    let state = AppState::load(paths, config.clone())?;
    let password_file = state.bootstrap_admin()?;
    if let Some(path) = &password_file {
        println!(
            "NetControl: initial administrator password written to {} (mode 0600). It is deleted after the first admin login.",
            path.display()
        );
    }

    tokio::spawn(monitor::monitor_loop(state.clone()));
    tokio::spawn(scheduler::scheduler_loop(state.clone()));

    let scan_on_start = config.server.scan_on_start || state.settings.read().await.scan_on_start;
    if scan_on_start {
        let state = state.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            let settings = state.settings.read().await.clone();
            let opts = ScanOptions {
                interface: settings.preferred_interface.clone(),
                methods: settings.default_scan_methods.clone(),
                nmap: settings.enable_nmap,
                mdns: settings.enable_mdns,
                max_hosts: settings.max_hosts,
                confirmed: true,
                ..Default::default()
            };
            if let Err(err) = run_scan(&state, opts, "startup", None).await {
                tracing::warn!(error = %err, "startup scan failed");
            }
        });
    }

    let app = api::router(state.clone());
    let scheme = if tls { "https" } else { "http" };
    tracing::info!(%addr, tls, "NetControl API listening at {scheme}://{addr}/api/v1");
    println!("NetControl API listening at {scheme}://{addr}/api/v1");

    if tls {
        let cert = config
            .server
            .tls_cert
            .as_ref()
            .ok_or_else(|| Error::Config("tls_cert is missing".into()))?;
        let key = config
            .server
            .tls_key
            .as_ref()
            .ok_or_else(|| Error::Config("tls_key is missing".into()))?;
        let tls_config = axum_server::tls_rustls::RustlsConfig::from_pem_file(cert, key)
            .await
            .map_err(|e| Error::Config(format!("cannot load TLS certificate/key: {e}")))?;
        axum_server::bind_rustls(addr, tls_config)
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .await
            .map_err(Error::Io)?;
    } else {
        let listener = tokio::net::TcpListener::bind(addr).await?;
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(Error::Io)?;
    }
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut signal) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            signal.recv().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    tracing::info!("shutdown signal received");
}
