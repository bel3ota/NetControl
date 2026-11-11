//! `netcontrol` — NetControl command line interface.
//!
//! Runs the shared engine locally against the same SQLite database and gateway
//! adapters used by the service and desktop app. Disruptive actions require an
//! explicit `--yes` or an interactive confirmation.

use clap::{Args, Parser, Subcommand};
use comfy_table::{presets::UTF8_FULL, Attribute, Cell, ContentArrangement, Table};
use netcontrol_core::config::{Config, Paths};
use netcontrol_core::models::{
    AccessAction, Device, DeviceCategory, DeviceFilter, DevicePatch, EnforcementResult,
    GatewayConfigInput, GatewayKind, GatewayProbe, NetworkInfo, ScanMethod, ScanOptions,
    TrafficOverview,
};
use netcontrol_core::util::{
    format_bps, format_bytes, format_kbps, now_ts, parse_rate_kbps, parse_ts,
};
use netcontrol_core::{Error, Result};
use netcontrol_discovery::InterfaceManager;
use netcontrol_service::{AppState, ScanOutcome};
use serde::Serialize;
use std::io::{IsTerminal, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(
    name = "netcontrol",
    version,
    about = "NetControl — authorized LAN discovery, monitoring and access management",
    long_about = None
)]
struct Cli {
    /// Emit machine-readable JSON.
    #[arg(long, global = true)]
    json: bool,
    /// Disable ANSI colors.
    #[arg(long, global = true)]
    no_color: bool,
    /// Increase log verbosity (-v, -vv).
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    verbose: u8,
    /// Accept confirmation prompts (required for non-interactive use).
    #[arg(long, global = true)]
    yes: bool,
    /// Talk to a remote NetControl service instead of the local database.
    #[arg(long, global = true, env = "NETCONTROL_SERVER")]
    server: Option<String>,
    /// Session token for the remote service.
    #[arg(long, global = true, env = "NETCONTROL_TOKEN", hide_env_values = true)]
    token: Option<String>,
    /// Accept invalid TLS certificates for a remote service (lab only).
    #[arg(long, global = true)]
    insecure: bool,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Show the dashboard (default).
    Dashboard,
    /// List network interfaces.
    Interfaces,
    /// Scan the connected network.
    Scan(ScanArgs),
    /// List discovered devices.
    Devices(DevicesArgs),
    /// Inspect or edit a device.
    Device(DeviceArgs),
    /// Live interface traffic.
    Monitor(MonitorArgs),
    /// Scan history.
    History {
        /// Show history for one device instead of scan sessions.
        #[arg(long)]
        device: Option<String>,
        #[arg(long, default_value_t = 20)]
        limit: u32,
    },
    /// Block a device.
    Block(BlockArgs),
    /// Restore access to a device.
    Unblock(UnblockArgs),
    /// Temporarily pause a device's internet access.
    Pause(PauseArgs),
    /// Set per-device bandwidth limits.
    Limit(LimitArgs),
    /// Clear per-device bandwidth limits.
    Unlimit(UnblockArgs),
    /// Mark a device as trusted.
    Trust(TargetArgs),
    /// Remove a device from the trusted list.
    Untrust(TargetArgs),
    /// Manage authorized gateway integrations.
    Gateway(GatewayArgs),
    /// Show or update settings.
    Config(ConfigArgs),
    /// Administrative operations.
    Admin(AdminArgs),
    /// Start the authenticated management API.
    Serve(ServeArgs),
    /// Interactive command loop.
    Interactive,
}

#[derive(Args, Debug)]
struct ScanArgs {
    /// Interface to scan (default: active interface).
    #[arg(short, long)]
    interface: Option<String>,
    /// Scan methods (neighbor, icmp, arp, tcp, nmap, mdns). Repeatable.
    #[arg(long = "method", value_delimiter = ',')]
    methods: Vec<String>,
    /// Use Nmap for host discovery.
    #[arg(long)]
    nmap: bool,
    /// Explicitly probe common TCP ports and record open ports.
    #[arg(long)]
    ports: bool,
    /// Disable mDNS discovery.
    #[arg(long)]
    no_mdns: bool,
    #[arg(long, default_value_t = 1200)]
    timeout_ms: u64,
    #[arg(long, default_value_t = 1024)]
    max_hosts: u32,
    /// Permit scanning a non-private range (explicit authorization).
    #[arg(long)]
    allow_public: bool,
}

#[derive(Args, Debug)]
struct DevicesArgs {
    #[arg(long)]
    online: bool,
    #[arg(long)]
    offline: bool,
    #[arg(long)]
    blocked: bool,
    #[arg(long)]
    trusted: bool,
    #[arg(long)]
    category: Option<String>,
    #[arg(long, value_name = "TEXT")]
    search: Option<String>,
    #[arg(long, default_value_t = 100)]
    limit: u32,
    #[arg(long, default_value_t = 0)]
    offset: u32,
    #[arg(long, default_value = "name")]
    sort: String,
    #[arg(long)]
    desc: bool,
}

#[derive(Args, Debug)]
struct DeviceArgs {
    #[command(subcommand)]
    command: DeviceCommand,
}

#[derive(Subcommand, Debug)]
enum DeviceCommand {
    /// Show detailed device information.
    Info { target: String },
    /// Assign a friendly name.
    Rename { target: String, name: String },
    /// Set the device category.
    Category { target: String, category: String },
    /// Add a note.
    Note { target: String, note: String },
}

#[derive(Args, Debug)]
struct TargetArgs {
    target: String,
}

#[derive(Args, Debug)]
struct BlockArgs {
    target: String,
    /// Temporary duration, e.g. 30m, 2h, 7d.
    #[arg(long)]
    for_duration: Option<String>,
    #[arg(long)]
    reason: Option<String>,
}

#[derive(Args, Debug)]
struct UnblockArgs {
    target: String,
}

#[derive(Args, Debug)]
struct PauseArgs {
    target: String,
    /// Duration (default 1h), e.g. 30m, 2h.
    #[arg(long, default_value = "1h")]
    for_duration: String,
}

#[derive(Args, Debug)]
struct LimitArgs {
    target: String,
    /// Download limit, e.g. 10Mbps. Use "unlimited" for no limit.
    #[arg(long, default_value = "unlimited")]
    download: String,
    /// Upload limit, e.g. 2Mbps.
    #[arg(long, default_value = "unlimited")]
    upload: String,
    #[arg(long)]
    priority: Option<i32>,
    #[arg(long)]
    for_duration: Option<String>,
}

#[derive(Args, Debug)]
struct MonitorArgs {
    #[arg(short, long)]
    interface: Option<String>,
    #[arg(long, default_value_t = 2)]
    interval: u64,
}

#[derive(Args, Debug)]
struct GatewayArgs {
    #[command(subcommand)]
    command: GatewayCommand,
}

#[derive(Subcommand, Debug)]
enum GatewayCommand {
    /// List configured gateways.
    List,
    /// Probe the active gateway.
    Status,
    /// Add a gateway integration.
    Add(AddGatewayArgs),
    /// Test a gateway.
    Test { id: Option<String> },
    /// Select the active gateway.
    Connect { id: String },
    /// List clients reported by the active gateway.
    Clients,
    /// Delete a gateway.
    Delete { id: String },
}

#[derive(Args, Debug)]
struct AddGatewayArgs {
    #[arg(long)]
    name: Option<String>,
    #[arg(long)]
    kind: String,
    #[arg(long)]
    host: Option<String>,
    #[arg(long)]
    port: Option<u16>,
    #[arg(long)]
    username: Option<String>,
    /// Secret/API key. Prefer --ask-password or the prompt to avoid shell history.
    #[arg(long, hide_env_values = true)]
    password: Option<String>,
    #[arg(long)]
    ask_password: bool,
    #[arg(long)]
    site: Option<String>,
    /// LAN interface (required for bandwidth shaping on OpenWrt/Linux).
    #[arg(long)]
    interface: Option<String>,
    #[arg(long)]
    no_tls: bool,
    #[arg(long)]
    insecure: bool,
}

#[derive(Args, Debug)]
struct ConfigArgs {
    #[command(subcommand)]
    command: Option<ConfigCommand>,
}

#[derive(Subcommand, Debug)]
enum ConfigCommand {
    Show,
    Path,
    Set { key: String, value: String },
    Edit,
}

#[derive(Args, Debug)]
struct AdminArgs {
    #[command(subcommand)]
    command: AdminCommand,
}

#[derive(Subcommand, Debug)]
enum AdminCommand {
    /// List local users.
    Users,
    /// Reset a local user's password and revoke all sessions.
    ResetPassword {
        #[arg(long, default_value = "admin")]
        username: String,
    },
}

#[derive(Args, Debug)]
struct ServeArgs {
    #[arg(long)]
    listen: Option<String>,
    #[arg(long)]
    tls_cert: Option<PathBuf>,
    #[arg(long)]
    tls_key: Option<PathBuf>,
    #[arg(long)]
    allow_remote: bool,
}

#[derive(Clone)]
struct Style {
    color: bool,
}

impl Style {
    fn paint(&self, text: &str, code: &str, bold: bool) -> String {
        if !self.color {
            return text.to_string();
        }
        format!(
            "\x1b[{}{}m{}\x1b[0m",
            if bold { "1;" } else { "" },
            code,
            text
        )
    }
    fn green(&self, text: &str) -> String {
        self.paint(text, "32", false)
    }
    fn red(&self, text: &str) -> String {
        self.paint(text, "31", false)
    }
    fn yellow(&self, text: &str) -> String {
        self.paint(text, "33", false)
    }
    fn cyan(&self, text: &str) -> String {
        self.paint(text, "36", false)
    }
    fn dim(&self, text: &str) -> String {
        self.paint(text, "2", false)
    }
    fn bold(&self, text: &str) -> String {
        self.paint(text, "37", true)
    }
}

struct Ctx {
    json: bool,
    yes: bool,
    style: Style,
    paths: Paths,
    config: Config,
}

#[tokio::main]
async fn main() {
    if let Err(err) = run().await {
        eprintln!("\x1b[31merror:\x1b[0m {err}");
        std::process::exit(exit_code(&err));
    }
}

fn exit_code(err: &Error) -> i32 {
    match err {
        Error::Unsupported(_) => 2,
        Error::Forbidden(_) => 3,
        Error::NotFound(_) => 4,
        Error::Validation(_) => 5,
        _ => 1,
    }
}

async fn run() -> Result<()> {
    let cli = Cli::parse();
    init_logging(cli.verbose);
    let color =
        !cli.no_color && std::env::var_os("NO_COLOR").is_none() && std::io::stdout().is_terminal();
    let style = Style { color };
    if let Some(server) = cli.server.clone() {
        return run_remote(cli, server, style).await;
    }
    let paths = Paths::discover()?;
    let config = Config::load_or_create(&paths)?;
    if let Some(Command::Serve(args)) = &cli.command {
        let mut config = config;
        if let Some(listen) = &args.listen {
            config.server.listen = listen.clone();
        }
        if args.tls_cert.is_some() {
            config.server.tls_cert = args.tls_cert.clone();
        }
        if args.tls_key.is_some() {
            config.server.tls_key = args.tls_key.clone();
        }
        if args.allow_remote {
            config.server.allow_remote = true;
        }
        config.save(&paths)?;
        return netcontrol_service::serve(paths, config).await;
    }
    let state = AppState::load(paths.clone(), config.clone())?;
    let ctx = Ctx {
        json: cli.json,
        yes: cli.yes,
        style,
        paths,
        config,
    };
    match cli.command.unwrap_or(Command::Dashboard) {
        Command::Dashboard => dashboard(&ctx, &state).await,
        Command::Interfaces => interfaces(&ctx).await,
        Command::Scan(args) => scan_command(&ctx, &state, args).await,
        Command::Devices(args) => devices(&ctx, &state, args).await,
        Command::Device(args) => device_command(&ctx, &state, args).await,
        Command::Monitor(args) => monitor_command(&ctx, &state, args).await,
        Command::History { device, limit } => history(&ctx, &state, device, limit).await,
        Command::Block(args) => block_command(&ctx, &state, args).await,
        Command::Unblock(args) => unblock_command(&ctx, &state, args).await,
        Command::Pause(args) => pause_command(&ctx, &state, args).await,
        Command::Limit(args) => limit_command(&ctx, &state, args).await,
        Command::Unlimit(args) => unlimit_command(&ctx, &state, args).await,
        Command::Trust(args) => trust_command(&ctx, &state, args, true).await,
        Command::Untrust(args) => trust_command(&ctx, &state, args, false).await,
        Command::Gateway(args) => gateway_command(&ctx, &state, args).await,
        Command::Config(args) => config_command(&ctx, &state, args).await,
        Command::Admin(args) => admin_command(&ctx, &state, args).await,
        Command::Interactive => interactive(&ctx, &state).await,
        Command::Serve(_) => unreachable!(),
    }
}

fn init_logging(verbose: u8) {
    let level = match verbose {
        0 => "warn",
        1 => "info",
        _ => "debug",
    };
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level)),
        )
        .with_writer(std::io::stderr)
        .without_time()
        .try_init();
}

fn status_dot(style: &Style, online: bool) -> String {
    if online {
        style.green("●")
    } else {
        style.dim("○")
    }
}

fn access_label(style: &Style, device: &Device) -> String {
    if device.is_blocked {
        style.red("blocked")
    } else if device.is_trusted {
        style.green("trusted")
    } else {
        style.dim("allowed")
    }
}

fn enforcement_note(style: &Style, device: &Device) -> String {
    match device.enforcement {
        netcontrol_core::models::EnforcementState::Applied => style.green("enforced"),
        netcontrol_core::models::EnforcementState::Failed => style.red("failed"),
        netcontrol_core::models::EnforcementState::Unsupported => style.yellow("unsupported"),
        netcontrol_core::models::EnforcementState::Pending => style.yellow("pending"),
        netcontrol_core::models::EnforcementState::Expired => style.dim("expired"),
        netcontrol_core::models::EnforcementState::None => style.dim("—"),
    }
}

fn device_table(style: &Style, items: &[Device]) -> String {
    let mut table = Table::new();
    table.load_preset(UTF8_FULL);
    table.set_content_arrangement(ContentArrangement::Dynamic);
    table.set_header(vec![
        Cell::new("").add_attribute(Attribute::Bold),
        Cell::new("Device").add_attribute(Attribute::Bold),
        Cell::new("IP").add_attribute(Attribute::Bold),
        Cell::new("MAC").add_attribute(Attribute::Bold),
        Cell::new("Vendor").add_attribute(Attribute::Bold),
        Cell::new("Type").add_attribute(Attribute::Bold),
        Cell::new("Limit").add_attribute(Attribute::Bold),
        Cell::new("Access").add_attribute(Attribute::Bold),
        Cell::new("Last seen").add_attribute(Attribute::Bold),
    ]);
    for device in items {
        let limit = match (device.limit_download_kbps, device.limit_upload_kbps) {
            (None, None) => style.dim("—"),
            (down, up) => format!(
                "↓{} ↑{}",
                down.map(format_kbps).unwrap_or_else(|| "—".into()),
                up.map(format_kbps).unwrap_or_else(|| "—".into())
            ),
        };
        table.add_row(vec![
            Cell::new(status_dot(style, device.online)),
            Cell::new(device.display_name()),
            Cell::new(device.ip.clone().unwrap_or_else(|| "—".into())),
            Cell::new(device.mac.clone().unwrap_or_else(|| "—".into())),
            Cell::new(
                device
                    .vendor
                    .clone()
                    .unwrap_or_else(|| "—".into())
                    .chars()
                    .take(28)
                    .collect::<String>(),
            ),
            Cell::new(device.category.label()),
            Cell::new(limit),
            Cell::new(access_label(style, device)),
            Cell::new(relative_time(device.last_seen.as_str())),
        ]);
    }
    table.to_string()
}

fn relative_time(ts: &str) -> String {
    let Some(parsed) = parse_ts(ts) else {
        return ts.to_string();
    };
    let seconds = (chrono::Utc::now() - parsed).num_seconds().max(0) as u64;
    if seconds < 10 {
        "just now".into()
    } else if seconds < 60 {
        format!("{seconds}s ago")
    } else if seconds < 3600 {
        format!("{}m ago", seconds / 60)
    } else if seconds < 86_400 {
        format!("{}h ago", seconds / 3600)
    } else {
        format!("{}d ago", seconds / 86_400)
    }
}

fn print_json<T: Serialize>(value: &T) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

async fn dashboard(ctx: &Ctx, state: &Arc<AppState>) -> Result<()> {
    let settings = state.settings.read().await.clone();
    let iface = InterfaceManager::choose(settings.preferred_interface.as_deref()).ok();
    let network = iface
        .as_ref()
        .and_then(|i| InterfaceManager::network_for(i).ok());
    let counts = state.db.counts()?;
    let probe = netcontrol_service::probe_active(state, false).await;
    let traffic = quick_traffic(state, network.as_ref()).await;
    let page = state.db.list_devices(&DeviceFilter {
        limit: 12,
        sort: Some("last_seen".into()),
        descending: true,
        ..Default::default()
    })?;
    let last_scan = state.db.last_scan()?;

    if ctx.json {
        return print_json(&serde_json::json!({
            "network": network,
            "interfaces": InterfaceManager::list().unwrap_or_default(),
            "counts": counts,
            "gateway": probe,
            "traffic": traffic,
            "last_scan": last_scan,
            "recent_devices": page.items,
        }));
    }

    let s = &ctx.style;
    println!();
    println!("{}", s.bold("  NetControl"));
    println!(
        "  {}",
        s.dim("authorized network discovery · monitoring · access control")
    );
    println!();
    match &network {
        Some(net) => {
            println!(
                "  {}  {}   {}",
                s.cyan("NETWORK"),
                s.bold(&net.cidr),
                net.ssid.clone().unwrap_or_default()
            );
            println!(
                "  {}  {}   {}",
                s.cyan("IFACE  "),
                iface.as_ref().map(|i| i.name.clone()).unwrap_or_default(),
                iface
                    .as_ref()
                    .map(|i| i.kind.to_string())
                    .unwrap_or_default()
            );
            println!(
                "  {}  {}   DNS {}",
                s.cyan("GATEWAY"),
                net.gateway.clone().unwrap_or_else(|| "—".into()),
                if net.dns.is_empty() {
                    "—".to_string()
                } else {
                    net.dns.join(", ")
                }
            );
        }
        None => println!("  {} no active network interface found", s.yellow("!")),
    }
    println!();
    println!(
        "  {} devices   {} online   {} offline   {} blocked   {} trusted   {} unknown",
        s.bold(&counts.total.to_string()),
        s.green(&counts.online.to_string()),
        counts.offline,
        s.red(&counts.blocked.to_string()),
        counts.trusted,
        counts.unknown
    );
    if let Some(traffic) = &traffic {
        if traffic.source == "measured" {
            println!(
                "  {} ↓ {}  ↑ {}   {}",
                s.cyan("TRAFFIC"),
                s.green(&format_bps(traffic.rx_bps)),
                s.cyan(&format_bps(traffic.tx_bps)),
                s.dim(&format!(
                    "total {} / {}",
                    format_bytes(traffic.rx_total_bytes, false),
                    format_bytes(traffic.tx_total_bytes, false)
                ))
            );
        } else {
            println!(
                "  {} {}",
                s.cyan("TRAFFIC"),
                s.dim("no live measurement yet — run `netcontrol monitor`")
            );
        }
    }
    match &probe {
        Some(probe) if probe.ok => println!(
            "  {} {}   {}   {}",
            s.cyan("GATEWAY"),
            probe.name,
            s.green("connected"),
            s.dim(&format!(
                "block={} bandwidth={}",
                probe.capabilities.block, probe.capabilities.bandwidth
            ))
        ),
        Some(probe) => println!(
            "  {} {}   {}",
            s.cyan("GATEWAY"),
            probe.name,
            s.yellow(&format!("not ready: {}", probe.message))
        ),
        None => println!(
            "  {} {}",
            s.cyan("GATEWAY"),
            s.yellow("not configured — discovery and monitoring only (see `netcontrol gateway add --help`)")
        ),
    }
    if let Some(scan) = last_scan {
        println!(
            "  {} {} on {} — {} hosts",
            s.cyan("LAST SCAN"),
            scan.started_at,
            scan.interface,
            scan.hosts_found
        );
    }
    println!();
    if page.items.is_empty() {
        println!(
            "  {}",
            s.dim("No devices yet. Run `netcontrol scan --yes`.")
        );
    } else {
        println!("{}", device_table(s, &page.items));
        if page.total > page.items.len() as u64 {
            println!(
                "  {}",
                s.dim(&format!(
                    "showing {} of {} — use `netcontrol devices`",
                    page.items.len(),
                    page.total
                ))
            );
        }
    }
    Ok(())
}

async fn quick_traffic(
    state: &Arc<AppState>,
    network: Option<&NetworkInfo>,
) -> Option<TrafficOverview> {
    let iface = network.map(|n| n.interface.clone())?;
    state.monitor.sample(&iface)?;
    tokio::time::sleep(Duration::from_millis(350)).await;
    let raw = state.monitor.sample(&iface)?;
    Some(TrafficOverview {
        interface: Some(iface),
        sampled_at: now_ts(),
        rx_bps: raw.rx_bps,
        tx_bps: raw.tx_bps,
        rx_total_bytes: raw.rx_total,
        tx_total_bytes: raw.tx_total,
        source: "measured".into(),
        per_device_supported: false,
        per_device_source: None,
    })
}

async fn interfaces(ctx: &Ctx) -> Result<()> {
    let list = tokio::task::spawn_blocking(InterfaceManager::list)
        .await
        .map_err(|e| Error::Internal(e.to_string()))??;
    if ctx.json {
        return print_json(&list);
    }
    let s = &ctx.style;
    let mut table = Table::new();
    table.load_preset(UTF8_FULL);
    table.set_header(vec![
        "",
        "Interface",
        "Type",
        "MAC",
        "IPv4",
        "Gateway",
        "SSID",
    ]);
    for iface in list {
        table.add_row(vec![
            if iface.is_default {
                s.green("★")
            } else {
                String::new()
            },
            iface.name,
            iface.kind.to_string(),
            iface.mac.unwrap_or_else(|| "—".into()),
            iface
                .ipv4
                .iter()
                .map(|v| v.cidr.clone())
                .collect::<Vec<_>>()
                .join(", "),
            iface.gateway4.unwrap_or_else(|| "—".into()),
            iface.ssid.unwrap_or_else(|| "—".into()),
        ]);
    }
    println!("{table}");
    println!("\n  {} default route", s.green("★"));
    Ok(())
}

fn confirm(ctx: &Ctx, prompt: &str) -> Result<()> {
    if ctx.yes {
        return Ok(());
    }
    if !std::io::stdin().is_terminal() {
        return Err(Error::Forbidden(format!(
            "{prompt}: refusing without --yes in a non-interactive session"
        )));
    }
    print!("{prompt} Type 'yes' to continue: ");
    std::io::stdout().flush().ok();
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    if input.trim() != "yes" {
        return Err(Error::Forbidden("operation cancelled".into()));
    }
    Ok(())
}

async fn scan_command(ctx: &Ctx, state: &Arc<AppState>, args: ScanArgs) -> Result<()> {
    let settings = state.settings.read().await.clone();
    let methods = if args.methods.is_empty() {
        settings.default_scan_methods.clone()
    } else {
        args.methods
            .iter()
            .map(|m| m.parse::<ScanMethod>())
            .collect::<Result<Vec<_>>>()?
    };
    let (iface, net) = InterfaceManager::detect_active(args.interface.as_deref())?;
    if !ctx.json {
        println!(
            "{} {}  interface {}  methods {}",
            ctx.style.cyan("scanning"),
            ctx.style.bold(&net.cidr),
            iface.name,
            methods
                .iter()
                .map(|m| m.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
        if let Some(gw) = &net.gateway {
            println!(
                "  gateway {}  ssid {}",
                gw,
                net.ssid.clone().unwrap_or_else(|| "—".into())
            );
        }
    }
    confirm(
        ctx,
        &format!(
            "This will actively probe {} on {}{}.",
            net.cidr,
            iface.name,
            if let Some(w) = &net.ssid {
                format!(" ({w})")
            } else {
                String::new()
            }
        ),
    )?;
    let opts = ScanOptions {
        interface: Some(iface.name.clone()),
        methods,
        nmap: args.nmap || settings.enable_nmap,
        ports: args.ports,
        timeout_ms: args.timeout_ms,
        max_hosts: args.max_hosts,
        mdns: !args.no_mdns && settings.enable_mdns,
        allow_public: args.allow_public,
        confirmed: true,
    };
    let outcome = netcontrol_service::run_scan(state, opts, "cli", None).await?;
    if ctx.json {
        return print_json(&outcome);
    }
    print_scan_outcome(ctx, &outcome);
    Ok(())
}

fn print_scan_outcome(ctx: &Ctx, outcome: &ScanOutcome) {
    let s = &ctx.style;
    let report = &outcome.report;
    println!();
    println!(
        "{} {} hosts on {} via {}",
        s.green("✓"),
        report.hosts.len(),
        report.cidr,
        report
            .methods_used
            .iter()
            .map(|m| m.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!(
        "  {} new device(s) · {} reminder(s)",
        outcome.new_devices,
        report.warnings.len()
    );
    for warning in &report.warnings {
        println!("  {} {}", s.yellow("!"), warning);
    }
    if !outcome.devices.is_empty() {
        println!();
        println!("{}", device_table(s, &outcome.devices));
    }
    if !outcome.report.privileged {
        println!(
            "  {}",
            s.dim("Unprivileged mode: ARP cache priming + ICMP + mDNS. Use Nmap/root for deeper probes.")
        );
    }
}

async fn devices(ctx: &Ctx, state: &Arc<AppState>, args: DevicesArgs) -> Result<()> {
    let category = match args.category {
        Some(value) => Some(value.parse::<DeviceCategory>()?),
        None => None,
    };
    let online = if args.online {
        Some(true)
    } else if args.offline {
        Some(false)
    } else {
        None
    };
    let filter = DeviceFilter {
        query: args.search,
        online,
        blocked: args.blocked.then_some(true),
        trusted: args.trusted.then_some(true),
        category,
        sort: Some(args.sort),
        descending: args.desc,
        limit: args.limit.clamp(1, 500),
        offset: args.offset,
        ..Default::default()
    };
    let page = state.db.list_devices(&filter)?;
    if ctx.json {
        return print_json(&page);
    }
    if page.items.is_empty() {
        println!("{}", ctx.style.dim("No matching devices."));
        return Ok(());
    }
    println!("{}", device_table(&ctx.style, &page.items));
    println!(
        "  {}",
        ctx.style.dim(&format!(
            "showing {} of {} devices",
            page.items.len(),
            page.total
        ))
    );
    Ok(())
}

async fn resolve_device(state: &Arc<AppState>, target: &str) -> Result<Device> {
    if let Some(device) = state.db.get_device(target)? {
        return Ok(device);
    }
    if target.parse::<std::net::IpAddr>().is_ok() {
        if let Some(device) = state.db.find_device_by_ip(target)? {
            return Ok(device);
        }
        if let Some(device) = state.db.find_device_by_mac(target)? {
            return Ok(device);
        }
    } else if let Some(device) = state.db.find_device_by_mac(target).ok().flatten() {
        return Ok(device);
    }
    let page = state.db.list_devices(&DeviceFilter {
        query: Some(target.to_string()),
        limit: 25,
        ..Default::default()
    })?;
    if page.items.len() == 1 {
        return Ok(page.items.into_iter().next().unwrap());
    }
    Err(Error::NotFound(format!(
        "no unique device matches {target:?}; use an IP, MAC or device ID"
    )))
}

async fn device_command(ctx: &Ctx, state: &Arc<AppState>, args: DeviceArgs) -> Result<()> {
    match args.command {
        DeviceCommand::Info { target } => {
            let device = resolve_device(state, &target).await?;
            let history = state.db.list_history(&device.id, 30)?;
            let traffic = state.db.latest_device_traffic(&device.id)?;
            let rules = state
                .db
                .list_access_rules(false, 200)?
                .into_iter()
                .filter(|r| r.device_id.as_deref() == Some(device.id.as_str()))
                .collect::<Vec<_>>();
            if ctx.json {
                return print_json(&serde_json::json!({
                    "device": device,
                    "history": history,
                    "traffic": traffic,
                    "access_rules": rules,
                }));
            }
            let s = &ctx.style;
            println!();
            println!("  {}", s.bold(&device.display_name()));
            println!("  {}", s.dim(&device.id));
            println!();
            println!(
                "  {:<14} {}",
                "Status",
                if device.online {
                    s.green("online")
                } else {
                    s.dim("offline")
                }
            );
            println!(
                "  {:<14} {}",
                "IP",
                device.ip.clone().unwrap_or_else(|| "—".into())
            );
            println!(
                "  {:<14} {}",
                "IPv6",
                device.ipv6.clone().unwrap_or_else(|| "—".into())
            );
            println!(
                "  {:<14} {}",
                "MAC",
                device.mac.clone().unwrap_or_else(|| "—".into())
            );
            println!(
                "  {:<14} {}",
                "Vendor",
                device.vendor.clone().unwrap_or_else(|| "—".into())
            );
            println!(
                "  {:<14} {} ({:?})",
                "Type",
                device.category.label(),
                device.category_source
            );
            println!(
                "  {:<14} {}",
                "Interface",
                device.interface.clone().unwrap_or_else(|| "—".into())
            );
            println!(
                "  {:<14} {}",
                "SSID",
                device.ssid.clone().unwrap_or_else(|| "—".into())
            );
            println!("  {:<14} {}", "First seen", device.first_seen);
            println!(
                "  {:<14} {}",
                "Last seen",
                format!(
                    "{} ({})",
                    device.last_seen,
                    relative_time(&device.last_seen)
                )
            );
            println!("  {:<14} {}", "Access", access_label(s, &device));
            println!("  {:<14} {}", "Enforcement", enforcement_note(s, &device));
            if let Some(until) = &device.blocked_until {
                println!("  {:<14} {}", "Blocked until", until);
            }
            if device.limit_download_kbps.is_some() || device.limit_upload_kbps.is_some() {
                println!(
                    "  {:<14} ↓ {}  ↑ {}",
                    "Limits",
                    device
                        .limit_download_kbps
                        .map(format_kbps)
                        .unwrap_or_else(|| "—".into()),
                    device
                        .limit_upload_kbps
                        .map(format_kbps)
                        .unwrap_or_else(|| "—".into())
                );
            }
            if let Some(traffic) = &traffic {
                println!(
                    "  {:<14} ↓ {}  ↑ {}  ({})",
                    "Traffic",
                    format_bps(traffic.rx_bps),
                    format_bps(traffic.tx_bps),
                    traffic.source
                );
            }
            if !device.open_ports.is_empty() {
                println!("  {:<14} {:?}", "Open ports", device.open_ports);
            }
            if !device.services.is_empty() {
                println!("  {:<14} {}", "Services", device.services.join(", "));
            }
            if !device.sources.is_empty() {
                println!("  {:<14} {}", "Sources", device.sources.join(", "));
            }
            if !history.is_empty() {
                println!();
                println!("  {}", s.bold("History"));
                for event in history {
                    println!(
                        "  {}  {:<12} {}",
                        event.ts,
                        event.event,
                        event.detail.unwrap_or_default()
                    );
                }
            }
            Ok(())
        }
        DeviceCommand::Rename { target, name } => {
            let device = resolve_device(state, &target).await?;
            let patch = DevicePatch {
                custom_name: Some(name.clone()),
                ..Default::default()
            };
            let updated = netcontrol_service::orchestration::patch_device(
                state, &device.id, &patch, "cli", None,
            )
            .await?;
            if ctx.json {
                return print_json(&updated);
            }
            println!(
                "{} renamed to {}",
                device.display_name(),
                ctx.style.bold(&updated.display_name())
            );
            Ok(())
        }
        DeviceCommand::Category { target, category } => {
            let device = resolve_device(state, &target).await?;
            let category = category.parse::<DeviceCategory>()?;
            let patch = DevicePatch {
                category: Some(category),
                ..Default::default()
            };
            let updated = netcontrol_service::orchestration::patch_device(
                state, &device.id, &patch, "cli", None,
            )
            .await?;
            if ctx.json {
                return print_json(&updated);
            }
            println!(
                "{} category set to {}",
                updated.display_name(),
                category.label()
            );
            Ok(())
        }
        DeviceCommand::Note { target, note } => {
            let device = resolve_device(state, &target).await?;
            let patch = DevicePatch {
                notes: Some(note),
                ..Default::default()
            };
            let updated = netcontrol_service::orchestration::patch_device(
                state, &device.id, &patch, "cli", None,
            )
            .await?;
            if ctx.json {
                return print_json(&updated);
            }
            println!("note saved for {}", updated.display_name());
            Ok(())
        }
    }
}

fn parse_duration_seconds(value: &str) -> Result<u64> {
    let raw = value.trim().to_ascii_lowercase();
    if raw.is_empty() {
        return Err(Error::Validation("empty duration".into()));
    }
    let (number, unit) = raw
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .map(|idx| (&raw[..idx], &raw[idx..]))
        .unwrap_or((&raw[..], "s"));
    let number: f64 = number
        .parse()
        .map_err(|_| Error::Validation(format!("invalid duration: {value}")))?;
    let multiplier = match unit {
        "s" | "sec" | "secs" | "seconds" => 1.0,
        "m" | "min" | "mins" | "minutes" => 60.0,
        "h" | "hr" | "hrs" | "hours" => 3600.0,
        "d" | "day" | "days" => 86_400.0,
        _ => {
            return Err(Error::Validation(format!(
                "unsupported duration unit: {unit}"
            )))
        }
    };
    let seconds = (number * multiplier).round() as u64;
    if seconds < 15 {
        return Err(Error::Validation(
            "duration must be at least 15 seconds".into(),
        ));
    }
    Ok(seconds)
}

async fn monitor_command(ctx: &Ctx, state: &Arc<AppState>, args: MonitorArgs) -> Result<()> {
    let settings = state.settings.read().await.clone();
    let iface = InterfaceManager::choose(
        args.interface
            .as_deref()
            .or(settings.preferred_interface.as_deref()),
    )?;
    if ctx.json {
        let mut ticker = tokio::time::interval(Duration::from_secs(args.interval.max(1)));
        loop {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => return Ok(()),
                _ = ticker.tick() => {
                    let _ = state.monitor.sample(&iface.name);
                    let raw = state.monitor.sample(&iface.name);
                    if let Some(raw) = raw {
                        print_json(&serde_json::json!({
                            "ts": now_ts(),
                            "interface": iface.name,
                            "rx_bps": raw.rx_bps,
                            "tx_bps": raw.tx_bps,
                            "source": "measured"
                        }))?;
                    }
                }
            }
        }
    }
    let s = &ctx.style;
    let mut ticker = tokio::time::interval(Duration::from_secs(args.interval.max(1)));
    println!(
        "{} {} — Ctrl-C to stop",
        s.bold("Monitoring"),
        iface.display()
    );
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                println!("\n{}", s.dim("monitor stopped"));
                return Ok(());
            }
            _ = ticker.tick() => {
                let raw = state.monitor.sample(&iface.name);
                let Some(raw) = raw else {
                    println!("{}", s.yellow("interface counters unavailable"));
                    continue;
                };
                print!(
                    "\r{}  ↓ {:>12}  ↑ {:>12}   total ↓ {} ↑ {}",
                    s.cyan(&now_ts()),
                    s.green(&format_bps(raw.rx_bps)),
                    s.cyan(&format_bps(raw.tx_bps)),
                    format_bytes(raw.rx_total, false),
                    format_bytes(raw.tx_total, false)
                );
                std::io::stdout().flush().ok();
            }
        }
    }
}

async fn history(
    ctx: &Ctx,
    state: &Arc<AppState>,
    device: Option<String>,
    limit: u32,
) -> Result<()> {
    if let Some(target) = device {
        let device = resolve_device(state, &target).await?;
        let history = state.db.list_history(&device.id, limit.clamp(1, 500))?;
        if ctx.json {
            return print_json(&history);
        }
        println!("History for {}", ctx.style.bold(&device.display_name()));
        for event in history {
            println!(
                "  {}  {:<14} {}",
                event.ts,
                event.event,
                event.detail.unwrap_or_default()
            );
        }
        return Ok(());
    }
    let scans = state.db.list_scans(limit.clamp(1, 200))?;
    if ctx.json {
        return print_json(&scans);
    }
    let s = &ctx.style;
    let mut table = Table::new();
    table.load_preset(UTF8_FULL);
    table.set_header(vec![
        "Started",
        "Interface",
        "CIDR",
        "Status",
        "Hosts",
        "Methods",
    ]);
    for scan in scans {
        table.add_row(vec![
            scan.started_at,
            scan.interface,
            scan.cidr,
            scan.status,
            scan.hosts_found.to_string(),
            scan.methods
                .iter()
                .map(|m| m.as_str())
                .collect::<Vec<_>>()
                .join(","),
        ]);
    }
    println!("{table}");
    println!(
        "  {}",
        s.dim("tip: netcontrol history --device <IP> for a device timeline")
    );
    Ok(())
}

async fn block_command(ctx: &Ctx, state: &Arc<AppState>, args: BlockArgs) -> Result<()> {
    let device = resolve_device(state, &args.target).await?;
    let duration = args
        .for_duration
        .as_deref()
        .map(parse_duration_seconds)
        .transpose()?;
    let when = duration
        .map(|seconds| format!(" for {}", human_duration(seconds)))
        .unwrap_or_else(|| " permanently".into());
    confirm(
        ctx,
        &format!(
            "Block {} ({}){when} through the active gateway?",
            device.display_name(),
            device.ip.clone().or(device.mac.clone()).unwrap_or_default()
        ),
    )?;
    let outcome = netcontrol_service::block_device(
        state,
        &device.id,
        AccessAction::Block,
        true,
        None,
        duration,
        args.reason.as_deref(),
        true,
        "cli",
        None,
    )
    .await?;
    print_action(ctx, &outcome.result, &outcome.device)
}

async fn pause_command(ctx: &Ctx, state: &Arc<AppState>, args: PauseArgs) -> Result<()> {
    let device = resolve_device(state, &args.target).await?;
    let seconds = parse_duration_seconds(&args.for_duration)?;
    confirm(
        ctx,
        &format!(
            "Pause internet access for {} ({}) for {}?",
            device.display_name(),
            device.ip.clone().unwrap_or_default(),
            human_duration(seconds)
        ),
    )?;
    let outcome = netcontrol_service::block_device(
        state,
        &device.id,
        AccessAction::Pause,
        true,
        None,
        Some(seconds),
        Some("paused from CLI"),
        true,
        "cli",
        None,
    )
    .await?;
    print_action(ctx, &outcome.result, &outcome.device)
}

async fn unblock_command(ctx: &Ctx, state: &Arc<AppState>, args: UnblockArgs) -> Result<()> {
    let device = resolve_device(state, &args.target).await?;
    confirm(
        ctx,
        &format!(
            "Restore access for {} ({})?",
            device.display_name(),
            device.ip.clone().url_or_empty()
        ),
    )?;
    let outcome = netcontrol_service::block_device(
        state,
        &device.id,
        AccessAction::Allow,
        false,
        None,
        None,
        None,
        true,
        "cli",
        None,
    )
    .await?;
    print_action(ctx, &outcome.result, &outcome.device)
}

trait UrlOrEmpty {
    fn url_or_empty(&self) -> String;
}

impl UrlOrEmpty for Option<String> {
    fn url_or_empty(&self) -> String {
        self.clone().unwrap_or_else(|| "—".into())
    }
}

async fn limit_command(ctx: &Ctx, state: &Arc<AppState>, args: LimitArgs) -> Result<()> {
    let device = resolve_device(state, &args.target).await?;
    let download = parse_rate_kbps(&args.download)?;
    let upload = parse_rate_kbps(&args.upload)?;
    if download.is_none() && upload.is_none() {
        return Err(Error::Validation(
            "both limits are unlimited; use `netcontrol unlimit` instead".into(),
        ));
    }
    let expiry = args
        .for_duration
        .as_deref()
        .map(parse_duration_seconds)
        .transpose()?
        .map(|seconds| {
            (chrono::Utc::now() + chrono::Duration::seconds(seconds as i64))
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        });
    confirm(
        ctx,
        &format!(
            "Apply limits to {} ({}): download {}, upload {}?",
            device.display_name(),
            device.ip.clone().unwrap_or_default(),
            download
                .map(format_kbps)
                .unwrap_or_else(|| "unlimited".into()),
            upload
                .map(format_kbps)
                .unwrap_or_else(|| "unlimited".into())
        ),
    )?;
    let outcome = netcontrol_service::set_bandwidth(
        state,
        &device.id,
        download,
        upload,
        args.priority,
        expiry.as_deref(),
        true,
        "cli",
        None,
    )
    .await?;
    print_action(ctx, &outcome.result, &outcome.device)
}

async fn unlimit_command(ctx: &Ctx, state: &Arc<AppState>, args: UnblockArgs) -> Result<()> {
    let device = resolve_device(state, &args.target).await?;
    confirm(
        ctx,
        &format!("Clear bandwidth limits for {}?", device.display_name()),
    )?;
    let outcome = netcontrol_service::clear_bandwidth(state, &device.id, true, "cli", None).await?;
    print_action(ctx, &outcome.result, &outcome.device)
}

async fn trust_command(
    ctx: &Ctx,
    state: &Arc<AppState>,
    args: TargetArgs,
    trusted: bool,
) -> Result<()> {
    let device = resolve_device(state, &args.target).await?;
    let updated = netcontrol_service::trust_device(state, &device.id, trusted, "cli", None).await?;
    if ctx.json {
        return print_json(&updated);
    }
    println!(
        "{} {}",
        if trusted { "Trusted" } else { "Untrusted" },
        ctx.style.bold(&updated.display_name())
    );
    Ok(())
}

fn print_action(ctx: &Ctx, result: &EnforcementResult, device: &Device) -> Result<()> {
    if ctx.json {
        return print_json(&serde_json::json!({ "result": result, "device": device }));
    }
    let s = &ctx.style;
    println!();
    if result.success && result.verified {
        println!(
            "{} {} — {}",
            s.green("✓ VERIFIED"),
            result.action,
            device.display_name()
        );
        println!("  {} {}", s.dim("adapter:"), result.adapter);
        println!("  {}", result.detail);
        if let Some(until) = &device.blocked_until {
            println!("  {}", s.dim(&format!("until {until}")));
        }
        if device.limit_download_kbps.is_some() || device.limit_upload_kbps.is_some() {
            println!(
                "  {} ↓ {}  ↑ {}",
                s.dim("limits:"),
                device
                    .limit_download_kbps
                    .map(format_kbps)
                    .unwrap_or_else(|| "—".into()),
                device
                    .limit_upload_kbps
                    .map(format_kbps)
                    .unwrap_or_else(|| "—".into())
            );
        }
        Ok(())
    } else if result.action == "unsupported" {
        println!("{} {}", s.yellow("UNSUPPORTED"), result.detail);
        println!(
            "  {}",
            s.dim(
                "No change was claimed. Configure an authorized gateway to enforce access control."
            )
        );
        Err(Error::Unsupported(result.detail.clone()))
    } else {
        println!("{} {}", s.red("FAILED"), result.detail);
        println!("  {}", s.dim("The device state was not changed."));
        Err(Error::Gateway(result.detail.clone()))
    }
}

fn human_duration(seconds: u64) -> String {
    if seconds % 86_400 == 0 {
        format!("{}d", seconds / 86_400)
    } else if seconds % 3600 == 0 {
        format!("{}h", seconds / 3600)
    } else if seconds % 60 == 0 {
        format!("{}m", seconds / 60)
    } else {
        format!("{seconds}s")
    }
}

async fn gateway_command(ctx: &Ctx, state: &Arc<AppState>, args: GatewayArgs) -> Result<()> {
    match args.command {
        GatewayCommand::List => {
            let gateways = state.db.list_gateways()?;
            let active = state.active_gateway_id.read().await.clone();
            if ctx.json {
                return print_json(&gateways);
            }
            if gateways.is_empty() {
                println!(
                    "{}",
                    ctx.style
                        .dim("No gateway configured. Discovery and monitoring only.")
                );
                return Ok(());
            }
            let s = &ctx.style;
            let mut table = Table::new();
            table.load_preset(UTF8_FULL);
            table.set_header(vec!["", "Name", "Kind", "Host", "Port", "Interface"]);
            for gateway in gateways {
                table.add_row(vec![
                    if active.as_deref() == Some(gateway.id.as_str()) {
                        s.green("★")
                    } else {
                        String::new()
                    },
                    gateway.name,
                    gateway.kind.to_string(),
                    gateway.host,
                    gateway.port.to_string(),
                    gateway.interface_hint.unwrap_or_else(|| "—".into()),
                ]);
            }
            println!("{table}");
            Ok(())
        }
        GatewayCommand::Status => {
            println!("{}", ctx.style.dim("probing active gateway…"));
            match netcontrol_service::probe_active(state, true).await {
                Some(probe) => {
                    if ctx.json {
                        return print_json(&probe);
                    }
                    print_probe(ctx, &probe);
                    Ok(())
                }
                None => {
                    println!(
                        "{}",
                        ctx.style.yellow("No gateway configured. NetControl can discover and monitor this network but cannot enforce access control.")
                    );
                    Err(Error::Unsupported("no gateway configured".into()))
                }
            }
        }
        GatewayCommand::Add(args) => add_gateway(ctx, state, args).await,
        GatewayCommand::Test { id } => {
            let id = match id {
                Some(id) => id,
                None => state
                    .active_gateway_id
                    .read()
                    .await
                    .clone()
                    .or_else(|| {
                        state
                            .db
                            .list_gateways()
                            .ok()?
                            .into_iter()
                            .next()
                            .map(|g| g.id)
                    })
                    .ok_or_else(|| Error::NotFound("no gateway configured".into()))?,
            };
            let probe = netcontrol_service::test_gateway(state, &id).await?;
            if ctx.json {
                return print_json(&probe);
            }
            print_probe(ctx, &probe);
            if !probe.ok {
                return Err(Error::Gateway(probe.message));
            }
            Ok(())
        }
        GatewayCommand::Connect { id } => {
            netcontrol_service::set_active_gateway(state, &id).await?;
            println!("{} gateway {} activated", ctx.style.green("✓"), id);
            Ok(())
        }
        GatewayCommand::Clients => {
            let clients = netcontrol_service::gateway_clients(state).await?;
            if ctx.json {
                return print_json(&clients);
            }
            let s = &ctx.style;
            let mut table = Table::new();
            table.load_preset(UTF8_FULL);
            table.set_header(vec!["", "IP", "MAC", "Hostname", "Vendor"]);
            for client in clients {
                table.add_row(vec![
                    if client.online {
                        s.green("●")
                    } else {
                        s.dim("○")
                    },
                    client.ip.unwrap_or_else(|| "—".into()),
                    client.mac.unwrap_or_else(|| "—".into()),
                    client.hostname.unwrap_or_else(|| "—".into()),
                    client.vendor.unwrap_or_else(|| "—".into()),
                ]);
            }
            println!("{table}");
            Ok(())
        }
        GatewayCommand::Delete { id } => {
            confirm(ctx, &format!("Delete gateway {id}?"))?;
            state.db.delete_gateway(&id)?;
            println!("{} gateway deleted", ctx.style.green("✓"));
            Ok(())
        }
    }
}

fn print_probe(ctx: &Ctx, probe: &GatewayProbe) {
    let s = &ctx.style;
    println!();
    if probe.ok {
        println!(
            "{} {} ({}) — {}ms",
            s.green("✓"),
            probe.name,
            probe.kind,
            probe.latency_ms
        );
    } else {
        println!("{} {} — {}", s.red("✗"), probe.name, probe.message);
        return;
    }
    if let Some(version) = &probe.version {
        println!("  {:<16} {}", "Version", version);
    }
    if let Some(model) = &probe.model {
        println!("  {:<16} {}", "Model", model);
    }
    let cap = |value: bool| if value { s.green("yes") } else { s.dim("no") };
    println!(
        "  {:<16} discovery={} leases={} block={} unblock={} bandwidth={} priority={}",
        "Capabilities",
        cap(probe.capabilities.discovery),
        cap(probe.capabilities.dhcp_leases),
        cap(probe.capabilities.block),
        cap(probe.capabilities.unblock),
        cap(probe.capabilities.bandwidth),
        cap(probe.capabilities.priority)
    );
    println!("  {}", probe.message);
}

async fn add_gateway(ctx: &Ctx, state: &Arc<AppState>, args: AddGatewayArgs) -> Result<()> {
    let kind: GatewayKind = args.kind.parse()?;
    let host = args.host.clone().unwrap_or_else(|| "local".to_string());
    let name = args
        .name
        .clone()
        .unwrap_or_else(|| format!("{kind} gateway"));
    let mut password = args.password.clone();
    if kind == GatewayKind::Linux {
        password = None;
    } else if args.ask_password || (password.is_none() && netcontrol_gateway::require_secret(kind))
    {
        password = Some(rpassword::prompt_password("Gateway password/API secret: ")?);
    }
    if netcontrol_gateway::require_secret(kind) && password.as_deref().unwrap_or("").is_empty() {
        return Err(Error::Validation(format!(
            "{kind} requires a password or API secret"
        )));
    }
    let input = GatewayConfigInput {
        name,
        kind,
        host,
        port: args.port,
        username: args.username,
        secret: None,
        site: args.site,
        interface_hint: args.interface,
        tls: Some(!args.no_tls),
        tls_insecure: Some(args.insecure),
        enabled: Some(true),
    };
    let sealed = password
        .as_deref()
        .filter(|p| !p.is_empty())
        .map(|p| state.key.encrypt(p))
        .transpose()?;
    let config = state.db.create_gateway(&input, sealed.as_deref())?;
    let first = state.db.list_gateways()?.len() == 1;
    if first {
        netcontrol_service::set_active_gateway(state, &config.id).await?;
    }
    state.db.audit(
        "cli",
        "create_gateway",
        Some(&config.id),
        "success",
        Some(&format!("{}", config.kind)),
        None,
    )?;
    println!(
        "{} gateway {} added{}",
        ctx.style.green("✓"),
        config.name,
        if first { " and activated" } else { "" }
    );
    println!("  test it with: netcontrol gateway test {}", config.id);
    Ok(())
}

async fn config_command(ctx: &Ctx, state: &Arc<AppState>, args: ConfigArgs) -> Result<()> {
    match args.command.unwrap_or(ConfigCommand::Show) {
        ConfigCommand::Show => {
            let settings = state.settings.read().await.clone();
            if ctx.json {
                return print_json(&serde_json::json!({
                    "paths": {
                        "config": ctx.paths.config_file,
                        "database": ctx.paths.database,
                        "master_key": ctx.paths.master_key,
                    },
                    "server": ctx.config.server,
                    "scan": ctx.config.scan,
                    "settings": settings,
                }));
            }
            let s = &ctx.style;
            println!("{}", s.bold("Paths"));
            println!("  config    {}", ctx.paths.config_file.display());
            println!("  database  {}", ctx.paths.database.display());
            println!("  key       {}", ctx.paths.master_key.display());
            println!();
            println!("{}", s.bold("Server"));
            println!("  listen       {}", ctx.config.server.listen);
            println!("  TLS          {}", ctx.config.tls_enabled());
            println!("  allow remote {}", ctx.config.server.allow_remote);
            println!();
            println!("{}", s.bold("Scan settings"));
            println!("  interval       {}s", settings.scan_interval_seconds);
            println!("  automatic scan {}", settings.auto_scan);
            println!("  preferred iface {:?}", settings.preferred_interface);
            println!("  methods        {:?}", settings.default_scan_methods);
            println!("  nmap           {}", settings.enable_nmap);
            println!("  mdns           {}", settings.enable_mdns);
            println!("  max hosts      {}", settings.max_hosts);
            println!("  retention      {} days", settings.retention_days);
            println!("  theme          {}", settings.theme);
            Ok(())
        }
        ConfigCommand::Path => {
            println!("{}", ctx.paths.config_file.display());
            Ok(())
        }
        ConfigCommand::Set { key, value } => {
            let mut settings = state.settings.read().await.clone();
            match key.as_str() {
                "scan_interval" | "scan_interval_seconds" => {
                    settings.scan_interval_seconds = value
                        .parse()
                        .map_err(|_| Error::Validation("invalid interval".into()))?;
                }
                "preferred_interface" | "interface" => {
                    settings.preferred_interface = if value == "none" || value.is_empty() {
                        None
                    } else {
                        Some(value.clone())
                    };
                }
                "auto_scan" => settings.auto_scan = parse_bool(&value)?,
                "nmap" => settings.enable_nmap = parse_bool(&value)?,
                "mdns" => settings.enable_mdns = parse_bool(&value)?,
                "theme" => settings.theme = value.clone(),
                "max_hosts" => {
                    settings.max_hosts = value
                        .parse()
                        .map_err(|_| Error::Validation("invalid max_hosts".into()))?
                }
                "retention_days" => {
                    settings.retention_days = value
                        .parse()
                        .map_err(|_| Error::Validation("invalid retention".into()))?
                }
                "notifications" => settings.notifications = parse_bool(&value)?,
                "scan_on_start" => settings.scan_on_start = parse_bool(&value)?,
                other => return Err(Error::Validation(format!("unknown setting: {other}"))),
            }
            state.db.save_settings(&settings)?;
            *state.settings.write().await = settings;
            println!("{} set {key} = {value}", ctx.style.green("✓"));
            Ok(())
        }
        ConfigCommand::Edit => {
            let editor = std::env::var("EDITOR").unwrap_or_else(|_| "nano".into());
            let status = std::process::Command::new(editor)
                .arg(&ctx.paths.config_file)
                .status()?;
            if !status.success() {
                return Err(Error::Internal("editor exited with an error".into()));
            }
            println!("config saved to {}", ctx.paths.config_file.display());
            Ok(())
        }
    }
}

fn parse_bool(value: &str) -> Result<bool> {
    match value.to_ascii_lowercase().as_str() {
        "1" | "true" | "on" | "yes" => Ok(true),
        "0" | "false" | "off" | "no" => Ok(false),
        _ => Err(Error::Validation(format!("expected on/off, got {value}"))),
    }
}

async fn admin_command(ctx: &Ctx, state: &Arc<AppState>, args: AdminArgs) -> Result<()> {
    match args.command {
        AdminCommand::Users => {
            let users = state.db.list_users()?;
            if ctx.json {
                return print_json(&users);
            }
            for user in users {
                println!(
                    "  {:<20} {:<8} {}{}",
                    user.username,
                    user.role.as_str(),
                    user.created_at,
                    if user.disabled { " (disabled)" } else { "" }
                );
            }
            Ok(())
        }
        AdminCommand::ResetPassword { username } => {
            confirm(
                ctx,
                &format!("Reset the password for local user {username} and revoke all sessions?"),
            )?;
            let user = state
                .db
                .find_user(&username)?
                .ok_or_else(|| Error::NotFound(format!("user {username}")))?;
            let password = netcontrol_core::security::generate_password();
            let hash = netcontrol_core::security::hash_password(&password)?;
            state.db.update_password(&user.id, &hash)?;
            state.db.revoke_user_sessions(&user.id)?;
            state.db.audit(
                "cli",
                "reset_password",
                Some(&user.id),
                "success",
                Some("local CLI reset"),
                None,
            )?;
            println!("{} New password for {username}:", ctx.style.green("✓"));
            println!("\n    {}\n", ctx.style.bold(&password));
            println!(
                "{}",
                ctx.style
                    .yellow("Store it now; it will not be shown again.")
            );
            Ok(())
        }
    }
}

async fn interactive(ctx: &Ctx, state: &Arc<AppState>) -> Result<()> {
    println!(
        "{} interactive mode — type {} for commands, {} to quit",
        ctx.style.bold("NetControl"),
        ctx.style.cyan("help"),
        ctx.style.cyan("quit")
    );
    loop {
        print!("{} ", ctx.style.cyan("netcontrol>"));
        std::io::stdout().flush().ok();
        let mut line = String::new();
        if std::io::stdin().read_line(&mut line)? == 0 {
            break;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }
        let result: Result<()> = match parts[0] {
            "quit" | "exit" => break,
            "help" | "?" => {
                println!(
                    "  scan | devices | info <target> | block <target> | unblock <target> | \
                     limit <target> --download 10Mbps | gateway status | dashboard | quit"
                );
                Ok(())
            }
            "scan" => {
                let args = ScanArgs {
                    interface: parts.get(1).map(|s| s.to_string()),
                    methods: Vec::new(),
                    nmap: false,
                    ports: false,
                    no_mdns: false,
                    timeout_ms: 1200,
                    max_hosts: 1024,
                    allow_public: false,
                };
                scan_command(ctx, state, args).await
            }
            "devices" => {
                devices(
                    ctx,
                    state,
                    DevicesArgs {
                        online: false,
                        offline: false,
                        blocked: false,
                        trusted: false,
                        category: None,
                        search: None,
                        limit: 50,
                        offset: 0,
                        sort: "name".into(),
                        desc: false,
                    },
                )
                .await
            }
            "dashboard" => dashboard(ctx, state).await,
            "info" => {
                let target = parts
                    .get(1)
                    .ok_or_else(|| Error::Validation("usage: info <target>".into()))?;
                device_command(
                    ctx,
                    state,
                    DeviceArgs {
                        command: DeviceCommand::Info {
                            target: target.to_string(),
                        },
                    },
                )
                .await
            }
            "block" => {
                let target = parts
                    .get(1)
                    .ok_or_else(|| Error::Validation("usage: block <target>".into()))?;
                block_command(
                    ctx,
                    state,
                    BlockArgs {
                        target: target.to_string(),
                        for_duration: None,
                        reason: None,
                    },
                )
                .await
            }
            "unblock" => {
                let target = parts
                    .get(1)
                    .ok_or_else(|| Error::Validation("usage: unblock <target>".into()))?;
                unblock_command(
                    ctx,
                    state,
                    UnblockArgs {
                        target: target.to_string(),
                    },
                )
                .await
            }
            "limit" => {
                let target = parts.get(1).ok_or_else(|| {
                    Error::Validation("usage: limit <target> --download 10Mbps".into())
                })?;
                let mut download = "unlimited".to_string();
                let mut upload = "unlimited".to_string();
                let mut i = 2;
                while i < parts.len() {
                    match parts[i] {
                        "--download" if i + 1 < parts.len() => {
                            download = parts[i + 1].to_string();
                            i += 2;
                        }
                        "--upload" if i + 1 < parts.len() => {
                            upload = parts[i + 1].to_string();
                            i += 2;
                        }
                        _ => i += 1,
                    }
                }
                limit_command(
                    ctx,
                    state,
                    LimitArgs {
                        target: target.to_string(),
                        download,
                        upload,
                        priority: None,
                        for_duration: None,
                    },
                )
                .await
            }
            "gateway" => {
                let sub = parts.get(1).copied().unwrap_or("status");
                match sub {
                    "status" => {
                        gateway_command(
                            ctx,
                            state,
                            GatewayArgs {
                                command: GatewayCommand::Status,
                            },
                        )
                        .await
                    }
                    "list" => {
                        gateway_command(
                            ctx,
                            state,
                            GatewayArgs {
                                command: GatewayCommand::List,
                            },
                        )
                        .await
                    }
                    "clients" => {
                        gateway_command(
                            ctx,
                            state,
                            GatewayArgs {
                                command: GatewayCommand::Clients,
                            },
                        )
                        .await
                    }
                    other => Err(Error::Validation(format!(
                        "unknown gateway command: {other}"
                    ))),
                }
            }
            other => Err(Error::Validation(format!("unknown command: {other}"))),
        };
        if let Err(err) = result {
            eprintln!("{} {err}", ctx.style.red("error:"));
        }
    }
    Ok(())
}

/// Remote mode is intentionally a thin client over the authenticated REST API.
/// It supports the operational commands; gateway provisioning and local
/// settings remain local-only.
async fn run_remote(cli: Cli, server: String, style: Style) -> Result<()> {
    let mut client = RemoteClient::new(server, cli.token.clone(), cli.insecure)?;
    if client.token.is_none() {
        if !std::io::stdin().is_terminal() {
            return Err(Error::Forbidden(
                "remote mode requires --token or NETCONTROL_TOKEN in a non-interactive session"
                    .into(),
            ));
        }
        let username = prompt_text("Username [admin]: ")?;
        let username = if username.trim().is_empty() {
            "admin".to_string()
        } else {
            username.trim().to_string()
        };
        let password = rpassword::prompt_password("Password: ")?;
        client.login(&username, &password).await?;
    }
    let ctx = Ctx {
        json: cli.json,
        yes: cli.yes,
        style: style.clone(),
        paths: Paths::discover()?,
        config: Config::default(),
    };
    match cli.command.unwrap_or(Command::Dashboard) {
        Command::Dashboard => {
            let value: serde_json::Value = client.get("/dashboard").await?;
            if ctx.json {
                return print_json(&value);
            }
            let dash: netcontrol_core::models::DashboardSummary = serde_json::from_value(value)?;
            print_remote_dashboard(&ctx, &dash);
            Ok(())
        }
        Command::Devices(args) => {
            if args.category.is_some() || args.search.is_some() || args.online || args.blocked || args.trusted {
                return Err(Error::Unsupported(
                    "remote filtering is not implemented; use the API or local mode".into(),
                ));
            }
            let page: netcontrol_core::models::Paged<Device> = client.get("/devices").await?;
            if ctx.json {
                return print_json(&page);
            }
            println!("{}", device_table(&ctx.style, &page.items));
            Ok(())
        }
        Command::Scan(args) => {
            confirm(&ctx, "Run a remote network scan?")?;
            let body = serde_json::json!({
                "interface": args.interface,
                "methods": args.methods,
                "nmap": args.nmap,
                "ports": args.ports,
                "confirm": true
            });
            let value: serde_json::Value = client.post("/scans", &body).await?;
            if ctx.json {
                return print_json(&value);
            }
            let devices: Vec<Device> = value
                .get("devices")
                .cloned()
                .and_then(|v| serde_json::from_value(v).ok())
                .unwrap_or_default();
            if devices.is_empty() {
                println!("{}", style.dim(&value.to_string()));
            } else {
                println!("{}", device_table(&style, &devices));
            }
            Ok(())
        }
        Command::Monitor(args) => {
            let interval = Duration::from_secs(args.interval.max(1));
            loop {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => return Ok(()),
                    _ = tokio::time::sleep(interval) => {
                        let traffic: TrafficOverview = client.get("/monitoring/overview").await?;
                        if ctx.json {
                            print_json(&traffic)?;
                        } else {
                            print!("\r{}  ↓ {:>12}  ↑ {:>12}   {}", style.cyan(&traffic.sampled_at), style.green(&format_bps(traffic.rx_bps)), style.cyan(&format_bps(traffic.tx_bps)), style.dim(&traffic.source));
                            std::io::stdout().flush().ok();
                        }
                    }
                }
            }
        }
        Command::Unblock(args) => remote_action(&ctx, &mut client, &args.target, "unblock", serde_json::json!({"confirm": true})).await,
        Command::Block(args) => remote_action(&ctx, &mut client, &args.target, "block", serde_json::json!({
            "confirm": true, "reason": args.reason,
            "duration_seconds": args.for_duration.as_deref().map(parse_duration_seconds).transpose()?
        })).await,
        Command::Pause(args) => remote_action(&ctx, &mut client, &args.target, "pause", serde_json::json!({
            "confirm": true, "duration_seconds": parse_duration_seconds(&args.for_duration)?
        })).await,
        Command::Unlimit(args) => {
            let device = remote_resolve(&mut client, &args.target).await?;
            let value: serde_json::Value = client.delete(&format!("/devices/{}/bandwidth", device.id)).await?;
            print_remote_action(&ctx, &value)
        }
        Command::Gateway(args) => match args.command {
            GatewayCommand::Status => {
                let value: serde_json::Value = client.get("/gateway/status").await?;
                if ctx.json { print_json(&value) } else { println!("{value:#}"); Ok(()) }
            }
            GatewayCommand::List => {
                let value: serde_json::Value = client.get("/gateways").await?;
                print_json(&value)
            }
            GatewayCommand::Clients => {
                let value: serde_json::Value = client.get("/gateways/active/clients").await?;
                print_json(&value)
            }
            _ => Err(Error::Unsupported("that gateway command is local-only".into())),
        },
        Command::Limit(_) | Command::Trust(_) | Command::Untrust(_) | Command::Device(_) | Command::Config(_) | Command::Admin(_) | Command::Interfaces | Command::History { .. } | Command::Serve(_) | Command::Interactive => {
            Err(Error::Unsupported("this command is not available in remote mode".into()))
        }
    }
}

async fn remote_resolve(client: &mut RemoteClient, target: &str) -> Result<Device> {
    let page: netcontrol_core::models::Paged<Device> = client
        .get(&format!("/devices?query={}&limit=25", urlencode(target)))
        .await?;
    page.items
        .into_iter()
        .find(|d| {
            d.id == target
                || d.ip.as_deref() == Some(target)
                || d.mac.as_deref() == Some(target)
                || d.hostname.as_deref() == Some(target)
        })
        .ok_or_else(|| Error::NotFound(format!("device {target} not found on the remote service")))
}

async fn remote_action(
    ctx: &Ctx,
    client: &mut RemoteClient,
    target: &str,
    action: &str,
    body: serde_json::Value,
) -> Result<()> {
    let device = remote_resolve(client, target).await?;
    confirm(
        ctx,
        &format!("{action} {} on the remote service?", device.display_name()),
    )?;
    let value: serde_json::Value = client
        .post(&format!("/devices/{}/{action}", device.id), &body)
        .await?;
    print_remote_action(ctx, &value)
}

fn print_remote_action(ctx: &Ctx, value: &serde_json::Value) -> Result<()> {
    if ctx.json {
        return print_json(value);
    }
    let result = value.get("result").cloned().unwrap_or_default();
    let success = result
        .get("verified")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let detail = result.get("detail").and_then(|v| v.as_str()).unwrap_or("");
    if success {
        println!("{} {}", ctx.style.green("✓ VERIFIED"), detail);
        Ok(())
    } else {
        println!("{} {}", ctx.style.red("NOT ENFORCED"), detail);
        Err(Error::Gateway(detail.to_string()))
    }
}

fn print_remote_dashboard(ctx: &Ctx, dash: &netcontrol_core::models::DashboardSummary) {
    let s = &ctx.style;
    println!("{}", s.bold("  NetControl — remote"));
    if let Some(net) = &dash.network {
        println!(
            "  {} {}   gateway {}   ssid {}",
            s.cyan("NETWORK"),
            net.cidr,
            net.gateway.clone().unwrap_or_else(|| "—".into()),
            net.ssid.clone().unwrap_or_else(|| "—".into())
        );
    }
    println!(
        "  {} devices   {} online   {} offline   {} blocked",
        dash.total_devices, dash.online_devices, dash.offline_devices, dash.blocked_devices
    );
    if let Some(t) = &dash.traffic {
        println!(
            "  {} ↓ {} ↑ {} ({})",
            s.cyan("TRAFFIC"),
            format_bps(t.rx_bps),
            format_bps(t.tx_bps),
            t.source
        );
    }
    println!(
        "  {} {}",
        s.cyan("ENFORCEMENT"),
        if dash.enforcement_available {
            s.green("available")
        } else {
            s.yellow("discovery/monitoring only")
        }
    );
}

fn urlencode(value: &str) -> String {
    value
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            other => format!("%{other:02X}"),
        })
        .collect()
}

fn prompt_text(prompt: &str) -> Result<String> {
    print!("{prompt}");
    std::io::stdout().flush().ok();
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    Ok(input.trim_end_matches(['\r', '\n']).to_string())
}

struct RemoteClient {
    base: String,
    token: Option<String>,
    http: reqwest::Client,
}

impl RemoteClient {
    fn new(server: String, token: Option<String>, insecure: bool) -> Result<Self> {
        let base = if server.starts_with("http://") || server.starts_with("https://") {
            server.trim_end_matches('/').to_string()
        } else {
            format!("https://{}", server.trim_end_matches('/'))
        };
        let http = reqwest::Client::builder()
            .danger_accept_invalid_certs(insecure)
            .timeout(Duration::from_secs(180))
            .build()
            .map_err(|e| Error::Internal(format!("HTTP client: {e}")))?;
        Ok(Self { base, token, http })
    }

    async fn login(&mut self, username: &str, password: &str) -> Result<()> {
        #[derive(serde::Deserialize)]
        struct Session {
            token: String,
        }
        let response = self
            .http
            .post(format!("{}/api/v1/auth/login", self.base))
            .json(&serde_json::json!({"username": username, "password": password}))
            .send()
            .await
            .map_err(|e| Error::Gateway(format!("cannot reach {}: {e}", self.base)))?;
        if !response.status().is_success() {
            return Err(Error::Forbidden("remote login failed".into()));
        }
        let session: Session = response
            .json()
            .await
            .map_err(|e| Error::Gateway(format!("invalid login response: {e}")))?;
        self.token = Some(session.token);
        Ok(())
    }

    fn request(&self, method: reqwest::Method, path: &str) -> Result<reqwest::RequestBuilder> {
        let token = self.token.as_deref().ok_or_else(|| Error::Unauthorized)?;
        Ok(self
            .http
            .request(method, format!("{}/api/v1{path}", self.base))
            .bearer_auth(token))
    }

    async fn get<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T> {
        let response = self
            .request(reqwest::Method::GET, path)?
            .send()
            .await
            .map_err(|e| Error::Gateway(format!("remote request failed: {e}")))?;
        decode(response).await
    }

    async fn post<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<T> {
        let response = self
            .request(reqwest::Method::POST, path)?
            .json(body)
            .send()
            .await
            .map_err(|e| Error::Gateway(format!("remote request failed: {e}")))?;
        decode(response).await
    }

    async fn delete<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T> {
        let response = self
            .request(reqwest::Method::DELETE, path)?
            .send()
            .await
            .map_err(|e| Error::Gateway(format!("remote request failed: {e}")))?;
        decode(response).await
    }
}

async fn decode<T: serde::de::DeserializeOwned>(response: reqwest::Response) -> Result<T> {
    let status = response.status();
    let text = response.text().await.unwrap_or_default();
    if !status.is_success() {
        let message = serde_json::from_str::<serde_json::Value>(&text)
            .ok()
            .and_then(|v| {
                v.get("error")
                    .and_then(|e| e.get("message"))
                    .and_then(|m| m.as_str())
                    .map(str::to_string)
            })
            .unwrap_or_else(|| format!("HTTP {}", status.as_u16()));
        return Err(Error::Gateway(message));
    }
    if text.trim().is_empty() {
        return serde_json::from_str("null").map_err(Error::from);
    }
    serde_json::from_str(&text)
        .map_err(|e| Error::Internal(format!("invalid remote response: {e}")))
}
