import clsx from "clsx";
import {
  Activity,
  ChevronRight,
  Gauge,
  LayoutDashboard,
  LogOut,
  MonitorSmartphone,
  RefreshCw,
  Router,
  ScanLine,
  Settings2,
  Shield,
  ShieldAlert,
  ShieldBan,
  ShieldCheck,
  Wifi,
  WifiOff,
} from "lucide-react";
import type { DashboardSummary, UserSummary } from "../types";
import { relativeTime } from "../lib/format";
import { Dot, Logo } from "./ui";

export type Page = "dashboard" | "devices" | "monitoring" | "access" | "gateways" | "settings";

const NAV: Array<{ id: Page; label: string; icon: React.ComponentType<{ size?: number; className?: string }> }> = [
  { id: "dashboard", label: "Dashboard", icon: LayoutDashboard },
  { id: "devices", label: "Devices", icon: MonitorSmartphone },
  { id: "monitoring", label: "Monitoring", icon: Activity },
  { id: "access", label: "Access control", icon: ShieldBan },
  { id: "gateways", label: "Gateways", icon: Router },
  { id: "settings", label: "Settings", icon: Settings2 },
];

const TITLES: Record<Page, { title: string; subtitle: string }> = {
  dashboard: { title: "Network overview", subtitle: "Live inventory, access state and measured traffic" },
  devices: { title: "Connected devices", subtitle: "Identify, name and manage every device on your network" },
  monitoring: { title: "Network monitoring", subtitle: "Measured interface throughput and history" },
  access: { title: "Access control", subtitle: "Blocked, trusted, limited and scheduled restrictions" },
  gateways: { title: "Gateway integrations", subtitle: "Authorized enforcement through your infrastructure" },
  settings: { title: "Settings", subtitle: "Discovery, safety, retention and appearance" },
};

export function Layout({
  page,
  onNavigate,
  dashboard,
  user,
  onLogout,
  onScan,
  onRefresh,
  refreshing,
  live,
  children,
}: {
  page: Page;
  onNavigate: (page: Page) => void;
  dashboard: DashboardSummary | null;
  user: UserSummary;
  onLogout: () => void;
  onScan: () => void;
  onRefresh: () => void;
  refreshing: boolean;
  live: boolean;
  children: React.ReactNode;
}) {
  const network = dashboard?.network;
  const probe = dashboard?.gateway;
  const titled = TITLES[page];

  return (
    <div className="flex h-full min-h-screen">
      <aside className="hidden w-[236px] shrink-0 flex-col border-r border-line/80 bg-[#070C12]/90 px-3.5 py-4 lg:flex">
        <div className="flex items-center gap-2.5 px-2">
          <span className="text-mint">
            <Logo size={31} />
          </span>
          <div>
            <p className="font-display text-[15px] font-semibold leading-none tracking-[0.02em] text-ink">
              NETCONTROL
            </p>
            <p className="mt-1 font-mono text-[9px] uppercase tracking-[0.22em] text-faint">
              network authority
            </p>
          </div>
        </div>

        <div className="mt-6 px-2">
          <span className="eyebrow">Workspace</span>
        </div>
        <nav className="mt-2 flex flex-col gap-0.5">
          {NAV.map((item) => {
            const Icon = item.icon;
            return (
              <button
                key={item.id}
                onClick={() => onNavigate(item.id)}
                className={clsx("nav-item text-left", page === item.id && "nav-item-active")}
              >
                <Icon size={17} className={page === item.id ? "text-mint" : ""} />
                <span className="flex-1">{item.label}</span>
                {item.id === "access" && dashboard && dashboard.blocked_devices > 0 && (
                  <span className="rounded-md bg-rose/15 px-1.5 py-0.5 font-mono text-[10px] text-rose">
                    {dashboard.blocked_devices}
                  </span>
                )}
                {page === item.id && <ChevronRight size={13} className="text-faint" />}
              </button>
            );
          })}
        </nav>

        <div className="mt-auto flex flex-col gap-2.5 pt-5">
          <div className="rounded-xl border border-line bg-raised/60 p-3">
            <div className="flex items-center justify-between">
              <span className="eyebrow">Current network</span>
              {network ? <Dot online={network.online} pulse /> : <WifiOff size={12} className="text-faint" />}
            </div>
            {network ? (
              <>
                <div className="mt-2 flex items-center gap-1.5">
                  {network.kind === "wifi" ? (
                    <Wifi size={13} className="text-mint" />
                  ) : (
                    <MonitorSmartphone size={13} className="text-azure" />
                  )}
                  <p className="truncate text-xs font-medium text-ink">
                    {network.ssid || network.interface}
                  </p>
                </div>
                <p className="mt-1 font-mono text-[10px] text-faint">
                  {network.cidr} · {network.interface}
                </p>
                {network.gateway && (
                  <p className="mt-0.5 font-mono text-[10px] text-faint">gw {network.gateway}</p>
                )}
              </>
            ) : (
              <p className="mt-2 text-[11px] text-muted">No active IPv4 interface</p>
            )}
          </div>

          <button
            className="rounded-xl border border-line bg-raised/60 p-3 text-left transition hover:border-line-strong"
            onClick={() => onNavigate("gateways")}
          >
            <div className="flex items-center justify-between">
              <span className="eyebrow">Enforcement</span>
              {probe?.ok ? (
                <ShieldCheck size={13} className="text-success" />
              ) : (
                <ShieldAlert size={13} className="text-amber" />
              )}
            </div>
            {probe?.ok ? (
              <>
                <p className="mt-2 truncate text-xs font-medium text-ink">{probe.name}</p>
                <p className="mt-1 text-[10px] text-success">Gateway verified</p>
              </>
            ) : (
              <>
                <p className="mt-2 text-xs font-medium text-ink">Discovery only</p>
                <p className="mt-1 text-[10px] leading-relaxed text-amber/90">
                  {probe ? "Gateway not ready" : "Add a gateway to enforce"}
                </p>
              </>
            )}
          </button>

          <div className="flex items-center gap-2 rounded-xl border border-line/70 px-2.5 py-2">
            <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-violet/15 font-display text-[11px] font-semibold text-violet">
              {user.username.slice(0, 2).toUpperCase()}
            </div>
            <div className="min-w-0 flex-1">
              <p className="truncate text-[11px] font-medium text-ink">{user.username}</p>
              <p className="font-mono text-[9px] uppercase tracking-wider text-faint">
                {user.role}
              </p>
            </div>
            <button
              onClick={onLogout}
              className="rounded-md p-1 text-faint transition hover:bg-panel-2 hover:text-ink"
              title="Sign out"
            >
              <LogOut size={13} />
            </button>
          </div>
        </div>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-20 border-b border-line/70 bg-base/80 px-5 py-3 backdrop-blur-xl lg:px-7">
          <div className="flex items-center gap-4">
            <div className="flex min-w-0 items-center gap-2 lg:hidden">
              <span className="text-mint">
                <Logo size={26} />
              </span>
            </div>
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2">
                <p className="font-mono text-[9px] uppercase tracking-[0.22em] text-faint">
                  NetControl / {page}
                </p>
                <span
                  className={clsx(
                    "inline-flex items-center gap-1 rounded-full border px-1.5 py-0.5 font-mono text-[9px] uppercase tracking-wider",
                    live
                      ? "border-success/25 bg-success/10 text-success"
                      : "border-line bg-raised text-faint",
                  )}
                >
                  <span className={clsx("h-1 w-1 rounded-full", live ? "animate-pulse bg-success" : "bg-faint")} />
                  {live ? "live" : "idle"}
                </span>
              </div>
              <p className="mt-0.5 truncate text-[11px] text-muted">
                {titled.subtitle}
              </p>
            </div>

            <div className="hidden items-center gap-2 md:flex">
              {dashboard?.last_scan && (
                <span className="hidden font-mono text-[10px] text-faint xl:inline">
                  scanned {relativeTime(dashboard.last_scan.started_at)}
                </span>
              )}
              <button
                className="btn-ghost h-9 px-2.5"
                onClick={onRefresh}
                disabled={refreshing}
                title="Refresh"
              >
                <RefreshCw size={15} className={refreshing ? "animate-spin" : ""} />
              </button>
              <button className="btn-primary h-9" onClick={onScan}>
                <ScanLine size={15} />
                Scan network
              </button>
            </div>
            <button className="btn-primary h-9 px-2.5 md:hidden" onClick={onScan} title="Scan">
              <ScanLine size={15} />
            </button>
          </div>
          <div className="mt-2 flex gap-1 overflow-x-auto lg:hidden">
            {NAV.map((item) => {
              const Icon = item.icon;
              return (
                <button
                  key={item.id}
                  onClick={() => onNavigate(item.id)}
                  className={clsx(
                    "flex items-center gap-1.5 whitespace-nowrap rounded-lg px-2.5 py-1.5 text-[11px]",
                    page === item.id ? "bg-panel-2 text-ink" : "text-muted",
                  )}
                >
                  <Icon size={13} />
                  {item.label}
                </button>
              );
            })}
          </div>
        </header>

        <main className="mx-auto w-full max-w-[1560px] flex-1 px-4 py-5 lg:px-7 lg:py-6">
          {children}
        </main>

        <footer className="flex flex-wrap items-center gap-x-5 gap-y-1 border-t border-line/60 px-5 py-2.5 font-mono text-[9px] uppercase tracking-wider text-faint lg:px-7">
          <span className="inline-flex items-center gap-1.5">
            <Shield size={10} /> authorized networks only
          </span>
          <span>NetControl v0.1.0</span>
          {dashboard && (
            <>
              <span>{dashboard.total_devices} devices indexed</span>
              <span className="ml-auto inline-flex items-center gap-1.5">
                <Gauge size={10} /> {dashboard.traffic?.source === "measured" ? "measured counters" : "no live sample"}
              </span>
            </>
          )}
        </footer>
      </div>
    </div>
  );
}

export function PageHeader({
  eyebrow,
  title,
  description,
  actions,
}: {
  eyebrow?: string;
  title: string;
  description?: string;
  actions?: React.ReactNode;
}) {
  return (
    <div className="mb-4 flex flex-wrap items-end justify-between gap-3">
      <div>
        {eyebrow && <p className="eyebrow mb-1">{eyebrow}</p>}
        <h2 className="font-display text-xl font-semibold tracking-tight text-ink">{title}</h2>
        {description && <p className="mt-1 max-w-2xl text-xs leading-relaxed text-muted">{description}</p>}
      </div>
      {actions && <div className="flex items-center gap-2">{actions}</div>}
    </div>
  );
}
