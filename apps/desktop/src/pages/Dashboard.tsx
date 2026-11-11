import { useEffect, useMemo, useState } from "react";
import {
  ArrowRight,
  ArrowUpRight,
  Ban,
  CheckCircle2,
  ChevronRight,
  CircleGauge,
  Clock3,
  Globe2,
  Network,
  Radar,
  Router,
  ScanLine,
  ShieldAlert,
  ShieldCheck,
  Users,
  Wifi,
} from "lucide-react";
import type { DashboardSummary, Device, MonitoringSample } from "../types";
import { api } from "../api";
import { formatBps, formatBytes, formatDate, relativeTime, deviceName } from "../lib/format";
import { PageHeader } from "../components/Layout";
import {
  AccessBadge,
  CategoryGlyph,
  Dot,
  EmptyState,
  LimitLabel,
  Pill,
  Skeleton,
  TrafficChart,
} from "../components/ui";
import type { Page } from "../components/Layout";

export function Dashboard({
  dashboard,
  loading,
  onNavigate,
  onScan,
  onRefresh,
}: {
  dashboard: DashboardSummary | null;
  loading: boolean;
  onNavigate: (page: Page) => void;
  onScan: () => void;
  onRefresh: () => void;
}) {
  const [devices, setDevices] = useState<Device[]>([]);
  const [samples, setSamples] = useState<MonitoringSample[]>([]);
  const [historyError, setHistoryError] = useState<string | null>(null);

  const interfaceName = dashboard?.network?.interface;
  useEffect(() => {
    let active = true;
    const load = async () => {
      try {
        const [page, history] = await Promise.all([
          api.devices({ limit: 7, sort: "last_seen", order: "desc" }),
          interfaceName
            ? api.monitoringHistory(30, 400, interfaceName)
            : Promise.resolve([]),
        ]);
        if (!active) return;
        setDevices(page.items);
        setSamples(history);
        setHistoryError(null);
      } catch (err) {
        if (active) setHistoryError(err instanceof Error ? err.message : String(err));
      }
    };
    load();
    const timer = window.setInterval(load, 5000);
    return () => {
      active = false;
      window.clearInterval(timer);
    };
  }, [interfaceName]);

  const network = dashboard?.network;
  const traffic = dashboard?.traffic;
  const probe = dashboard?.gateway;
  const categorySummary = useMemo(() => {
    const counts = new Map<string, number>();
    devices.forEach((device) => counts.set(device.category, (counts.get(device.category) ?? 0) + 1));
    return [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5);
  }, [devices]);

  if (loading && !dashboard) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-40" />
        <div className="grid grid-cols-2 gap-4 xl:grid-cols-4">
          {[0, 1, 2, 3].map((key) => (
            <Skeleton key={key} className="h-28" />
          ))}
        </div>
        <div className="grid gap-4 xl:grid-cols-3">
          <Skeleton className="h-72 xl:col-span-2" />
          <Skeleton className="h-72" />
        </div>
      </div>
    );
  }

  if (!dashboard) {
    return (
      <EmptyState
        icon={ShieldAlert}
        title="Cannot load the management service"
        description="The dashboard could not be loaded. Check that the NetControl service is running and that you are signed in."
        action={
          <button className="btn-ghost" onClick={onRefresh}>
            Retry
          </button>
        }
      />
    );
  }

  return (
    <div className="animate-fade-up">
      <PageHeader
        eyebrow="Command center"
        title={
          network?.ssid ||
          (network ? (network.kind === "wifi" ? "Wi-Fi network" : "Wired network") : "No active network")
        }
        description={
          network
            ? `${network.cidr} · ${network.interface} · gateway ${network.gateway ?? "unknown"}`
            : "Connect to Wi-Fi or Ethernet to begin discovery."
        }
        actions={
          <>
            {dashboard.enforcement_available ? (
              <Pill tone="success">
                <ShieldCheck size={11} /> Enforcement active
              </Pill>
            ) : (
              <Pill tone="warning">
                <ShieldAlert size={11} /> Discovery only
              </Pill>
            )}
            <button className="btn-primary" onClick={onScan}>
              <ScanLine size={15} /> Scan
            </button>
          </>
        }
      />

      <section className="panel relative mb-4 overflow-hidden">
        <div className="absolute inset-0 bg-grid-fade opacity-30" style={{ backgroundSize: "46px 46px" }} />
        <div className="absolute -right-24 -top-24 h-80 w-80 rounded-full border border-mint/10" />
        <div className="absolute -right-10 -top-10 h-56 w-56 rounded-full border border-mint/15" />
        <div className="relative grid gap-6 p-5 lg:grid-cols-[1.6fr_1fr] lg:p-6">
          <div>
            <div className="flex flex-wrap items-center gap-2">
              <span className="eyebrow">Current network</span>
              {network && <Dot online={network.online} pulse />}
              <span className="font-mono text-[10px] text-faint">
                {network ? `${network.kind} · ${network.local_ip}` : "offline"}
              </span>
            </div>
            <h2 className="mt-2 font-display text-3xl font-semibold tracking-tight text-ink">
              {network?.ssid ||
                (network ? (network.kind === "wifi" ? "Wi-Fi network" : "Wired network") : "No interface")}
            </h2>
            <div className="mt-4 flex flex-wrap gap-x-7 gap-y-3">
              <Metric icon={Network} label="Subnet" value={network?.cidr ?? "-"} />
              <Metric icon={Router} label="Gateway" value={network?.gateway ?? "-"} />
              <Metric icon={Globe2} label="DNS" value={network?.dns.join(", ") || "-"} />
              <Metric
                icon={Clock3}
                label="Last scan"
                value={dashboard.last_scan ? relativeTime(dashboard.last_scan.started_at) : "never"}
              />
            </div>

            <div className="mt-6 flex flex-wrap items-center gap-2">
              <button className="btn-ghost" onClick={() => onNavigate("devices")}>
                <Users size={14} /> Open device inventory
              </button>
              <button className="btn-ghost" onClick={() => onNavigate("monitoring")}>
                <CircleGauge size={14} /> Live monitoring
              </button>
              {!dashboard.enforcement_available && (
                <button className="btn-ghost border-amber/25 text-amber" onClick={() => onNavigate("gateways")}>
                  <ShieldAlert size={14} /> Connect a gateway
                </button>
              )}
            </div>
          </div>

          <div className="relative min-h-[170px]">
            <div className="absolute inset-0 flex items-center justify-center">
              <div className="relative flex h-44 w-44 items-center justify-center rounded-full border border-mint/15">
                <div className="absolute h-32 w-32 rounded-full border border-mint/20" />
                <div className="absolute h-20 w-20 rounded-full border border-mint/30" />
                <div className="absolute h-full w-full animate-sweep rounded-full border-t border-mint/50" />
                <div className="relative flex h-12 w-12 items-center justify-center rounded-full border border-mint/40 bg-mint/10 text-mint">
                  <Radar size={21} />
                </div>
                {categorySummary.slice(0, 5).map(([category], index) => {
                  const angle = (index / Math.max(categorySummary.length, 1)) * Math.PI * 2 - Math.PI / 3;
                  const radius = 66;
                  return (
                    <span
                      key={category}
                      className="absolute h-2 w-2 rounded-full bg-mint shadow-[0_0_10px_rgba(63,224,174,.9)]"
                      style={{
                        transform: `translate(${Math.cos(angle) * radius}px, ${Math.sin(angle) * radius}px)`,
                      }}
                    />
                  );
                })}
              </div>
            </div>
            <div className="absolute bottom-0 right-0 text-right">
              <p className="font-mono text-[10px] uppercase tracking-widest text-faint">Monitored</p>
              <p className="font-display text-2xl font-semibold text-ink">
                {dashboard.online_devices}
                <span className="ml-1 text-sm text-faint">online</span>
              </p>
            </div>
          </div>
        </div>
      </section>

      <div className="mb-4 grid grid-cols-2 gap-3 xl:grid-cols-4">
        <Stat
          label="Devices indexed"
          value={dashboard.total_devices}
          hint={`${dashboard.unknown_devices} awaiting identification`}
          icon={Network}
          accent="text-azure"
          onClick={() => onNavigate("devices")}
        />
        <Stat
          label="Online now"
          value={dashboard.online_devices}
          hint={`${dashboard.offline_devices} offline retained`}
          icon={Wifi}
          accent="text-success"
          onClick={() => onNavigate("devices")}
        />
        <Stat
          label="Blocked"
          value={dashboard.blocked_devices}
          hint={
            dashboard.blocked_devices > 0
              ? "Verified by gateway"
              : dashboard.enforcement_available
                ? "No active restrictions"
                : "Requires a gateway"
          }
          icon={Ban}
          accent="text-rose"
          onClick={() => onNavigate("access")}
        />
        <Stat
          label="Trusted"
          value={dashboard.trusted_devices}
          hint="Protected from accidental actions"
          icon={ShieldCheck}
          accent="text-mint"
          onClick={() => onNavigate("access")}
        />
      </div>

      <div className="mb-4 grid gap-4 xl:grid-cols-[1.7fr_1fr]">
        <section className="panel">
          <div className="panel-header">
            <div>
              <p className="eyebrow">Measured throughput</p>
              <h3 className="mt-1 font-display text-base font-semibold text-ink">
                Interface traffic
              </h3>
            </div>
            <div className="flex items-center gap-4">
              <div className="text-right">
                <p className="eyebrow">Download</p>
                <p className="mono text-sm text-mint">{formatBps(traffic?.rx_bps ?? 0)}</p>
              </div>
              <div className="text-right">
                <p className="eyebrow">Upload</p>
                <p className="mono text-sm text-azure">{formatBps(traffic?.tx_bps ?? 0)}</p>
              </div>
            </div>
          </div>
          <div className="px-4 pb-4 pt-3">
            <TrafficChart samples={samples} height={200} />
            <div className="mt-3 flex flex-wrap items-center justify-between gap-2 border-t border-line/60 pt-3 text-[10px] text-faint">
              <span className="inline-flex items-center gap-1.5">
                <Dot online={traffic?.source === "measured"} />
                {traffic?.source === "measured"
                  ? `measured on ${traffic.interface ?? "interface"}`
                  : traffic?.source === "gateway"
                    ? "measured through gateway"
                    : "no live measurement"}
              </span>
              <span className="mono">
                total ↓ {formatBytes(traffic?.rx_total_bytes ?? 0)} · ↑{" "}
                {formatBytes(traffic?.tx_total_bytes ?? 0)}
              </span>
            </div>
            {historyError && <p className="mt-2 text-[10px] text-rose">{historyError}</p>}
          </div>
        </section>

        <section className="panel flex flex-col">
          <div className="panel-header">
            <div>
              <p className="eyebrow">Authorized enforcement</p>
              <h3 className="mt-1 font-display text-base font-semibold text-ink">Gateway</h3>
            </div>
            {probe?.ok ? (
              <Pill tone="success">
                <CheckCircle2 size={11} /> connected
              </Pill>
            ) : (
              <Pill tone="warning">{probe ? "not ready" : "not configured"}</Pill>
            )}
          </div>
          <div className="flex flex-1 flex-col p-4">
            {probe ? (
              <>
                <div className="flex items-start gap-2.5">
                  <span className="flex h-9 w-9 items-center justify-center rounded-xl border border-line bg-raised text-mint">
                    <Router size={17} />
                  </span>
                  <div className="min-w-0">
                    <p className="truncate text-sm font-medium text-ink">{probe.name}</p>
                    <p className="font-mono text-[10px] uppercase tracking-wider text-faint">
                      {probe.kind} {probe.version ? `· ${probe.version}` : ""}
                    </p>
                  </div>
                </div>
                <p className="mt-3 text-[11px] leading-relaxed text-muted">{probe.message}</p>
                <div className="mt-4 grid grid-cols-2 gap-2">
                  <Capability label="Block" ok={probe.capabilities.block} />
                  <Capability label="Unblock" ok={probe.capabilities.unblock} />
                  <Capability label="Bandwidth" ok={probe.capabilities.bandwidth} />
                  <Capability label="Leases" ok={probe.capabilities.dhcp_leases} />
                </div>
              </>
            ) : (
              <div className="flex flex-1 flex-col justify-center py-3 text-center">
                <span className="mx-auto flex h-10 w-10 items-center justify-center rounded-xl border border-amber/25 bg-amber/5 text-amber">
                  <ShieldAlert size={19} />
                </span>
                <p className="mt-3 text-xs font-medium text-ink">Discovery and monitoring only</p>
                <p className="mt-1 text-[11px] leading-relaxed text-muted">
                  NetControl never claims a block without an authorized gateway confirming it.
                </p>
              </div>
            )}
            <div className="mt-auto flex items-center justify-between border-t border-line/60 pt-3">
              <span className="text-[10px] text-faint">
                {probe?.latency_ms ? `probe ${probe.latency_ms}ms` : "no probe cached"}
              </span>
              <button
                className="inline-flex items-center gap-1 text-[11px] font-medium text-mint hover:underline"
                onClick={() => onNavigate("gateways")}
              >
                Manage <ArrowRight size={12} />
              </button>
            </div>
          </div>
        </section>
      </div>

      <section className="panel">
        <div className="panel-header">
          <div>
            <p className="eyebrow">Recently observed</p>
            <h3 className="mt-1 font-display text-base font-semibold text-ink">Devices</h3>
          </div>
          <button
            className="inline-flex items-center gap-1 text-[11px] font-medium text-mint hover:underline"
            onClick={() => onNavigate("devices")}
          >
            All devices <ChevronRight size={13} />
          </button>
        </div>
        {devices.length === 0 ? (
          <EmptyState
            icon={ScanLine}
            title="No devices discovered yet"
            description="Run an authorized scan to populate the inventory. ARP, ICMP, mDNS and optional Nmap results are merged into one device record."
            action={
              <button className="btn-primary" onClick={onScan}>
                <ScanLine size={15} /> Scan network
              </button>
            }
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[760px]">
              <thead>
                <tr className="border-b border-line/70">
                  <th className="table-header px-4 py-2.5">Device</th>
                  <th className="table-header px-4 py-2.5">Address</th>
                  <th className="table-header px-4 py-2.5">Type</th>
                  <th className="table-header px-4 py-2.5">Limit</th>
                  <th className="table-header px-4 py-2.5">Access</th>
                  <th className="table-header px-4 py-2.5 text-right">Last seen</th>
                </tr>
              </thead>
              <tbody>
                {devices.map((device) => (
                  <tr
                    key={device.id}
                    className="group cursor-pointer border-b border-line/50 last:border-0 hover:bg-panel-2/50"
                    onClick={() => onNavigate("devices")}
                  >
                    <td className="px-4 py-2.5">
                      <div className="flex items-center gap-2.5">
                        <CategoryGlyph category={device.category} />
                        <div className="min-w-0">
                          <div className="flex items-center gap-1.5">
                            <Dot online={device.online} />
                            <span className="truncate text-xs font-medium text-ink">
                              {deviceName(device)}
                            </span>
                          </div>
                          <p className="mt-0.5 max-w-[220px] truncate text-[10px] text-faint">
                            {device.vendor || "Vendor unknown"}
                          </p>
                        </div>
                      </div>
                    </td>
                    <td className="px-4 py-2.5">
                      <p className="mono text-[11px] text-ink">{device.ip || "-"}</p>
                      <p className="mono mt-0.5 text-[10px] text-faint">{device.mac || "-"}</p>
                    </td>
                    <td className="px-4 py-2.5">
                      <Pill>{device.category.replace("_", " ")}</Pill>
                    </td>
                    <td className="px-4 py-2.5">
                      <LimitLabel down={device.limit_download_kbps} up={device.limit_upload_kbps} />
                    </td>
                    <td className="px-4 py-2.5">
                      <AccessBadge blocked={device.is_blocked} trusted={device.is_trusted} />
                    </td>
                    <td className="px-4 py-2.5 text-right">
                      <span className="text-[10px] text-faint">{relativeTime(device.last_seen)}</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <div className="mt-4 flex flex-wrap items-center justify-between gap-2 px-1 text-[10px] text-faint">
        <span>
          {dashboard.last_scan
            ? `Last scan ${formatDate(dashboard.last_scan.started_at)} · ${dashboard.last_scan.hosts_found} hosts · ${dashboard.last_scan.methods.join(", ")}`
            : "No scan recorded"}
        </span>
        <button className="inline-flex items-center gap-1 hover:text-mint" onClick={onRefresh}>
          refresh snapshot <ArrowUpRight size={11} />
        </button>
      </div>
    </div>
  );
}

function Metric({
  icon: Icon,
  label,
  value,
}: {
  icon: React.ComponentType<{ size?: number; className?: string }>;
  label: string;
  value: string;
}) {
  return (
    <div className="min-w-[110px]">
      <p className="eyebrow flex items-center gap-1.5">
        <Icon size={11} /> {label}
      </p>
      <p className="mt-1 max-w-[240px] truncate mono text-[11px] text-ink">{value}</p>
    </div>
  );
}

function Capability({ label, ok }: { label: string; ok: boolean }) {
  return (
    <div className="rounded-lg border border-line bg-raised/50 px-2.5 py-2">
      <p className="text-[10px] text-faint">{label}</p>
      <p className={`mt-0.5 text-[11px] font-medium ${ok ? "text-success" : "text-faint"}`}>
        {ok ? "supported" : "unavailable"}
      </p>
    </div>
  );
}

function Stat({
  label,
  value,
  hint,
  icon: Icon,
  accent,
  onClick,
}: {
  label: string;
  value: number;
  hint: string;
  icon: React.ComponentType<{ size?: number; className?: string }>;
  accent: string;
  onClick?: () => void;
}) {
  return (
    <button
      onClick={onClick}
      className="panel group flex items-start gap-3 p-4 text-left transition hover:border-line-strong"
    >
      <span className={`flex h-9 w-9 items-center justify-center rounded-xl border border-line bg-raised ${accent}`}>
        <Icon size={17} />
      </span>
      <div className="min-w-0 flex-1">
        <p className="font-mono text-[10px] uppercase tracking-[0.15em] text-faint">{label}</p>
        <p className="mt-0.5 font-display text-2xl font-semibold leading-none text-ink">{value}</p>
        <p className="mt-1.5 truncate text-[10px] text-muted">{hint}</p>
      </div>
      <ArrowUpRight
        size={13}
        className="text-faint opacity-0 transition group-hover:opacity-100"
      />
    </button>
  );
}
