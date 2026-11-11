import { useEffect, useState } from "react";
import {
  Activity,
  ArrowDownToLine,
  ArrowUpFromLine,
  CircleGauge,
  Clock3,
  Info,
  Radio,
  RefreshCw,
  Router,
  ShieldAlert,
  Wifi,
} from "lucide-react";
import type { DashboardSummary, MonitoringSample, TrafficOverview } from "../types";
import { api } from "../api";
import { formatBps, formatBytes, formatDate } from "../lib/format";
import { PageHeader } from "../components/Layout";
import { Dot, EmptyState, Pill, Skeleton, TrafficChart } from "../components/ui";

const RANGES = [
  { label: "15 minutes", minutes: 15 },
  { label: "1 hour", minutes: 60 },
  { label: "6 hours", minutes: 360 },
  { label: "24 hours", minutes: 1440 },
];

export function Monitoring({ dashboard }: { dashboard: DashboardSummary | null }) {
  const [range, setRange] = useState(60);
  const [samples, setSamples] = useState<MonitoringSample[]>([]);
  const [overview, setOverview] = useState<TrafficOverview | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [refreshTick, setRefreshTick] = useState(0);
  const interfaceName = overview?.interface ?? dashboard?.network?.interface;

  useEffect(() => {
    let active = true;
    const load = async () => {
      try {
        const [history, current] = await Promise.all([
          api.monitoringHistory(range, 2000, interfaceName ?? undefined),
          api.monitoringOverview(),
        ]);
        if (!active) return;
        setSamples(history);
        setOverview(current);
        setError(null);
      } catch (err) {
        if (active) setError(err instanceof Error ? err.message : String(err));
      } finally {
        if (active) setLoading(false);
      }
    };
    load();
    const timer = window.setInterval(load, 4000);
    return () => {
      active = false;
      window.clearInterval(timer);
    };
  }, [range, refreshTick, interfaceName]);

  const maxSample = samples.reduce(
    (acc, sample) => ({
      rx: Math.max(acc.rx, sample.rx_bps),
      tx: Math.max(acc.tx, sample.tx_bps),
    }),
    { rx: 0, tx: 0 },
  );
  const avg = samples.length
    ? {
        rx: samples.reduce((sum, sample) => sum + sample.rx_bps, 0) / samples.length,
        tx: samples.reduce((sum, sample) => sum + sample.tx_bps, 0) / samples.length,
      }
    : { rx: 0, tx: 0 };
  const perDevice = dashboard?.gateway?.capabilities.traffic_stats ?? false;
  const probe = dashboard?.gateway;

  return (
    <div className="animate-fade-up">
      <PageHeader
        eyebrow="Telemetry"
        title="Network monitoring"
        description="Every number on this page comes from measured interface counters or an authorized gateway. No synthetic or estimated series are displayed as measured."
        actions={
          <>
            <Pill tone={overview?.source === "measured" ? "success" : "warning"}>
              <span className={`h-1.5 w-1.5 rounded-full ${overview?.source === "measured" ? "bg-success" : "bg-amber"}`} />
              {overview?.source === "measured" ? "measured" : overview?.source ?? "unavailable"}
            </Pill>
            <button className="btn-ghost" onClick={() => setRefreshTick((value) => value + 1)}>
              <RefreshCw size={14} className={loading ? "animate-spin" : ""} /> Refresh
            </button>
          </>
        }
      />

      {error && (
        <div className="mb-3 rounded-xl border border-rose/25 bg-rose/5 px-3 py-2.5 text-[11px] text-rose">
          {error}
        </div>
      )}

      <div className="mb-4 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <LiveCard
          label="Download now"
          value={overview ? formatBps(overview.rx_bps) : "—"}
          detail={`avg ${formatBps(avg.rx)} · peak ${formatBps(maxSample.rx)}`}
          icon={ArrowDownToLine}
          accent="text-mint"
        />
        <LiveCard
          label="Upload now"
          value={overview ? formatBps(overview.tx_bps) : "—"}
          detail={`avg ${formatBps(avg.tx)} · peak ${formatBps(maxSample.tx)}`}
          icon={ArrowUpFromLine}
          accent="text-azure"
        />
        <LiveCard
          label="Downloaded"
          value={formatBytes(overview?.rx_total_bytes ?? 0)}
          detail="interface total since boot"
          icon={Activity}
          accent="text-violet"
        />
        <LiveCard
          label="Uploaded"
          value={formatBytes(overview?.tx_total_bytes ?? 0)}
          detail="interface total since boot"
          icon={Radio}
          accent="text-amber"
        />
      </div>

      <section className="panel mb-4">
        <div className="panel-header">
          <div>
            <p className="eyebrow">Throughput · {overview?.interface ?? dashboard?.network?.interface ?? "interface"}</p>
            <h3 className="mt-1 font-display text-base font-semibold text-ink">
              {samples.length} aggregated samples
            </h3>
          </div>
          <div className="flex items-center gap-1 rounded-xl border border-line bg-raised/50 p-0.5">
            {RANGES.map((option) => (
              <button
                key={option.minutes}
                onClick={() => setRange(option.minutes)}
                className={`rounded-lg px-2.5 py-1.5 text-[11px] transition ${
                  range === option.minutes ? "bg-panel-2 text-ink" : "text-muted hover:text-ink"
                }`}
              >
                {option.label}
              </button>
            ))}
          </div>
        </div>
        <div className="p-4">
          {loading && samples.length === 0 ? (
            <Skeleton className="h-56" />
          ) : samples.length === 0 ? (
            <EmptyState
              icon={CircleGauge}
              title="No traffic samples yet"
              description="The monitoring loop samples /proc/net/dev every three seconds while the service is running. Start the service or wait a moment."
            />
          ) : (
            <>
              <TrafficChart samples={samples} height={260} />
              <div className="mt-3 grid grid-cols-2 gap-2 border-t border-line/60 pt-3 sm:grid-cols-4">
                <MiniStat label="Samples" value={String(samples.length)} />
                <MiniStat label="Bucket" value="1 minute average" />
                <MiniStat
                  label="Last sample"
                  value={overview ? formatDate(overview.sampled_at) : "—"}
                />
                <MiniStat label="Source" value={overview?.source ?? "unavailable"} />
              </div>
            </>
          )}
        </div>
      </section>

      <div className="grid gap-4 xl:grid-cols-[1.6fr_1fr]">
        <section className="panel">
          <div className="panel-header">
            <div>
              <p className="eyebrow">Interfaces</p>
              <h3 className="mt-1 font-display text-base font-semibold text-ink">Active links</h3>
            </div>
            <Pill>{dashboard?.interfaces.length ?? 0} detected</Pill>
          </div>
          <div>
            {(dashboard?.interfaces ?? [])
              .filter((iface) => iface.is_up && !iface.is_loopback)
              .map((iface) => (
                <div
                  key={iface.name}
                  className="flex flex-wrap items-center gap-x-4 gap-y-1 border-b border-line/60 px-4 py-3 last:border-0"
                >
                  <div className="flex min-w-[180px] flex-1 items-center gap-2">
                    {iface.kind === "wifi" ? (
                      <Wifi size={14} className="text-mint" />
                    ) : (
                      <Router size={14} className="text-azure" />
                    )}
                    <span className="text-xs font-medium text-ink">{iface.name}</span>
                    {iface.is_default && <Pill tone="info">default</Pill>}
                  </div>
                  <div className="mono text-[10px] text-faint">
                    {iface.ipv4[0]?.cidr ?? "no IPv4"}
                  </div>
                  <div className="mono text-[10px] text-faint">
                    {iface.ipv4[0]?.address ?? "—"}
                  </div>
                  <div className="flex items-center gap-1.5">
                    <Dot online />
                    <span className="text-[10px] text-muted">{iface.kind.replace("_", " ")}</span>
                  </div>
                  {iface.ssid && <span className="text-[10px] text-faint">{iface.ssid}</span>}
                </div>
              ))}
          </div>
        </section>

        <section className="panel">
          <div className="panel-header">
            <div>
              <p className="eyebrow">Per-device measurement</p>
              <h3 className="mt-1 font-display text-base font-semibold text-ink">Gateway telemetry</h3>
            </div>
            {perDevice ? (
              <Pill tone="success">measured</Pill>
            ) : (
              <Pill tone="warning">unavailable</Pill>
            )}
          </div>
          <div className="p-4">
            {perDevice ? (
              <div className="flex items-start gap-2 text-[11px] leading-relaxed text-muted">
                <Info size={14} className="mt-0.5 shrink-0 text-mint" />
                <p>
                  {probe?.name} reports per-client byte counters. NetControl stores these as
                  measured gateway samples and uses them for device history. Device traffic is
                  available in each device's detail drawer.
                </p>
              </div>
            ) : (
              <div className="flex items-start gap-2 text-[11px] leading-relaxed text-muted">
                <ShieldAlert size={14} className="mt-0.5 shrink-0 text-amber" />
                <div>
                  <p>
                    {probe?.ok
                      ? "The active gateway does not expose per-client traffic counters."
                      : "No enforcement gateway is connected, so only total interface traffic is measurable."}
                  </p>
                  <p className="mt-2 text-faint">
                    NetControl will not fabricate per-device rates. Interface counters remain
                    measured and are shown above.
                  </p>
                </div>
              </div>
            )}
            <div className="mt-4 space-y-2 border-t border-line/60 pt-3 text-[10px] text-faint">
              <div className="flex items-center gap-2">
                <Clock3 size={11} /> Aggregation: one-minute averages
              </div>
              <div className="flex items-center gap-2">
                <Activity size={11} /> Sampling interval: 3 seconds
              </div>
              <div className="flex items-center gap-2">
                <Radio size={11} /> Source: /proc/net/dev and gateway API
              </div>
            </div>
          </div>
        </section>
      </div>
    </div>
  );
}

function LiveCard({
  label,
  value,
  detail,
  icon: Icon,
  accent,
}: {
  label: string;
  value: string;
  detail: string;
  icon: React.ComponentType<{ size?: number; className?: string }>;
  accent: string;
}) {
  return (
    <div className="panel flex items-start gap-3 p-4">
      <span className={`flex h-9 w-9 items-center justify-center rounded-xl border border-line bg-raised ${accent}`}>
        <Icon size={17} />
      </span>
      <div className="min-w-0">
        <p className="font-mono text-[10px] uppercase tracking-[0.15em] text-faint">{label}</p>
        <p className="mt-1 truncate font-display text-xl font-semibold leading-none text-ink">
          {value}
        </p>
        <p className="mt-1.5 truncate text-[10px] text-muted">{detail}</p>
      </div>
    </div>
  );
}

function MiniStat({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <p className="text-[9px] uppercase tracking-wider text-faint">{label}</p>
      <p className="mono mt-0.5 text-[11px] text-ink">{value}</p>
    </div>
  );
}
