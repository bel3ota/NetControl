import { useCallback, useEffect, useState } from "react";
import {
  AlertTriangle,
  Check,
  Database,
  HardDrive,
  Loader2,
  Lock,
  RefreshCw,
  Save,
  ScanLine,
  Server,
  ShieldCheck,
  SlidersHorizontal,
} from "lucide-react";
import clsx from "clsx";
import type { AppSettings, AuditLog, DashboardSummary, SystemStatus, UserSummary } from "../types";
import { api } from "../api";
import { formatDate } from "../lib/format";
import { PageHeader } from "../components/Layout";
import { Pill, Skeleton } from "../components/ui";
import { useToast } from "../components/toast";

const METHOD_OPTIONS = [
  { id: "neighbor", label: "Neighbor table", description: "Kernel ARP/NDP cache" },
  { id: "icmp", label: "ICMP echo", description: "Unprivileged ping sweep" },
  { id: "mdns", label: "mDNS", description: "Hostnames and service discovery" },
  { id: "arp", label: "Active ARP", description: "Raw arp-scan when privileged" },
  { id: "tcp", label: "TCP probe", description: "Used for explicit port discovery" },
  { id: "nmap", label: "Nmap", description: "When an explicit scan requests it" },
];

export function Settings({
  dashboard,
  user,
}: {
  dashboard: DashboardSummary | null;
  user: UserSummary;
}) {
  const toast = useToast();
  const [settings, setSettings] = useState<AppSettings | null>(null);
  const [status, setStatus] = useState<SystemStatus | null>(null);
  const [audit, setAudit] = useState<AuditLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [dirty, setDirty] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [current, system, logs] = await Promise.all([
        api.settings(),
        api.systemStatus(),
        api.audit(80),
      ]);
      setSettings(current);
      setStatus(system);
      setAudit(logs);
      setDirty(false);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const update = <K extends keyof AppSettings>(key: K, value: AppSettings[K]) => {
    setSettings((current) => (current ? { ...current, [key]: value } : current));
    setDirty(true);
  };

  const save = async () => {
    if (!settings) return;
    setSaving(true);
    try {
      const updated = await api.saveSettings(settings);
      setSettings(updated);
      setDirty(false);
      toast.success("Settings saved", "New values apply to the shared engine.");
      await load();
    } catch (err) {
      toast.error("Could not save settings", err instanceof Error ? err.message : String(err));
    } finally {
      setSaving(false);
    }
  };

  const toggleMethod = (id: string) => {
    if (!settings) return;
    const current = settings.default_scan_methods;
    update(
      "default_scan_methods",
      current.includes(id) ? current.filter((entry) => entry !== id) : [...current, id],
    );
  };

  return (
    <div className="animate-fade-up">
      <PageHeader
        eyebrow="Configuration"
        title="Settings"
        description="Scanning, safety and retention are shared by the CLI, desktop app and any connected client. Administrative actions are audited."
        actions={
          <>
            <button className="btn-ghost" onClick={load} disabled={loading}>
              <RefreshCw size={14} className={loading ? "animate-spin" : ""} /> Reload
            </button>
            <button className="btn-primary" onClick={save} disabled={saving || !dirty}>
              {saving ? <Loader2 size={14} className="animate-spin" /> : <Save size={14} />}
              Save changes
            </button>
          </>
        }
      />

      {error && (
        <div className="mb-3 rounded-xl border border-rose/25 bg-rose/5 px-3 py-2.5 text-[11px] text-rose">
          {error}
        </div>
      )}

      {loading && !settings ? (
        <div className="grid gap-4 xl:grid-cols-2">
          <Skeleton className="h-96" />
          <Skeleton className="h-96" />
        </div>
      ) : settings ? (
        <div className="grid gap-4 xl:grid-cols-[1.25fr_.75fr]">
          <div className="space-y-4">
            <section className="panel">
              <div className="panel-header">
                <div>
                  <p className="eyebrow">Discovery</p>
                  <h3 className="mt-1 font-display text-base font-semibold text-ink">
                    Scanning behavior
                  </h3>
                </div>
                <ScanLine size={16} className="text-mint" />
              </div>
              <div className="space-y-4 p-4">
                <div className="grid gap-3 sm:grid-cols-2">
                  <div>
                    <label className="label">Preferred interface</label>
                    <select
                      className="input"
                      value={settings.preferred_interface ?? ""}
                      onChange={(event) =>
                        update("preferred_interface", event.target.value || null)
                      }
                    >
                      <option value="">Auto-detect (default route)</option>
                      {(dashboard?.interfaces ?? [])
                        .filter((iface) => !iface.is_loopback)
                        .map((iface) => (
                          <option key={iface.name} value={iface.name}>
                            {iface.name} · {iface.ipv4[0]?.cidr ?? "no IPv4"} · {iface.kind}
                          </option>
                        ))}
                    </select>
                  </div>
                  <div>
                    <label className="label">Automatic scan interval (seconds)</label>
                    <input
                      className="input"
                      type="number"
                      min={15}
                      max={86400}
                      value={settings.scan_interval_seconds}
                      onChange={(event) =>
                        update("scan_interval_seconds", Number(event.target.value))
                      }
                    />
                  </div>
                  <div>
                    <label className="label">Maximum hosts per scan</label>
                    <input
                      className="input"
                      type="number"
                      min={1}
                      max={65534}
                      value={settings.max_hosts}
                      onChange={(event) => update("max_hosts", Number(event.target.value))}
                    />
                  </div>
                  <div>
                    <label className="label">History retention (days)</label>
                    <input
                      className="input"
                      type="number"
                      min={1}
                      max={3650}
                      value={settings.retention_days}
                      onChange={(event) => update("retention_days", Number(event.target.value))}
                    />
                  </div>
                </div>

                <div className="flex items-center justify-between rounded-xl border border-line bg-raised/40 px-3 py-2.5">
                  <div>
                    <p className="text-xs font-medium text-ink">Automatic scanning</p>
                    <p className="mt-0.5 text-[10px] text-faint">
                      Periodically scan the preferred interface. The service must be running.
                    </p>
                  </div>
                  <Switch
                    checked={settings.auto_scan}
                    onChange={(value) => update("auto_scan", value)}
                  />
                </div>
                <div className="flex items-center justify-between rounded-xl border border-line bg-raised/40 px-3 py-2.5">
                  <div>
                    <p className="text-xs font-medium text-ink">Scan on service start</p>
                    <p className="mt-0.5 text-[10px] text-faint">
                      Run one authorized discovery pass when the backend starts.
                    </p>
                  </div>
                  <Switch
                    checked={settings.scan_on_start}
                    onChange={(value) => update("scan_on_start", value)}
                  />
                </div>

                <div>
                  <label className="label">Default discovery methods</label>
                  <div className="grid gap-2 sm:grid-cols-2">
                    {METHOD_OPTIONS.map((method) => {
                      const checked = settings.default_scan_methods.includes(method.id);
                      return (
                        <button
                          key={method.id}
                          type="button"
                          onClick={() => toggleMethod(method.id)}
                          className={clsx(
                            "flex items-start gap-2 rounded-xl border p-2.5 text-left transition",
                            checked
                              ? "border-mint/35 bg-mint/5"
                              : "border-line bg-raised/40 hover:border-line-strong",
                          )}
                        >
                          <span
                            className={clsx(
                              "mt-0.5 flex h-4 w-4 items-center justify-center rounded border",
                              checked
                                ? "border-mint bg-mint text-[#04120D]"
                                : "border-line-strong text-transparent",
                            )}
                          >
                            <Check size={10} strokeWidth={3} />
                          </span>
                          <span>
                            <span className="block text-[11px] font-medium text-ink">
                              {method.label}
                            </span>
                            <span className="mt-0.5 block text-[10px] text-faint">
                              {method.description}
                            </span>
                          </span>
                        </button>
                      );
                    })}
                  </div>
                </div>

                <div className="flex flex-wrap gap-4 rounded-xl border border-line bg-raised/40 px-3 py-2.5">
                  <label className="flex items-center gap-2 text-[11px] text-muted">
                    <input
                      type="checkbox"
                      checked={settings.enable_mdns}
                      onChange={(event) => update("enable_mdns", event.target.checked)}
                      className="accent-[#3FE0AE]"
                    />
                    Enable mDNS discovery
                  </label>
                  <label className="flex items-center gap-2 text-[11px] text-muted">
                    <input
                      type="checkbox"
                      checked={settings.enable_nmap}
                      onChange={(event) => update("enable_nmap", event.target.checked)}
                      className="accent-[#3FE0AE]"
                    />
                    Enable Nmap when installed
                  </label>
                  <label className="flex items-center gap-2 text-[11px] text-muted">
                    <input
                      type="checkbox"
                      checked={settings.notifications}
                      onChange={(event) => update("notifications", event.target.checked)}
                      className="accent-[#3FE0AE]"
                    />
                    Desktop notifications
                  </label>
                </div>
              </div>
            </section>

            <section className="panel">
              <div className="panel-header">
                <div>
                  <p className="eyebrow">Audit trail</p>
                  <h3 className="mt-1 font-display text-base font-semibold text-ink">
                    Recent administrative actions
                  </h3>
                </div>
                <Pill>{audit.length} entries</Pill>
              </div>
              <div className="max-h-[330px] overflow-y-auto">
                {audit.length === 0 ? (
                  <p className="px-4 py-8 text-center text-[11px] text-faint">No audit entries yet.</p>
                ) : (
                  audit.slice(0, 40).map((entry) => (
                    <div
                      key={entry.id}
                      className="flex items-start gap-3 border-b border-line/50 px-4 py-2.5 last:border-0"
                    >
                      <span
                        className={clsx(
                          "mt-1 h-1.5 w-1.5 shrink-0 rounded-full",
                          entry.outcome === "success"
                            ? "bg-success"
                            : entry.outcome === "failed"
                              ? "bg-rose"
                              : "bg-amber",
                        )}
                      />
                      <div className="min-w-0 flex-1">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="text-[11px] font-medium text-ink">{entry.action}</span>
                          <span className="text-[10px] text-faint">{entry.actor}</span>
                          {entry.target && (
                            <span className="mono text-[9px] text-faint">{entry.target.slice(0, 12)}</span>
                          )}
                          <Pill
                            tone={
                              entry.outcome === "success"
                                ? "success"
                                : entry.outcome === "failed"
                                  ? "danger"
                                  : "warning"
                            }
                          >
                            {entry.outcome}
                          </Pill>
                        </div>
                        {entry.detail && (
                          <p className="mt-0.5 truncate text-[10px] text-muted">{entry.detail}</p>
                        )}
                      </div>
                      <span className="mono shrink-0 text-[9px] text-faint">
                        {formatDate(entry.ts)}
                      </span>
                    </div>
                  ))
                )}
              </div>
            </section>
          </div>

          <div className="space-y-4">
            <section className="panel">
              <div className="panel-header">
                <div>
                  <p className="eyebrow">Runtime</p>
                  <h3 className="mt-1 font-display text-base font-semibold text-ink">
                    Service status
                  </h3>
                </div>
                <Server size={16} className="text-azure" />
              </div>
              <div className="divide-y divide-line/60">
                <Row label="Version" value={status?.version ?? "—"} />
                <Row label="Host" value={status?.hostname ?? "—"} />
                <Row label="Platform" value={status?.platform ?? "—"} />
                <Row label="Uptime" value={status ? `${Math.floor(status.uptime_seconds / 60)}m` : "—"} />
                <Row label="Listen" value={status?.listening ?? "local desktop"} />
                <Row label="TLS" value={status?.tls ? "enabled" : "loopback only"} />
                <Row label="Privileged probes" value={status?.privileged ? "available" : "unprivileged"} />
                <Row label="Database" value={status?.database ?? "—"} mono />
              </div>
            </section>

            <section className="panel p-4">
              <p className="eyebrow flex items-center gap-1.5">
                <Lock size={11} /> Security posture
              </p>
              <div className="mt-3 space-y-2.5 text-[11px] leading-relaxed text-muted">
                <div className="flex gap-2">
                  <ShieldCheck size={13} className="mt-0.5 shrink-0 text-mint" />
                  Opaque session tokens; only SHA-256 digests are persisted.
                </div>
                <div className="flex gap-2">
                  <KeyIcon />
                  Gateway credentials use AES-256-GCM with a 0600 master key.
                </div>
                <div className="flex gap-2">
                  <Database size={13} className="mt-0.5 shrink-0 text-azure" />
                  SQLite in WAL mode with versioned migrations and audit logs.
                </div>
                <div className="flex gap-2">
                  <AlertTriangle size={13} className="mt-0.5 shrink-0 text-amber" />
                  Remote API exposure requires TLS; loopback is the default.
                </div>
              </div>
            </section>

            <section className="panel p-4">
              <p className="eyebrow">Account</p>
              <div className="mt-3 flex items-center gap-3">
                <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-violet/15 font-display text-xs font-semibold text-violet">
                  {user.username.slice(0, 2).toUpperCase()}
                </div>
                <div>
                  <p className="text-xs font-medium text-ink">{user.username}</p>
                  <p className="font-mono text-[9px] uppercase tracking-wider text-faint">
                    {user.role} · local session
                  </p>
                </div>
              </div>
              <p className="mt-3 text-[10px] leading-relaxed text-faint">
                Password changes and user management are available through the authenticated API
                (`POST /auth/password`) and the `netcontrol admin` CLI command.
              </p>
            </section>

            <section className="panel p-4">
              <p className="eyebrow flex items-center gap-1.5">
                <SlidersHorizontal size={11} /> Appearance
              </p>
              <div className="mt-3 flex items-center justify-between rounded-xl border border-line bg-raised/40 px-3 py-2.5">
                <div>
                  <p className="text-xs font-medium text-ink">Dark interface</p>
                  <p className="mt-0.5 text-[10px] text-faint">Default and recommended</p>
                </div>
                <Pill tone="success">active</Pill>
              </div>
              <p className="mt-2 flex items-center gap-1.5 text-[10px] text-faint">
                <HardDrive size={11} /> Additional themes can be stored in settings for future
                clients.
              </p>
            </section>
          </div>
        </div>
      ) : null}
    </div>
  );
}

function Switch({ checked, onChange }: { checked: boolean; onChange: (value: boolean) => void }) {
  return (
    <button
      type="button"
      onClick={() => onChange(!checked)}
      className={clsx(
        "relative h-5 w-9 shrink-0 rounded-full transition",
        checked ? "bg-mint" : "bg-line-strong",
      )}
      aria-pressed={checked}
    >
      <span
        className={clsx(
          "absolute top-0.5 h-4 w-4 rounded-full bg-white transition",
          checked ? "left-[18px]" : "left-0.5",
        )}
      />
    </button>
  );
}

function Row({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex items-start justify-between gap-3 px-4 py-2.5">
      <span className="text-[10px] uppercase tracking-wider text-faint">{label}</span>
      <span className={clsx("max-w-[240px] break-all text-right text-[11px] text-ink", mono && "mono text-[9px]")}>
        {value}
      </span>
    </div>
  );
}

function KeyIcon() {
  return (
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" className="mt-0.5 shrink-0 text-violet">
      <circle cx="8" cy="8" r="4" stroke="currentColor" strokeWidth="1.7" />
      <path d="m11 11 9 9m-3-3 2-2m-5 0 2-2" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" />
    </svg>
  );
}
