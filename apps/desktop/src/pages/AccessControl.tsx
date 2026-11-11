import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Clock3,
  Gauge,
  History,
  RefreshCw,
  ShieldCheck,
  ShieldOff,
  ShieldX,
} from "lucide-react";
import clsx from "clsx";
import type { AccessRule, BandwidthRule, DashboardSummary, Device } from "../types";
import { api } from "../api";
import { deviceName, formatDate, formatKbps, relativeTime } from "../lib/format";
import { PageHeader } from "../components/Layout";
import {
  AccessBadge,
  CategoryGlyph,
  ConfirmDialog,
  Dot,
  EmptyState,
  EnforcementBadge,
  LimitLabel,
  Pill,
  Skeleton,
} from "../components/ui";
import { useToast } from "../components/toast";

type Tab = "blocked" | "trusted" | "limits" | "rules";

export function AccessControl({
  dashboard,
  onChanged,
}: {
  dashboard: DashboardSummary | null;
  onChanged: () => void;
}) {
  const toast = useToast();
  const [tab, setTab] = useState<Tab>("blocked");
  const [devices, setDevices] = useState<Device[]>([]);
  const [rules, setRules] = useState<AccessRule[]>([]);
  const [bandwidth, setBandwidth] = useState<BandwidthRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [confirm, setConfirm] = useState<
    | { type: "unblock" | "untrust" | "clear"; device: Device }
    | null
  >(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [all, access, limits] = await Promise.all([
        api.devices({ limit: 500, sort: "name" }),
        api.accessRules(),
        api.bandwidthRules(),
      ]);
      setDevices(all.items);
      setRules(access);
      setBandwidth(limits);
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

  const names = useMemo(() => {
    const map = new Map<string, Device>();
    devices.forEach((device) => map.set(device.id, device));
    return map;
  }, [devices]);

  const blocked = devices.filter((device) => device.is_blocked);
  const trusted = devices.filter((device) => device.is_trusted);
  const limited = devices.filter(
    (device) => device.limit_download_kbps !== null || device.limit_upload_kbps !== null,
  );
  const tabs: Array<{ id: Tab; label: string; count: number }> = [
    { id: "blocked", label: "Blocked", count: blocked.length },
    { id: "trusted", label: "Trusted", count: trusted.length },
    { id: "limits", label: "Limits", count: limited.length },
    { id: "rules", label: "Rule history", count: rules.length },
  ];

  const act = async () => {
    if (!confirm) return;
    setBusy(true);
    try {
      if (confirm.type === "unblock") {
        const result = await api.unblock(confirm.device.id);
        if (result.result.verified) {
          toast.success("Access restored", result.result.detail);
        } else {
          toast.error("Not enforced", result.result.detail);
        }
      } else if (confirm.type === "untrust") {
        await api.trust(confirm.device.id, false);
        toast.success("Trust removed", deviceName(confirm.device));
      } else {
        const result = await api.clearLimit(confirm.device.id);
        if (result.result.verified) {
          toast.success("Limits cleared", result.result.detail);
        } else {
          toast.error("Not enforced", result.result.detail);
        }
      }
      setConfirm(null);
      await load();
      onChanged();
    } catch (err) {
      toast.error("Operation failed", err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="animate-fade-up">
      <PageHeader
        eyebrow="Policy"
        title="Access control"
        description="Only verified gateway state is shown as enforced. Every disruptive action is confirmed and written to the audit log."
        actions={
          <>
            <button className="btn-ghost" onClick={load} disabled={loading}>
              <RefreshCw size={14} className={loading ? "animate-spin" : ""} /> Refresh
            </button>
            {!dashboard?.enforcement_available && (
              <Pill tone="warning">
                <ShieldX size={11} /> discovery only
              </Pill>
            )}
          </>
        }
      />

      {error && (
        <div className="mb-3 rounded-xl border border-rose/25 bg-rose/5 px-3 py-2.5 text-[11px] text-rose">
          {error}
        </div>
      )}

      <div className="mb-3 flex flex-wrap gap-1 rounded-xl border border-line bg-raised/40 p-1">
        {tabs.map((entry) => (
          <button
            key={entry.id}
            onClick={() => setTab(entry.id)}
            className={clsx(
              "flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-[11px] font-medium transition",
              tab === entry.id ? "bg-panel-2 text-ink" : "text-muted hover:text-ink",
            )}
          >
            {entry.label}
            <span
              className={clsx(
                "rounded px-1 font-mono text-[9px]",
                tab === entry.id ? "bg-mint/15 text-mint" : "bg-raised text-faint",
              )}
            >
              {entry.count}
            </span>
          </button>
        ))}
      </div>

      <section className="panel overflow-hidden">
        {loading && devices.length === 0 ? (
          <div className="space-y-2 p-4">
            {Array.from({ length: 6 }).map((_, index) => (
              <Skeleton key={index} className="h-12" />
            ))}
          </div>
        ) : tab === "blocked" ? (
          blocked.length === 0 ? (
            <EmptyState
              icon={ShieldCheck}
              title="No blocked devices"
              description={
                dashboard?.enforcement_available
                  ? "Block a device from the inventory to restrict its access through the active gateway."
                  : "No enforcement gateway is configured. Discovery and monitoring remain available, but blocking cannot be applied or verified."
              }
            />
          ) : (
            <DeviceList devices={blocked} actionLabel="Restore access" actionIcon={ShieldCheck} onAction={(device) => setConfirm({ type: "unblock", device })} />
          )
        ) : tab === "trusted" ? (
          trusted.length === 0 ? (
            <EmptyState
              icon={ShieldCheck}
              title="No trusted devices"
              description="Trusted devices are highlighted in the inventory. A trusted device can still be blocked by an explicit administrative action."
            />
          ) : (
            <DeviceList devices={trusted} actionLabel="Remove trust" actionIcon={ShieldOff} onAction={(device) => setConfirm({ type: "untrust", device })} />
          )
        ) : tab === "limits" ? (
          limited.length === 0 ? (
            <EmptyState
              icon={Gauge}
              title="No bandwidth limits applied"
              description="Apply per-device limits from the device inventory. Limits are only shown after the gateway confirms them."
            />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[760px]">
                <thead>
                  <tr className="border-b border-line/70">
                    <th className="table-header px-4 py-3">Device</th>
                    <th className="table-header px-4 py-3">Download</th>
                    <th className="table-header px-4 py-3">Upload</th>
                    <th className="table-header px-4 py-3">Priority</th>
                    <th className="table-header px-4 py-3">Expires</th>
                    <th className="table-header px-4 py-3">Enforcement</th>
                    <th className="table-header px-4 py-3 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {limited.map((device) => (
                    <tr key={device.id} className="border-b border-line/50 last:border-0">
                      <td className="px-4 py-2.5">
                        <DeviceCell device={device} />
                      </td>
                      <td className="mono px-4 py-2.5 text-[11px] text-mint">
                        {formatKbps(device.limit_download_kbps)}
                      </td>
                      <td className="mono px-4 py-2.5 text-[11px] text-azure">
                        {formatKbps(device.limit_upload_kbps)}
                      </td>
                      <td className="px-4 py-2.5 text-[11px] text-muted">
                        {device.priority ?? "-"}
                      </td>
                      <td className="px-4 py-2.5 text-[10px] text-faint">
                        {device.limit_expires_at ? formatDate(device.limit_expires_at) : "no expiry"}
                      </td>
                      <td className="px-4 py-2.5">
                        <EnforcementBadge state={device.enforcement} />
                      </td>
                      <td className="px-4 py-2.5 text-right">
                        <button
                          className="btn-danger h-7 px-2 text-[10px]"
                          onClick={() => setConfirm({ type: "clear", device })}
                        >
                          Clear limits
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )
        ) : rules.length === 0 ? (
          <EmptyState
            icon={History}
            title="No rule history"
            description="Access and bandwidth operations are recorded here with their verification state."
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[900px]">
              <thead>
                <tr className="border-b border-line/70">
                  <th className="table-header px-4 py-3">Time</th>
                  <th className="table-header px-4 py-3">Action</th>
                  <th className="table-header px-4 py-3">Target</th>
                  <th className="table-header px-4 py-3">State</th>
                  <th className="table-header px-4 py-3">Actor</th>
                  <th className="table-header px-4 py-3">Detail</th>
                </tr>
              </thead>
              <tbody>
                {rules.slice(0, 80).map((rule) => {
                  const device = rule.device_id ? names.get(rule.device_id) : undefined;
                  return (
                    <tr key={rule.id} className="border-b border-line/50 last:border-0">
                      <td className="mono px-4 py-2.5 text-[10px] text-faint">
                        {formatDate(rule.created_at)}
                      </td>
                      <td className="px-4 py-2.5">
                        <Pill tone={rule.action === "allow" ? "success" : rule.action === "pause" ? "warning" : "danger"}>
                          {rule.action}
                        </Pill>
                      </td>
                      <td className="px-4 py-2.5">
                        <p className="text-[11px] text-ink">
                          {device ? deviceName(device) : rule.ip || rule.mac || "unknown"}
                        </p>
                        <p className="mono text-[9px] text-faint">{rule.ip || rule.mac || "-"}</p>
                      </td>
                      <td className="px-4 py-2.5">
                        <EnforcementBadge state={rule.state} />
                      </td>
                      <td className="px-4 py-2.5 text-[10px] text-muted">{rule.created_by || "system"}</td>
                      <td className="max-w-[280px] px-4 py-2.5">
                        <p className="truncate text-[10px] text-faint" title={rule.last_error || ""}>
                          {rule.last_error || "-"}
                        </p>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {bandwidth.length > 0 && tab === "rules" && (
        <p className="mt-3 px-1 text-[10px] text-faint">
          {bandwidth.length} bandwidth rule records are retained separately in the audit database.
        </p>
      )}

      <ConfirmDialog
        open={confirm !== null}
        title={
          confirm?.type === "unblock"
            ? "Restore access"
            : confirm?.type === "untrust"
              ? "Remove trusted status"
              : "Clear bandwidth limits"
        }
        description={
          confirm
            ? `${confirm.type === "unblock" ? "Unblock" : confirm.type === "untrust" ? "Untrust" : "Clear limits for"} ${deviceName(confirm.device)}?`
            : ""
        }
        confirmLabel={confirm?.type === "unblock" ? "Restore access" : confirm?.type === "untrust" ? "Remove trust" : "Clear limits"}
        danger={confirm?.type !== "unblock"}
        busy={busy}
        onCancel={() => setConfirm(null)}
        onConfirm={act}
      >
        <p className="text-[11px] leading-relaxed text-muted">
          {confirm?.type === "untrust"
            ? "Trusted status only affects presentation and safeguards; it does not change gateway rules."
            : "The active gateway must confirm the change before the device state is updated."}
        </p>
      </ConfirmDialog>
    </div>
  );
}

function DeviceCell({ device }: { device: Device }) {
  return (
    <div className="flex items-center gap-2.5">
      <CategoryGlyph category={device.category} />
      <div className="min-w-0">
        <div className="flex items-center gap-1.5">
          <Dot online={device.online} />
          <span className="max-w-[220px] truncate text-xs font-medium text-ink">{deviceName(device)}</span>
        </div>
        <p className="mono mt-0.5 text-[10px] text-faint">{device.ip || device.mac || "-"}</p>
      </div>
    </div>
  );
}

function DeviceList({
  devices,
  actionLabel,
  actionIcon: ActionIcon,
  onAction,
}: {
  devices: Device[];
  actionLabel: string;
  actionIcon: React.ComponentType<{ size?: number }>;
  onAction: (device: Device) => void;
}) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[780px]">
        <thead>
          <tr className="border-b border-line/70">
            <th className="table-header px-4 py-3">Device</th>
            <th className="table-header px-4 py-3">Address</th>
            <th className="table-header px-4 py-3">Access</th>
            <th className="table-header px-4 py-3">Limits</th>
            <th className="table-header px-4 py-3">Since</th>
            <th className="table-header px-4 py-3 text-right">Actions</th>
          </tr>
        </thead>
        <tbody>
          {devices.map((device) => (
            <tr key={device.id} className="border-b border-line/50 last:border-0">
              <td className="px-4 py-2.5">
                <DeviceCell device={device} />
              </td>
              <td className="px-4 py-2.5">
                <p className="mono text-[11px] text-ink">{device.ip || "-"}</p>
                <p className="mono text-[9px] text-faint">{device.mac || "-"}</p>
              </td>
              <td className="px-4 py-2.5">
                <AccessBadge blocked={device.is_blocked} trusted={device.is_trusted} />
              </td>
              <td className="px-4 py-2.5">
                <LimitLabel down={device.limit_download_kbps} up={device.limit_upload_kbps} />
              </td>
              <td className="px-4 py-2.5">
                <span className="inline-flex items-center gap-1 text-[10px] text-faint">
                  <Clock3 size={10} /> {relativeTime(device.last_seen)}
                </span>
              </td>
              <td className="px-4 py-2.5 text-right">
                <button className="btn-ghost h-7 px-2 text-[10px]" onClick={() => onAction(device)}>
                  <ActionIcon size={12} /> {actionLabel}
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
