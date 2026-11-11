import { useCallback, useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  Ban,
  ChevronLeft,
  ChevronRight,
  CircleHelp,
  Filter,
  Gauge,
  History,
  Loader2,
  PencilLine,
  RefreshCw,
  Search,
  ShieldBan,
  ShieldCheck,
  ShieldOff,
  X,
} from "lucide-react";
import clsx from "clsx";
import type {
  ActionResult,
  BandwidthRequest,
  DashboardSummary,
  Device,
  DeviceCategory,
  DeviceDetail,
  DeviceFilter,
  Paged,
  RestrictionRequest,
} from "../types";
import { api } from "../api";
import {
  CATEGORY_LABEL,
  deviceName,
  formatBps,
  formatDate,
  formatKbps,
  relativeTime,
} from "../lib/format";
import { PageHeader } from "../components/Layout";
import {
  AccessBadge,
  CategoryGlyph,
  ConfirmDialog,
  Dot,
  EmptyState,
  EnforcementBadge,
  LimitLabel,
  Modal,
  Pill,
  Skeleton,
} from "../components/ui";
import { useToast } from "../components/toast";

type ActionKind = "block" | "pause" | "limit" | "rename";
type ActionState = { kind: ActionKind; device: Device } | null;

export function Devices({
  dashboard,
  onChanged,
  onScan,
}: {
  dashboard: DashboardSummary | null;
  onChanged: () => void;
  onScan: () => void;
}) {
  const toast = useToast();
  const [filter, setFilter] = useState<DeviceFilter>({
    limit: 25,
    offset: 0,
    sort: "last_seen",
    order: "desc",
  });
  const [search, setSearch] = useState("");
  const [data, setData] = useState<Paged<Device> | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<Device | null>(null);
  const [action, setAction] = useState<ActionState>(null);
  const [refreshTick, setRefreshTick] = useState(0);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      setFilter((current) => ({ ...current, query: search.trim() || undefined, offset: 0 }));
    }, 250);
    return () => window.clearTimeout(timer);
  }, [search]);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const page = await api.devices(filter);
      setData(page);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, [filter, refreshTick]);

  useEffect(() => {
    load();
  }, [load]);

  const refresh = () => {
    setRefreshTick((value) => value + 1);
    onChanged();
  };

  const items = data?.items ?? [];
  const total = data?.total ?? 0;
  const offset = filter.offset ?? 0;
  const limit = filter.limit ?? 25;
  const activeFilterCount = [
    filter.online,
    filter.blocked,
    filter.trusted,
    filter.category,
    filter.query,
  ].filter((value) => value !== undefined && value !== null && value !== "").length;

  return (
    <div className="animate-fade-up">
      <PageHeader
        eyebrow="Inventory"
        title="Connected devices"
        description="Every observation is merged by MAC into a persistent device record. Historical devices stay visible after they disconnect."
        actions={
          <>
            <Pill>
              {total} device{total === 1 ? "" : "s"}
            </Pill>
            <button className="btn-ghost" onClick={refresh} disabled={loading}>
              <RefreshCw size={14} className={loading ? "animate-spin" : ""} /> Refresh
            </button>
          </>
        }
      />

      <div className="mb-3 flex flex-wrap items-center gap-2">
        <div className="relative min-w-[230px] flex-1">
          <Search
            size={15}
            className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-faint"
          />
          <input
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder="Search name, IP, MAC, vendor or notes…"
            className="input h-9 pl-9 text-xs"
          />
        </div>
        <div className="flex items-center gap-1 rounded-xl border border-line bg-raised/50 p-0.5">
          {[
            { label: "All", value: undefined, active: filter.online === undefined && !filter.blocked && !filter.trusted },
            { label: "Online", value: true, active: filter.online === true },
            { label: "Blocked", value: false, active: filter.blocked === true },
            { label: "Trusted", value: false, active: filter.trusted === true },
          ].map((tab, index) => {
            const key = ["all", "online", "blocked", "trusted"][index];
            return (
              <button
                key={key}
                onClick={() =>
                  setFilter((current) => ({
                    ...current,
                    offset: 0,
                    online: key === "online" ? true : undefined,
                    blocked: key === "blocked" ? true : undefined,
                    trusted: key === "trusted" ? true : undefined,
                  }))
                }
                className={clsx(
                  "rounded-lg px-2.5 py-1.5 text-[11px] font-medium transition",
                  tab.active ? "bg-panel-2 text-ink" : "text-muted hover:text-ink",
                )}
              >
                {tab.label}
              </button>
            );
          })}
        </div>
        <div className="relative">
          <Filter size={13} className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-faint" />
          <select
            value={filter.category ?? ""}
            onChange={(event) =>
              setFilter((current) => ({
                ...current,
                category: (event.target.value || undefined) as DeviceCategory | undefined,
                offset: 0,
              }))
            }
            className="input h-9 appearance-none pl-8 pr-7 text-[11px]"
          >
            <option value="">All types</option>
            {Object.entries(CATEGORY_LABEL).map(([value, label]) => (
              <option key={value} value={value}>
                {label}
              </option>
            ))}
          </select>
        </div>
        <select
          value={`${filter.sort}:${filter.order}`}
          onChange={(event) => {
            const [sort, order] = event.target.value.split(":");
            setFilter((current) => ({
              ...current,
              sort,
              order: order as "asc" | "desc",
              offset: 0,
            }));
          }}
          className="input h-9 w-auto text-[11px]"
        >
          <option value="last_seen:desc">Last seen</option>
          <option value="name:asc">Name</option>
          <option value="ip:asc">IP address</option>
          <option value="category:asc">Type</option>
          <option value="first_seen:desc">First discovered</option>
        </select>
        {activeFilterCount > 0 && (
          <button
            className="btn-ghost h-9 px-2 text-[11px]"
            onClick={() => {
              setSearch("");
              setFilter({ limit: 25, offset: 0, sort: "last_seen", order: "desc" });
            }}
          >
            <X size={12} /> Clear
          </button>
        )}
        <button className="btn-primary h-9" onClick={onScan}>
          Scan
        </button>
      </div>

      <section className="panel overflow-hidden">
        {error ? (
          <EmptyState
            icon={AlertTriangle}
            title="Could not load devices"
            description={error}
            action={
              <button className="btn-ghost" onClick={refresh}>
                Retry
              </button>
            }
          />
        ) : loading && !data ? (
          <div className="space-y-2 p-4">
            {Array.from({ length: 8 }).map((_, index) => (
              <Skeleton key={index} className="h-12" />
            ))}
          </div>
        ) : items.length === 0 ? (
          <EmptyState
            icon={ShieldOff}
            title={activeFilterCount > 0 ? "No devices match these filters" : "No devices discovered yet"}
            description={
              activeFilterCount > 0
                ? "Broaden the search or clear filters to see the full inventory."
                : "Run an authorized scan to populate the inventory. NetControl merges ARP, ICMP, mDNS and optional Nmap evidence."
            }
            action={
              <button className="btn-primary" onClick={onScan}>
                Scan network
              </button>
            }
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[980px]">
              <thead>
                <tr className="border-b border-line/70">
                  <th className="table-header px-4 py-3">Device</th>
                  <th className="table-header px-4 py-3">Address</th>
                  <th className="table-header px-4 py-3">Type</th>
                  <th className="table-header px-4 py-3">Limit</th>
                  <th className="table-header px-4 py-3">Access</th>
                  <th className="table-header px-4 py-3">Enforcement</th>
                  <th className="table-header px-4 py-3">Seen</th>
                  <th className="table-header px-4 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className={loading ? "opacity-60" : ""}>
                {items.map((device) => (
                  <tr
                    key={device.id}
                    className="group cursor-pointer border-b border-line/50 last:border-0 hover:bg-panel-2/40"
                    onClick={() => setSelected(device)}
                  >
                    <td className="px-4 py-2.5">
                      <div className="flex items-center gap-2.5">
                        <CategoryGlyph category={device.category} />
                        <div className="min-w-0">
                          <div className="flex items-center gap-1.5">
                            <Dot online={device.online} pulse={device.online} />
                            <span className="max-w-[210px] truncate text-xs font-medium text-ink">
                              {deviceName(device)}
                            </span>
                            {device.is_trusted && (
                              <ShieldCheck size={12} className="shrink-0 text-mint" />
                            )}
                          </div>
                          <p className="mt-0.5 max-w-[230px] truncate text-[10px] text-faint">
                            {device.vendor || "Unknown vendor"}
                            {device.hostname && device.custom_name ? ` · ${device.hostname}` : ""}
                          </p>
                        </div>
                      </div>
                    </td>
                    <td className="px-4 py-2.5">
                      <p className="mono text-[11px] text-ink">{device.ip || "—"}</p>
                      <p className="mono mt-0.5 text-[10px] text-faint">{device.mac || "—"}</p>
                    </td>
                    <td className="px-4 py-2.5">
                      <Pill>{CATEGORY_LABEL[device.category] ?? device.category}</Pill>
                    </td>
                    <td className="px-4 py-2.5">
                      <LimitLabel down={device.limit_download_kbps} up={device.limit_upload_kbps} />
                    </td>
                    <td className="px-4 py-2.5">
                      <AccessBadge blocked={device.is_blocked} trusted={device.is_trusted} />
                    </td>
                    <td className="px-4 py-2.5">
                      <EnforcementBadge state={device.enforcement} />
                    </td>
                    <td className="px-4 py-2.5">
                      <span className="text-[10px] text-faint">{relativeTime(device.last_seen)}</span>
                    </td>
                    <td className="px-4 py-2.5">
                      <div
                        className="flex items-center justify-end gap-1"
                        onClick={(event) => event.stopPropagation()}
                      >
                        <button
                          title={device.is_blocked ? "Unblock" : "Block"}
                          className={clsx(
                            "rounded-lg p-1.5 transition hover:bg-raised",
                            device.is_blocked ? "text-rose" : "text-faint hover:text-rose",
                          )}
                          onClick={() => setAction({ kind: "block", device })}
                        >
                          {device.is_blocked ? <ShieldCheck size={14} /> : <ShieldBan size={14} />}
                        </button>
                        <button
                          title="Bandwidth limit"
                          className="rounded-lg p-1.5 text-faint transition hover:bg-raised hover:text-azure"
                          onClick={() => setAction({ kind: "limit", device })}
                        >
                          <Gauge size={14} />
                        </button>
                        <button
                          title="Edit"
                          className="rounded-lg p-1.5 text-faint transition hover:bg-raised hover:text-ink"
                          onClick={() => setAction({ kind: "rename", device })}
                        >
                          <PencilLine size={14} />
                        </button>
                        <button
                          className="rounded-lg p-1.5 text-faint transition hover:bg-raised hover:text-ink"
                          onClick={() => setSelected(device)}
                          title="Details"
                        >
                          <ChevronRight size={14} />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <div className="flex items-center justify-between border-t border-line/60 px-4 py-2.5">
          <span className="text-[10px] text-faint">
            {total === 0
              ? "no records"
              : `${offset + 1}–${Math.min(offset + items.length, total)} of ${total}`}
          </span>
          <div className="flex items-center gap-1">
            <button
              className="btn-ghost h-7 px-2 text-[10px]"
              disabled={offset === 0}
              onClick={() => setFilter((current) => ({ ...current, offset: Math.max(0, offset - limit) }))}
            >
              <ChevronLeft size={12} /> Prev
            </button>
            <button
              className="btn-ghost h-7 px-2 text-[10px]"
              disabled={offset + limit >= total}
              onClick={() => setFilter((current) => ({ ...current, offset: offset + limit }))}
            >
              Next <ChevronRight size={12} />
            </button>
          </div>
        </div>
      </section>

      {selected && (
        <DeviceDrawer
          device={selected}
          enforcementAvailable={dashboard?.enforcement_available ?? false}
          onClose={() => setSelected(null)}
          onAction={(kind) => {
            setAction({ kind, device: selected });
          }}
          onChanged={() => {
            refresh();
          }}
        />
      )}

      {action && (
        <DeviceActionModal
          state={action}
          enforcementAvailable={dashboard?.enforcement_available ?? false}
          onClose={() => setAction(null)}
          onDone={(result) => {
            if (!result) {
              toast.success("Device updated", "Name, category and trust settings saved.");
            } else if (result.result.verified) {
                toast.success(
                  "Change verified",
                  `${result.device.custom_name || result.device.hostname || result.device.ip}: ${result.result.detail}`,
                );
              } else {
                toast.error(
                  result.result.action === "unsupported" ? "Not supported" : "Not enforced",
                  result.result.detail,
                );
            }
            setAction(null);
            refresh();
          }}
          onError={(message) => toast.error("Operation failed", message)}
        />
      )}
    </div>
  );
}

function DeviceDrawer({
  device,
  enforcementAvailable,
  onClose,
  onAction,
  onChanged,
}: {
  device: Device;
  enforcementAvailable: boolean;
  onClose: () => void;
  onAction: (kind: ActionKind) => void;
  onChanged: () => void;
}) {
  const [detail, setDetail] = useState<DeviceDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [confirmUnblock, setConfirmUnblock] = useState(false);
  const toast = useToast();

  useEffect(() => {
    let active = true;
    setLoading(true);
    api
      .deviceDetail(device.id)
      .then((value) => {
        if (active) {
          setDetail(value);
          setError(null);
        }
      })
      .catch((err) => active && setError(err instanceof Error ? err.message : String(err)))
      .finally(() => active && setLoading(false));
    return () => {
      active = false;
    };
  }, [device.id]);

  const unblock = async () => {
    try {
      const result = await api.unblock(device.id);
      if (result.result.verified) {
        toast.success("Access restored", result.result.detail);
        onChanged();
        onClose();
      } else {
        toast.error("Not enforced", result.result.detail);
      }
    } catch (err) {
      toast.error("Unblock failed", err instanceof Error ? err.message : String(err));
    }
  };

  const current = detail?.device ?? device;

  return (
    <>
      <div className="fixed inset-0 z-40 bg-[#02060A]/70 backdrop-blur-sm" onClick={onClose} />
      <aside className="fixed bottom-0 right-0 top-0 z-50 flex w-full max-w-[460px] flex-col overflow-hidden border-l border-line-strong bg-[#080E15] shadow-panel">
        <div className="flex shrink-0 items-start justify-between border-b border-line px-5 py-4">
          <div className="flex items-center gap-3">
            <CategoryGlyph category={current.category} />
            <div>
              <h2 className="font-display text-base font-semibold text-ink">{deviceName(current)}</h2>
              <p className="mono mt-0.5 text-[10px] text-faint">{current.ip || "no IP"} · {current.interface || "unknown iface"}</p>
            </div>
          </div>
          <button className="rounded-lg p-1.5 text-faint hover:bg-raised hover:text-ink" onClick={onClose}>
            <X size={16} />
          </button>
        </div>

        <div className="min-h-0 flex-1 overflow-y-auto px-5 py-4">
          {loading && <Skeleton className="h-32" />}
          {error && (
            <div className="rounded-xl border border-rose/25 bg-rose/5 px-3 py-2 text-[11px] text-rose">
              {error}
            </div>
          )}
          <div className="grid grid-cols-2 gap-2">
            <Info label="MAC address" value={current.mac} mono />
            <Info label="Vendor" value={current.vendor} />
            <Info label="Type" value={CATEGORY_LABEL[current.category] ?? current.category} />
            <Info label="First seen" value={formatDate(current.first_seen)} />
            <Info label="Last seen" value={formatDate(current.last_seen)} />
            <Info label="SSID" value={current.ssid} />
            <Info
              label="Download limit"
              value={current.limit_download_kbps ? formatKbps(current.limit_download_kbps) : "Unlimited"}
            />
            <Info
              label="Upload limit"
              value={current.limit_upload_kbps ? formatKbps(current.limit_upload_kbps) : "Unlimited"}
            />
          </div>

          <div className="mt-3 flex items-center justify-between rounded-xl border border-line bg-raised/50 px-3 py-2.5">
            <span className="text-[11px] text-muted">Access state</span>
            <AccessBadge blocked={current.is_blocked} trusted={current.is_trusted} />
          </div>
          <div className="mt-2 flex items-center justify-between rounded-xl border border-line bg-raised/50 px-3 py-2.5">
            <span className="text-[11px] text-muted">Enforcement</span>
            <EnforcementBadge state={current.enforcement} />
          </div>
          {current.blocked_until && (
            <p className="mt-2 px-1 text-[10px] text-amber/80">
              Temporary restriction until {formatDate(current.blocked_until)}
            </p>
          )}

          {!enforcementAvailable && (
            <div className="mt-3 flex items-start gap-2 rounded-xl border border-amber/20 bg-amber/5 px-3 py-2.5 text-[10px] leading-relaxed text-amber/90">
              <CircleHelp size={13} className="mt-0.5 shrink-0" />
              No authorized gateway is ready. Access changes will be reported as unsupported and
              will not modify the device state.
            </div>
          )}

          {detail?.traffic && (
            <div className="mt-4">
              <p className="eyebrow mb-2">Latest per-device traffic</p>
              <div className="flex items-center justify-between rounded-xl border border-line bg-raised/50 px-3 py-2.5">
                <span className="mono text-[11px] text-mint">↓ {formatBps(detail.traffic.rx_bps)}</span>
                <span className="mono text-[11px] text-azure">↑ {formatBps(detail.traffic.tx_bps)}</span>
                <span className="text-[10px] text-faint">{detail.traffic.source}</span>
              </div>
            </div>
          )}

          <div className="mt-4">
            <p className="eyebrow mb-2 flex items-center gap-1.5">
              <History size={11} /> Recent activity
            </p>
            <div className="rounded-xl border border-line">
              {detail?.history.length ? (
                detail.history.slice(0, 8).map((event) => (
                  <div key={event.id} className="flex gap-2 border-b border-line/60 px-3 py-2 last:border-0">
                    <span className="mono w-16 shrink-0 text-[9px] text-faint">
                      {new Date(event.ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
                    </span>
                    <div className="min-w-0">
                      <p className="text-[11px] text-ink">{event.event}</p>
                      {event.detail && <p className="mt-0.5 text-[10px] text-faint">{event.detail}</p>}
                    </div>
                  </div>
                ))
              ) : (
                <p className="px-3 py-4 text-center text-[10px] text-faint">No history recorded.</p>
              )}
            </div>
          </div>

          {detail?.access_rules.length ? (
            <div className="mt-4">
              <p className="eyebrow mb-2">Access rules</p>
              <div className="space-y-1.5">
                {detail.access_rules.slice(0, 4).map((rule) => (
                  <div key={rule.id} className="rounded-lg border border-line bg-raised/40 px-3 py-2">
                    <div className="flex items-center justify-between">
                      <span className="text-[11px] text-ink">{rule.action}</span>
                      <EnforcementBadge state={rule.state} />
                    </div>
                    {rule.last_error && <p className="mt-1 text-[10px] text-rose">{rule.last_error}</p>}
                  </div>
                ))}
              </div>
            </div>
          ) : null}

          {current.notes && (
            <div className="mt-4 rounded-xl border border-line bg-raised/40 px-3 py-2 text-[11px] text-muted">
              {current.notes}
            </div>
          )}
        </div>

        <div className="grid shrink-0 grid-cols-2 gap-2 border-t border-line p-4">
          {current.is_blocked ? (
            <button className="btn-primary" onClick={() => setConfirmUnblock(true)}>
              <ShieldCheck size={14} /> Restore access
            </button>
          ) : (
            <button className="btn-danger" onClick={() => onAction("block")}>
              <Ban size={14} /> Block device
            </button>
          )}
          <button className="btn-ghost" onClick={() => onAction("pause")}>
            <ShieldOff size={14} /> Pause
          </button>
          <button className="btn-ghost" onClick={() => onAction("limit")}>
            <Gauge size={14} /> Bandwidth
          </button>
          <button className="btn-ghost" onClick={() => onAction("rename")}>
            <PencilLine size={14} /> Edit
          </button>
        </div>
      </aside>

      <ConfirmDialog
        open={confirmUnblock}
        title="Restore internet access"
        description={`Remove the verified block for ${deviceName(current)}?`}
        confirmLabel="Restore access"
        onCancel={() => setConfirmUnblock(false)}
        onConfirm={() => {
          setConfirmUnblock(false);
          unblock();
        }}
      >
        <p className="text-[11px] leading-relaxed text-muted">
          NetControl will ask the active gateway to remove the rule and will only update the
          device state if the gateway confirms it.
        </p>
      </ConfirmDialog>
    </>
  );
}

function Info({ label, value, mono }: { label: string; value: string | null; mono?: boolean }) {
  return (
    <div className="rounded-xl border border-line bg-raised/40 p-2.5">
      <p className="text-[9px] uppercase tracking-wider text-faint">{label}</p>
      <p className={clsx("mt-1 break-all text-[11px] text-ink", mono && "mono text-[10px]")}>
        {value || "—"}
      </p>
    </div>
  );
}

function DeviceActionModal({
  state,
  enforcementAvailable,
  onClose,
  onDone,
  onError,
}: {
  state: NonNullable<ActionState>;
  enforcementAvailable: boolean;
  onClose: () => void;
  onDone: (result: ActionResult | null) => void;
  onError: (message: string) => void;
}) {
  const device = state.device;
  const [busy, setBusy] = useState(false);
  const [duration, setDuration] = useState(state.kind === "pause" ? 3600 : 0);
  const [reason, setReason] = useState("");
  const [download, setDownload] = useState(
    device.limit_download_kbps ? String(device.limit_download_kbps / 1000) : "10",
  );
  const [upload, setUpload] = useState(
    device.limit_upload_kbps ? String(device.limit_upload_kbps / 1000) : "2",
  );
  const [unit, setUnit] = useState("Mbps");
  const [priority, setPriority] = useState<string>("");
  const [name, setName] = useState(device.custom_name || "");
  const [category, setCategory] = useState<DeviceCategory>(device.category);
  const [notes, setNotes] = useState(device.notes || "");
  const [trusted, setTrusted] = useState(device.is_trusted);
  const [confirmUnblock, setConfirmUnblock] = useState(false);

  const title =
    state.kind === "block"
      ? "Restrict device access"
      : state.kind === "pause"
        ? "Pause internet access"
        : state.kind === "limit"
          ? "Bandwidth limits"
          : "Edit device";

  const isBlocked = device.is_blocked;

  const run = async () => {
    setBusy(true);
    try {
      if (state.kind === "rename") {
        await api.updateDevice(device.id, {
          custom_name: name.trim() || null,
          category,
          notes: notes.trim() || null,
          is_trusted: trusted,
        });
        onDone(null);
        return;
      }
      if (state.kind === "block" && isBlocked) {
        setConfirmUnblock(true);
        return;
      }
      if (state.kind === "block") {
        const body: RestrictionRequest = {
          confirm: true,
          duration_seconds: duration || null,
          reason: reason.trim() || null,
        };
        const result = await api.block(device.id, body);
        onDone(result);
      } else if (state.kind === "pause") {
        const body: RestrictionRequest = {
          confirm: true,
          duration_seconds: duration,
          reason: reason.trim() || "Paused from desktop",
        };
        const result = await api.pause(device.id, body);
        onDone(result);
      } else if (state.kind === "limit") {
        const multiplier = unit === "Gbps" ? 1_000_000 : unit === "Mbps" ? 1_000 : 1;
        const down = download.trim() ? Math.round(Number(download) * multiplier) : null;
        const up = upload.trim() ? Math.round(Number(upload) * multiplier) : null;
        if ((!down || down <= 0) && (!up || up <= 0)) {
          throw new Error("Enter a download or upload limit.");
        }
        const body: BandwidthRequest = {
          confirm: true,
          download_kbps: down && down > 0 ? down : null,
          upload_kbps: up && up > 0 ? up : null,
          priority: priority ? Number(priority) : null,
          expires_at:
            duration > 0
              ? new Date(Date.now() + duration * 1000).toISOString()
              : null,
        };
        const result = await api.setLimit(device.id, body);
        onDone(result);
      }
    } catch (err) {
      onError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  const unblock = async () => {
    setBusy(true);
    try {
      const result = await api.unblock(device.id);
      onDone(result);
    } catch (err) {
      onError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  const clearLimit = async () => {
    setBusy(true);
    try {
      const result = await api.clearLimit(device.id);
      onDone(result);
    } catch (err) {
      onError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  const durationOptions = useMemo(
    () => [
      { value: 0, label: "Permanent" },
      { value: 900, label: "15 minutes" },
      { value: 3600, label: "1 hour" },
      { value: 21600, label: "6 hours" },
      { value: 86400, label: "24 hours" },
      { value: 604800, label: "7 days" },
    ],
    [],
  );

  return (
    <>
      <Modal
        open
        onClose={onClose}
        title={title}
        subtitle={`${deviceName(device)} · ${device.ip || device.mac || "no address"}`}
        width="max-w-lg"
      >
        {state.kind === "block" && !isBlocked && (
          <>
            <div className="mb-4 flex items-start gap-2 rounded-xl border border-line bg-raised/40 px-3 py-2.5 text-[11px] leading-relaxed text-muted">
              <AlertTriangle size={14} className="mt-0.5 shrink-0 text-amber" />
              Blocking is enforced by the active gateway. NetControl will only report success
              after the gateway confirms the rule.
            </div>
            <label className="label">Duration</label>
            <select
              className="input mb-3"
              value={duration}
              onChange={(event) => setDuration(Number(event.target.value))}
            >
              {durationOptions.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </select>
            <label className="label">Reason (optional)</label>
            <input
              className="input"
              value={reason}
              onChange={(event) => setReason(event.target.value)}
              placeholder="e.g. untrusted guest device"
            />
          </>
        )}

        {state.kind === "block" && isBlocked && (
          <p className="text-[11px] leading-relaxed text-muted">
            This device is currently blocked
            {device.blocked_until ? ` until ${formatDate(device.blocked_until)}` : ""}. Restore
            access through the gateway?
          </p>
        )}

        {state.kind === "pause" && (
          <>
            <label className="label">Pause for</label>
            <select
              className="input mb-3"
              value={duration}
              onChange={(event) => setDuration(Number(event.target.value))}
            >
              {durationOptions
                .filter((option) => option.value > 0)
                .map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
            </select>
            <label className="label">Reason (optional)</label>
            <input
              className="input"
              value={reason}
              onChange={(event) => setReason(event.target.value)}
              placeholder="temporary restriction"
            />
            <p className="mt-2 text-[10px] text-faint">
              NetControl will automatically remove the restriction when the timer expires.
            </p>
          </>
        )}

        {state.kind === "limit" && (
          <>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="label">Download limit</label>
                <div className="flex gap-1.5">
                  <input
                    className="input"
                    inputMode="decimal"
                    value={download}
                    onChange={(event) => setDownload(event.target.value)}
                    placeholder="10"
                  />
                  <select
                    className="input w-24"
                    value={unit}
                    onChange={(event) => setUnit(event.target.value)}
                  >
                    <option>Mbps</option>
                    <option>Kbps</option>
                    <option>Gbps</option>
                  </select>
                </div>
              </div>
              <div>
                <label className="label">Upload limit</label>
                <div className="flex gap-1.5">
                  <input
                    className="input"
                    inputMode="decimal"
                    value={upload}
                    onChange={(event) => setUpload(event.target.value)}
                    placeholder="2"
                  />
                  <select
                    className="input w-24"
                    value={unit}
                    onChange={(event) => setUnit(event.target.value)}
                  >
                    <option>Mbps</option>
                    <option>Kbps</option>
                    <option>Gbps</option>
                  </select>
                </div>
              </div>
            </div>
            <div className="mt-3 grid grid-cols-2 gap-3">
              <div>
                <label className="label">Priority</label>
                <select
                  className="input"
                  value={priority}
                  onChange={(event) => setPriority(event.target.value)}
                >
                  <option value="">Default</option>
                  {[1, 2, 3, 4, 5, 6, 7].map((value) => (
                    <option key={value} value={value}>
                      {value} {value === 7 ? "(highest)" : ""}
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label className="label">Expires</label>
                <select
                  className="input"
                  value={duration}
                  onChange={(event) => setDuration(Number(event.target.value))}
                >
                  {durationOptions.map((option) => (
                    <option key={option.value} value={option.value}>
                      {option.value === 0 ? "No expiry" : option.label}
                    </option>
                  ))}
                </select>
              </div>
            </div>
            {(device.limit_download_kbps || device.limit_upload_kbps) && (
              <button
                className="btn-danger mt-4 w-full"
                onClick={clearLimit}
                disabled={busy}
              >
                <X size={14} /> Clear applied limits
              </button>
            )}
          </>
        )}

        {state.kind === "rename" && (
          <>
            <label className="label">Friendly name</label>
            <input
              className="input mb-3"
              value={name}
              onChange={(event) => setName(event.target.value)}
              placeholder={device.hostname || "e.g. Living room TV"}
            />
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="label">Category</label>
                <select
                  className="input"
                  value={category}
                  onChange={(event) => setCategory(event.target.value as DeviceCategory)}
                >
                  {Object.entries(CATEGORY_LABEL).map(([value, label]) => (
                    <option key={value} value={value}>
                      {label}
                    </option>
                  ))}
                </select>
              </div>
              <div className="flex items-end">
                <label className="flex w-full cursor-pointer items-center gap-2 rounded-xl border border-line bg-raised/40 px-3 py-2.5 text-[11px] text-muted">
                  <input
                    type="checkbox"
                    checked={trusted}
                    onChange={(event) => setTrusted(event.target.checked)}
                    className="accent-[#3FE0AE]"
                  />
                  Trusted device
                </label>
              </div>
            </div>
            <label className="label mt-3">Notes</label>
            <textarea
              className="input min-h-[72px] resize-none"
              value={notes}
              onChange={(event) => setNotes(event.target.value)}
              placeholder="Optional notes about this device"
            />
          </>
        )}

        {!enforcementAvailable && state.kind !== "rename" && (
          <div className="mt-4 flex items-start gap-2 rounded-xl border border-amber/20 bg-amber/5 px-3 py-2.5 text-[10px] leading-relaxed text-amber/90">
            <CircleHelp size={13} className="mt-0.5 shrink-0" />
            No enforcement gateway is ready. This operation will be rejected as unsupported and
            the device will not be marked blocked or limited.
          </div>
        )}

        <div className="mt-5 flex justify-end gap-2">
          <button className="btn-ghost" onClick={onClose} disabled={busy}>
            Cancel
          </button>
          {state.kind === "block" && isBlocked ? (
            <button className="btn-primary" onClick={() => setConfirmUnblock(true)} disabled={busy}>
              Restore access
            </button>
          ) : (
            <button
              className={state.kind === "block" ? "btn-danger" : "btn-primary"}
              onClick={run}
              disabled={busy}
            >
              {busy && <Loader2 size={14} className="animate-spin" />}
              {state.kind === "pause"
                ? "Pause access"
                : state.kind === "limit"
                  ? "Apply limits"
                  : state.kind === "rename"
                    ? "Save changes"
                    : "Block device"}
            </button>
          )}
        </div>
      </Modal>

      <ConfirmDialog
        open={confirmUnblock}
        title="Restore access"
        description={`Remove the block for ${deviceName(device)}?`}
        confirmLabel="Restore access"
        onCancel={() => setConfirmUnblock(false)}
        onConfirm={() => {
          setConfirmUnblock(false);
          unblock();
        }}
      >
        <p className="text-[11px] leading-relaxed text-muted">
          The active gateway must confirm that the rule was removed. If it cannot, the device
          will remain marked as blocked.
        </p>
      </ConfirmDialog>
    </>
  );
}
