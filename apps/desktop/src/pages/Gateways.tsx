import { useCallback, useEffect, useState } from "react";
import {
  Check,
  ChevronRight,
  CircleHelp,
  KeyRound,
  Loader2,
  Lock,
  Network,
  Plus,
  RefreshCw,
  Router,
  Server,
  ShieldCheck,
  ShieldAlert,
  Trash2,
  Wifi,
} from "lucide-react";
import clsx from "clsx";
import type {
  GatewayInput,
  GatewayProbe,
  GatewayView,
} from "../types";
import { api } from "../api";
import { formatDate } from "../lib/format";
import { PageHeader } from "../components/Layout";
import {
  CapabilityRow,
  ConfirmDialog,
  EmptyState,
  Modal,
  Pill,
  Skeleton,
} from "../components/ui";
import { useToast } from "../components/toast";

const KINDS: Array<{
  id: GatewayInput["kind"];
  label: string;
  port: number;
  tls: boolean;
  user?: string;
  hint: string;
  hostHint: string;
  auth: string;
}> = [
  {
    id: "openwrt",
    label: "OpenWrt",
    port: 22,
    tls: false,
    user: "root",
    hint: "SSH + UCI/fw4. Persistent firewall rules, tc shaping.",
    hostHint: "192.168.1.1",
    auth: "SSH key is preferred. Password auth requires sshpass.",
  },
  {
    id: "mikrotik",
    label: "MikroTik RouterOS",
    port: 8729,
    tls: true,
    user: "admin",
    hint: "Native RouterOS API, address-list firewall and simple queues.",
    hostHint: "192.168.88.1",
    auth: "API user and password. API-SSL is strongly recommended.",
  },
  {
    id: "unifi",
    label: "UniFi Network",
    port: 443,
    tls: true,
    user: "admin",
    hint: "Local UniFi controller. Client block and user-group rate limits.",
    hostHint: "unifi.local",
    auth: "Local controller administrator credentials.",
  },
  {
    id: "pfsense",
    label: "pfSense",
    port: 22,
    tls: false,
    user: "admin",
    hint: "SSH + easyrule. Blocking verified through pfctl.",
    hostHint: "192.168.1.1",
    auth: "SSH key is preferred. Interface hint is the firewall interface (e.g. lan).",
  },
  {
    id: "opnsense",
    label: "OPNsense",
    port: 443,
    tls: true,
    user: "",
    hint: "REST API alias management. Requires API key/secret.",
    hostHint: "192.168.1.1",
    auth: "API key and secret. A block rule is created on first use when supported.",
  },
  {
    id: "linux",
    label: "Linux gateway (this host)",
    port: 0,
    tls: false,
    hint: "nftables block set + tc HTB. Requires the privileged helper.",
    hostHint: "local",
    auth: "Install netcontrol-helper and the sudoers rule from docs/GATEWAYS.md.",
  },
];

export function Gateways({ onChanged }: { onChanged: () => void }) {
  const toast = useToast();
  const [gateways, setGateways] = useState<GatewayView[]>([]);
  const [probe, setProbe] = useState<GatewayProbe | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showForm, setShowForm] = useState(false);
  const [editing, setEditing] = useState<GatewayView | null>(null);
  const [deleting, setDeleting] = useState<GatewayView | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [list, status] = await Promise.all([api.gateways(), api.gatewayStatus()]);
      setGateways(list);
      setProbe(status);
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

  const test = async (gateway: GatewayView) => {
    setBusyId(gateway.id);
    try {
      const result = await api.testGateway(gateway.id);
      if (result.ok) {
        toast.success(`${gateway.name} reachable`, result.message);
      } else {
        toast.error(`${gateway.name} not ready`, result.message);
      }
      await load();
    } catch (err) {
      toast.error("Gateway probe failed", err instanceof Error ? err.message : String(err));
    } finally {
      setBusyId(null);
    }
  };

  const activate = async (gateway: GatewayView) => {
    setBusyId(gateway.id);
    try {
      await api.activateGateway(gateway.id);
      toast.success("Active gateway changed", gateway.name);
      await load();
      onChanged();
    } catch (err) {
      toast.error("Could not activate", err instanceof Error ? err.message : String(err));
    } finally {
      setBusyId(null);
    }
  };

  const remove = async () => {
    if (!deleting) return;
    setBusyId(deleting.id);
    try {
      await api.deleteGateway(deleting.id);
      toast.success("Gateway removed", deleting.name);
      setDeleting(null);
      await load();
      onChanged();
    } catch (err) {
      toast.error("Could not delete gateway", err instanceof Error ? err.message : String(err));
    } finally {
      setBusyId(null);
    }
  };

  const active = gateways.find((gateway) => gateway.active);
  const capabilities = probe?.capabilities ?? active?.capabilities;

  return (
    <div className="animate-fade-up">
      <PageHeader
        eyebrow="Infrastructure"
        title="Gateway integrations"
        description="Access control is only as real as the infrastructure behind it. NetControl supports six adapters and verifies every change against the managed device."
        actions={
          <>
            <button className="btn-ghost" onClick={load} disabled={loading}>
              <RefreshCw size={14} className={loading ? "animate-spin" : ""} /> Refresh
            </button>
            <button className="btn-primary" onClick={() => { setEditing(null); setShowForm(true); }}>
              <Plus size={14} /> Add gateway
            </button>
          </>
        }
      />

      {error && (
        <div className="mb-3 rounded-xl border border-rose/25 bg-rose/5 px-3 py-2.5 text-[11px] text-rose">
          {error}
        </div>
      )}

      <div className="mb-4 grid gap-4 xl:grid-cols-[1.55fr_1fr]">
        <section className="panel overflow-hidden">
          <div className="panel-header">
            <div>
              <p className="eyebrow">Active enforcement path</p>
              <h3 className="mt-1 font-display text-base font-semibold text-ink">
                {active ? active.name : "No gateway selected"}
              </h3>
            </div>
            {probe?.ok ? (
              <Pill tone="success">
                <ShieldCheck size={11} /> verified
              </Pill>
            ) : (
              <Pill tone="warning">
                <ShieldAlert size={11} /> not ready
              </Pill>
            )}
          </div>
          <div className="p-4">
            {loading && !probe ? (
              <Skeleton className="h-28" />
            ) : probe ? (
              <>
                <div className="flex flex-wrap items-center gap-x-6 gap-y-2">
                  <div>
                    <p className="eyebrow">Adapter</p>
                    <p className="mt-1 text-xs text-ink">{probe.kind}</p>
                  </div>
                  <div>
                    <p className="eyebrow">Version</p>
                    <p className="mt-1 text-xs text-ink">{probe.version || "-"}</p>
                  </div>
                  <div>
                    <p className="eyebrow">Latency</p>
                    <p className="mono mt-1 text-xs text-ink">{probe.latency_ms}ms</p>
                  </div>
                  <div className="min-w-0 flex-1">
                    <p className="eyebrow">Message</p>
                    <p className="mt-1 line-clamp-2 text-[11px] leading-relaxed text-muted">{probe.message}</p>
                  </div>
                </div>
                <div className="mt-4 grid gap-4 border-t border-line/60 pt-3 sm:grid-cols-2">
                  <div>
                    <CapabilityRow label="Client discovery" supported={capabilities?.discovery ?? false} />
                    <CapabilityRow label="DHCP leases" supported={capabilities?.dhcp_leases ?? false} />
                    <CapabilityRow label="Block / unblock" supported={capabilities?.block ?? false} />
                    <CapabilityRow label="Bandwidth limits" supported={capabilities?.bandwidth ?? false} />
                  </div>
                  <div>
                    <CapabilityRow label="Priority" supported={capabilities?.priority ?? false} />
                    <CapabilityRow label="Traffic statistics" supported={capabilities?.traffic_stats ?? false} />
                    <CapabilityRow label="Schedules" supported={capabilities?.schedules ?? false} />
                    <CapabilityRow label="Verified operations" supported={probe.ok} />
                  </div>
                </div>
              </>
            ) : (
              <EmptyState
                icon={ShieldAlert}
                title="Access control is not configured"
                description="NetControl can still discover devices, resolve vendors, identify services and measure interface traffic. Add a supported gateway to block devices or enforce bandwidth limits."
                action={
                  <button className="btn-primary" onClick={() => setShowForm(true)}>
                    <Plus size={14} /> Add your first gateway
                  </button>
                }
              />
            )}
          </div>
        </section>

        <section className="panel p-4">
          <p className="eyebrow">Safety model</p>
          <h3 className="mt-1 font-display text-sm font-semibold text-ink">
            Never claim an unverified change
          </h3>
          <ul className="mt-3 space-y-2.5 text-[11px] leading-relaxed text-muted">
            <li className="flex gap-2">
              <Check size={13} className="mt-0.5 shrink-0 text-mint" />
              Every block, unblock and limit is read back from the gateway before the device state changes.
            </li>
            <li className="flex gap-2">
              <Check size={13} className="mt-0.5 shrink-0 text-mint" />
              If the network has no authorized gateway, the operation is reported as unsupported.
            </li>
            <li className="flex gap-2">
              <Check size={13} className="mt-0.5 shrink-0 text-mint" />
              Gateway passwords and API keys are sealed with AES-256-GCM; only a hash of session tokens is stored.
            </li>
            <li className="flex gap-2">
              <Lock size={13} className="mt-0.5 shrink-0 text-azure" />
              Remote management requires HTTPS. Discovery never scans public address space without an explicit override.
            </li>
          </ul>
        </section>
      </div>

      <section className="panel">
        <div className="panel-header">
          <div>
            <p className="eyebrow">Configured</p>
            <h3 className="mt-1 font-display text-base font-semibold text-ink">Gateways</h3>
          </div>
          <Pill>{gateways.length} configured</Pill>
        </div>
        {gateways.length === 0 && !loading ? (
          <EmptyState
            icon={Network}
            title="No gateway integrations"
            description="Supported adapters: OpenWrt, MikroTik RouterOS, UniFi, pfSense, OPNsense and a local Linux gateway."
          />
        ) : (
          <div className="grid gap-3 p-4 xl:grid-cols-2">
            {gateways.map((gateway) => {
              const kind = KINDS.find((entry) => entry.id === gateway.kind);
              return (
                <div
                  key={gateway.id}
                  className={clsx(
                    "rounded-xl border bg-raised/30 p-4 transition",
                    gateway.active ? "border-mint/30 bg-mint/[.03]" : "border-line",
                  )}
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex items-start gap-3">
                      <span
                        className={clsx(
                          "flex h-9 w-9 items-center justify-center rounded-xl border",
                          gateway.active
                            ? "border-mint/30 bg-mint/10 text-mint"
                            : "border-line bg-raised text-muted",
                        )}
                      >
                        {gateway.kind === "unifi" ? <Wifi size={16} /> : gateway.kind === "linux" ? <Server size={16} /> : <Router size={16} />}
                      </span>
                      <div>
                        <div className="flex items-center gap-2">
                          <p className="text-sm font-medium text-ink">{gateway.name}</p>
                          {gateway.active && <Pill tone="success">active</Pill>}
                        </div>
                        <p className="mono mt-0.5 text-[10px] text-faint">
                          {kind?.label ?? gateway.kind} · {gateway.host}
                          {gateway.port ? `:${gateway.port}` : ""}
                        </p>
                      </div>
                    </div>
                    <span title={gateway.has_secret ? "Secret stored encrypted" : "No secret stored"}>
                      <KeyRound size={13} className={gateway.has_secret ? "text-mint" : "text-faint"} />
                    </span>
                  </div>

                  <p className="mt-3 text-[11px] leading-relaxed text-muted">{kind?.hint}</p>
                  <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-1 font-mono text-[9px] text-faint">
                    <span>{gateway.tls ? "TLS" : "plain transport"}</span>
                    {gateway.interface_hint && <span>iface {gateway.interface_hint}</span>}
                    {gateway.username && <span>user {gateway.username}</span>}
                    <span>added {formatDate(gateway.created_at)}</span>
                  </div>

                  <div className="mt-4 flex flex-wrap items-center gap-2 border-t border-line/60 pt-3">
                    <button
                      className="btn-ghost h-7 px-2 text-[10px]"
                      onClick={() => test(gateway)}
                      disabled={busyId === gateway.id}
                    >
                      {busyId === gateway.id ? <Loader2 size={12} className="animate-spin" /> : <ShieldCheck size={12} />}
                      Test
                    </button>
                    {!gateway.active && (
                      <button
                        className="btn-ghost h-7 px-2 text-[10px]"
                        onClick={() => activate(gateway)}
                        disabled={busyId === gateway.id}
                      >
                        <ChevronRight size={12} /> Activate
                      </button>
                    )}
                    <button
                      className="btn-ghost h-7 px-2 text-[10px]"
                      onClick={() => {
                        setEditing(gateway);
                        setShowForm(true);
                      }}
                    >
                      Edit
                    </button>
                    <button
                      className="btn-danger ml-auto h-7 px-2 text-[10px]"
                      onClick={() => setDeleting(gateway)}
                    >
                      <Trash2 size={12} /> Remove
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </section>

      {showForm && (
        <GatewayForm
          editing={editing}
          onClose={() => setShowForm(false)}
          onSaved={async () => {
            setShowForm(false);
            await load();
            onChanged();
          }}
        />
      )}

      <ConfirmDialog
        open={deleting !== null}
        title="Remove gateway"
        description={deleting ? `Remove ${deleting.name}?` : ""}
        confirmLabel="Remove gateway"
        danger
        busy={busyId !== null}
        onCancel={() => setDeleting(null)}
        onConfirm={remove}
      >
        <p className="text-[11px] leading-relaxed text-muted">
          This removes the encrypted credentials and configuration from NetControl. It does not
          alter rules already applied on the gateway.
        </p>
      </ConfirmDialog>
    </div>
  );
}

function GatewayForm({
  editing,
  onClose,
  onSaved,
}: {
  editing: GatewayView | null;
  onClose: () => void;
  onSaved: () => void;
}) {
  const toast = useToast();
  const initialKind = KINDS.find((entry) => entry.id === (editing?.kind ?? "openwrt")) ?? KINDS[0];
  const [kind, setKind] = useState(initialKind.id);
  const [name, setName] = useState(editing?.name ?? initialKind.label);
  const [host, setHost] = useState(editing?.host ?? initialKind.hostHint);
  const [port, setPort] = useState(String(editing?.port ?? initialKind.port));
  const [username, setUsername] = useState(editing?.username ?? initialKind.user ?? "");
  const [secret, setSecret] = useState("");
  const [site, setSite] = useState(editing?.site ?? "");
  const [iface, setIface] = useState(
    editing?.interface_hint ?? (editing?.kind === "linux" ? "" : ""),
  );
  const [tls, setTls] = useState(editing?.tls ?? initialKind.tls);
  const [insecure, setInsecure] = useState(editing?.tls_insecure ?? false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const meta = KINDS.find((entry) => entry.id === kind) ?? KINDS[0];

  const switchKind = (next: string) => {
    const entry = KINDS.find((candidate) => candidate.id === next);
    if (!entry) return;
    setKind(entry.id);
    if (!editing) {
      setName(entry.label);
      setHost(entry.hostHint);
      setPort(String(entry.port));
      setUsername(entry.user ?? "");
      setTls(entry.tls);
      setSecret("");
    }
  };

  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      const input: GatewayInput = {
        name: name.trim(),
        kind,
        host: host.trim(),
        port: port ? Number(port) : null,
        username: username.trim() || null,
        secret: secret || undefined,
        site: site.trim() || null,
        interface_hint: iface.trim() || null,
        tls,
        tls_insecure: insecure,
        enabled: true,
      };
      if (editing) {
        await api.updateGateway(editing.id, input);
        toast.success("Gateway updated", name);
      } else {
        await api.createGateway(input);
        toast.success("Gateway added", `${name} is ready to test`);
      }
      onSaved();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  const requiresSecret = ["mikrotik", "unifi", "opnsense"].includes(kind);
  const canSubmit =
    name.trim().length > 0 &&
    host.trim().length > 0 &&
    (editing !== null || !requiresSecret || secret.length > 0);

  return (
    <Modal
      open
      onClose={onClose}
      title={editing ? "Edit gateway" : "Add authorized gateway"}
      subtitle="Credentials are encrypted before being stored. Secrets are never returned by the API."
      width="max-w-2xl"
    >
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
        {KINDS.map((entry) => (
          <button
            key={entry.id}
            type="button"
            onClick={() => switchKind(entry.id)}
            className={clsx(
              "rounded-xl border px-3 py-2.5 text-left transition",
              kind === entry.id
                ? "border-mint/40 bg-mint/5"
                : "border-line bg-raised/40 hover:border-line-strong",
            )}
          >
            <span className="block text-[11px] font-medium text-ink">{entry.label}</span>
            <span className="mt-0.5 block font-mono text-[9px] uppercase tracking-wider text-faint">
              {entry.id === "linux" ? "local" : `port ${entry.port}`}
            </span>
          </button>
        ))}
      </div>

      <div className="mt-4 grid gap-3 sm:grid-cols-2">
        <div>
          <label className="label">Display name</label>
          <input className="input" value={name} onChange={(event) => setName(event.target.value)} />
        </div>
        <div>
          <label className="label">
            {kind === "linux" ? "Host (local)" : "Host or IP"}
          </label>
          <input
            className="input"
            value={host}
            onChange={(event) => setHost(event.target.value)}
            spellCheck={false}
          />
        </div>
        {kind !== "linux" && (
          <div>
            <label className="label">Port</label>
            <input
              className="input"
              value={port}
              onChange={(event) => setPort(event.target.value)}
              inputMode="numeric"
            />
          </div>
        )}
        {kind !== "linux" && (
          <div>
            <label className="label">Username / API key</label>
            <input
              className="input"
              value={username}
              onChange={(event) => setUsername(event.target.value)}
              spellCheck={false}
            />
          </div>
        )}
        {kind !== "linux" && (
          <div>
            <label className="label">
              {editing ? "Secret (leave blank to keep current)" : "Password / API secret"}
            </label>
            <input
              className="input"
              type="password"
              value={secret}
              onChange={(event) => setSecret(event.target.value)}
              placeholder={editing?.has_secret ? "•••••••• (unchanged)" : ""}
              autoComplete="new-password"
            />
          </div>
        )}
        {(kind === "openwrt" || kind === "linux" || kind === "pfsense") && (
          <div>
            <label className="label">
              LAN / firewall interface
              <span className="ml-1 text-faint">(for shaping)</span>
            </label>
            <input
              className="input"
              value={iface}
              onChange={(event) => setIface(event.target.value)}
              placeholder={kind === "linux" ? "e.g. enp1s0f1" : kind === "pfsense" ? "lan" : "br-lan"}
              spellCheck={false}
            />
          </div>
        )}
        {(kind === "unifi" || kind === "opnsense") && (
          <div>
            <label className="label">Site {kind === "opnsense" ? "(optional)" : ""}</label>
            <input
              className="input"
              value={site}
              onChange={(event) => setSite(event.target.value)}
              placeholder={kind === "unifi" ? "default" : ""}
            />
          </div>
        )}
      </div>

      {kind !== "linux" && (
        <div className="mt-4 flex flex-wrap gap-5 rounded-xl border border-line bg-raised/40 px-3 py-2.5">
          <label className="flex items-center gap-2 text-[11px] text-muted">
            <input type="checkbox" checked={tls} onChange={(event) => setTls(event.target.checked)} className="accent-[#3FE0AE]" />
            Use TLS / HTTPS
          </label>
          <label className="flex items-center gap-2 text-[11px] text-muted">
            <input type="checkbox" checked={insecure} onChange={(event) => setInsecure(event.target.checked)} className="accent-[#FEB454]" />
            Accept self-signed certificate / unknown SSH host key
          </label>
        </div>
      )}

      <div className="mt-3 flex items-start gap-2 rounded-xl border border-line bg-raised/40 px-3 py-2.5 text-[10px] leading-relaxed text-muted">
        <CircleHelp size={13} className="mt-0.5 shrink-0 text-azure" />
        <span>
          {meta.auth} Interface hints are required for OpenWrt/Linux shaping and pfSense rule
          creation. Everything is verified by reading the gateway back.
        </span>
      </div>

      {error && (
        <div className="mt-3 rounded-xl border border-rose/25 bg-rose/5 px-3 py-2.5 text-[11px] text-rose">
          {error}
        </div>
      )}

      <div className="mt-5 flex justify-end gap-2">
        <button className="btn-ghost" onClick={onClose} disabled={busy}>
          Cancel
        </button>
        <button className="btn-primary" onClick={submit} disabled={busy || !canSubmit}>
          {busy ? <Loader2 size={14} className="animate-spin" /> : <Check size={14} />}
          {editing ? "Save changes" : "Add gateway"}
        </button>
      </div>
    </Modal>
  );
}
