import { useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  Check,
  CircleCheck,
  Loader2,
  Radar,
  ScanLine,
  ShieldCheck,
} from "lucide-react";
import type { DashboardSummary, ScanResult } from "../types";
import { api } from "../api";
import { Modal, Pill } from "./ui";
import { useToast } from "./toast";

const METHODS = [
  { id: "neighbor", label: "Neighbor/ARP cache", hint: "Kernel ARP + NDP table" },
  { id: "icmp", label: "ICMP echo", hint: "Unprivileged ping sweep" },
  { id: "mdns", label: "mDNS / DNS-SD", hint: "Hostnames and service types" },
  { id: "arp", label: "Active ARP", hint: "Raw arp-scan when privileged" },
  { id: "tcp", label: "TCP liveness", hint: "Connect probes on common ports" },
  { id: "nmap", label: "Nmap discovery", hint: "Uses installed nmap binary" },
];

export function ScanDialog({
  open,
  onClose,
  dashboard,
  onComplete,
}: {
  open: boolean;
  onClose: () => void;
  dashboard: DashboardSummary | null;
  onComplete: () => void;
}) {
  const toast = useToast();
  const interfaces = useMemo(
    () =>
      (dashboard?.interfaces ?? []).filter(
        (iface) => !iface.is_loopback && iface.is_up && iface.ipv4.length > 0,
      ),
    [dashboard],
  );
  const [iface, setIface] = useState("");
  const [methods, setMethods] = useState<string[]>(["neighbor", "icmp", "mdns"]);
  const [ports, setPorts] = useState(false);
  const [allowPublic, setAllowPublic] = useState(false);
  const [authorized, setAuthorized] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ScanResult | null>(null);

  useEffect(() => {
    if (!open) return;
    setResult(null);
    setError(null);
    setBusy(false);
    setAuthorized(false);
    const preferred =
      dashboard?.network?.interface ??
      interfaces.find((entry) => entry.is_default)?.name ??
      interfaces[0]?.name ??
      "";
    setIface(preferred);
    setMethods(["neighbor", "icmp", "mdns"]);
  }, [open, dashboard?.network?.interface, interfaces]);

  const target = interfaces.find((entry) => entry.name === iface);
  const nmapEnabled = methods.includes("nmap");
  const arpEnabled = methods.includes("arp");

  const run = async () => {
    if (!authorized) {
      setError("Confirm that you are authorized to scan this network.");
      return;
    }
    if (!iface) {
      setError("Select a network interface.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const response = await api.scan({
        interface: iface,
        methods,
        nmap: nmapEnabled,
        ports,
        mdns: methods.includes("mdns"),
        allow_public: allowPublic,
        confirm: true,
      });
      setResult(response);
      toast.success(
        "Scan complete",
        `${response.report.hosts.length} hosts · ${response.new_devices} new`,
      );
      onComplete();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal
      open={open}
      onClose={() => {
        if (!busy) onClose();
      }}
      title="Discover network devices"
      subtitle="Active probes are sent only to the selected local interface."
      width="max-w-2xl"
    >
      {result ? (
        <div>
          <div className="flex items-start gap-3 rounded-xl border border-success/25 bg-success/5 p-3.5">
            <CircleCheck size={18} className="mt-0.5 text-success" />
            <div className="flex-1">
              <p className="text-sm font-semibold text-ink">
                Scan finished on {result.report.cidr}
              </p>
              <p className="mt-0.5 text-xs text-muted">
                {result.report.hosts.length} hosts · {result.new_devices} new ·{" "}
                {result.report.methods_used.length
                  ? result.report.methods_used.join(", ")
                  : "no probe succeeded"}
              </p>
            </div>
            <Pill tone="success">verified</Pill>
          </div>

          {result.report.warnings.length > 0 && (
            <div className="mt-3 space-y-1.5">
              {result.report.warnings.map((warning) => (
                <div
                  key={warning}
                  className="flex items-start gap-2 rounded-lg border border-amber/20 bg-amber/5 px-3 py-2 text-[11px] text-amber/90"
                >
                  <AlertTriangle size={13} className="mt-0.5 shrink-0" />
                  <span>{warning}</span>
                </div>
              ))}
            </div>
          )}

          <div className="mt-4 max-h-64 overflow-y-auto rounded-xl border border-line">
            {result.devices.slice(0, 30).map((device) => (
              <div
                key={device.id}
                className="flex items-center gap-2 border-b border-line/60 px-3 py-2 last:border-0"
              >
                <span className={`h-1.5 w-1.5 rounded-full ${device.online ? "bg-success" : "bg-faint"}`} />
                <span className="min-w-0 flex-1 truncate text-xs text-ink">
                  {device.custom_name || device.hostname || device.ip}
                </span>
                <span className="mono text-[10px] text-faint">{device.ip}</span>
                <span className="mono text-[10px] text-faint">{device.mac}</span>
              </div>
            ))}
            {result.devices.length === 0 && (
              <p className="px-3 py-6 text-center text-xs text-faint">No devices discovered.</p>
            )}
          </div>
          <div className="mt-4 flex justify-end">
            <button className="btn-primary" onClick={onClose}>
              Done
            </button>
          </div>
        </div>
      ) : (
        <>
          <div className="mb-4 rounded-xl border border-line bg-raised/50 p-3.5">
            <div className="flex items-center gap-2 text-xs text-muted">
              <Radar size={15} className="text-mint" />
              <span>
                Discovery combines kernel neighbor tables, unprivileged ICMP, mDNS, optional
                Nmap and explicit port probes.
              </span>
            </div>
          </div>

          <label className="label">Network interface</label>
          <select
            className="input mb-4"
            value={iface}
            onChange={(event) => setIface(event.target.value)}
            disabled={busy}
          >
            {interfaces.length === 0 && <option value="">No active IPv4 interface</option>}
            {interfaces.map((entry) => (
              <option key={entry.name} value={entry.name}>
                {entry.name} · {entry.ipv4[0]?.cidr} · {entry.kind}
                {entry.is_default ? " · default" : ""}
              </option>
            ))}
          </select>

          {target && (
            <div className="mb-4 grid grid-cols-3 gap-2 rounded-xl border border-line bg-raised/40 p-3">
              <div>
                <p className="eyebrow">Range</p>
                <p className="mt-1 mono text-[11px] text-ink">{target.ipv4[0]?.cidr}</p>
              </div>
              <div>
                <p className="eyebrow">Gateway</p>
                <p className="mt-1 mono text-[11px] text-ink">{target.gateway4 || "-"}</p>
              </div>
              <div className="min-w-0">
                <p className="eyebrow">SSID</p>
                <p className="mt-1 truncate text-[11px] text-ink">{target.ssid || "-"}</p>
              </div>
            </div>
          )}

          <label className="label">Discovery methods</label>
          <div className="mb-4 grid grid-cols-1 gap-2 sm:grid-cols-2">
            {METHODS.map((method) => {
              const checked = methods.includes(method.id);
              return (
                <button
                  key={method.id}
                  type="button"
                  onClick={() =>
                    setMethods((current) =>
                      checked
                        ? current.filter((entry) => entry !== method.id)
                        : [...current, method.id],
                    )
                  }
                  disabled={busy || (method.id === "nmap" && !dashboard?.interfaces.length)}
                  className={`flex items-start gap-2 rounded-xl border p-2.5 text-left transition ${
                    checked
                      ? "border-mint/40 bg-mint/5"
                      : "border-line bg-raised/40 hover:border-line-strong"
                  }`}
                >
                  <span
                    className={`mt-0.5 flex h-4 w-4 items-center justify-center rounded border ${
                      checked ? "border-mint bg-mint text-[#04120D]" : "border-line-strong text-transparent"
                    }`}
                  >
                    <Check size={11} strokeWidth={3} />
                  </span>
                  <span>
                    <span className="block text-xs font-medium text-ink">{method.label}</span>
                    <span className="mt-0.5 block text-[10px] leading-snug text-faint">
                      {method.hint}
                    </span>
                  </span>
                </button>
              );
            })}
          </div>

          {arpEnabled && (
            <p className="mb-3 text-[11px] text-amber/80">
              Active ARP requires root or CAP_NET_RAW; otherwise NetControl falls back to
              kernel ARP priming and reports it.
            </p>
          )}

          <div className="mb-3 flex items-center justify-between rounded-xl border border-line bg-raised/40 px-3 py-2.5">
            <div>
              <p className="text-xs font-medium text-ink">Probe common TCP ports</p>
              <p className="text-[10px] text-faint">
                Explicitly authorized port discovery for discovered hosts
              </p>
            </div>
            <button
              type="button"
              onClick={() => setPorts((value) => !value)}
              disabled={busy}
              className={`relative h-5 w-9 rounded-full transition ${ports ? "bg-mint" : "bg-line-strong"}`}
              aria-pressed={ports}
            >
              <span
                className={`absolute top-0.5 h-4 w-4 rounded-full bg-white transition ${
                  ports ? "left-[18px]" : "left-0.5"
                }`}
              />
            </button>
          </div>

          <details className="mb-3 rounded-xl border border-line bg-raised/30 px-3 py-2">
            <summary className="cursor-pointer text-[11px] text-muted">Advanced</summary>
            <label className="mt-2 flex items-start gap-2 text-[11px] text-muted">
              <input
                type="checkbox"
                checked={allowPublic}
                onChange={(event) => setAllowPublic(event.target.checked)}
                className="mt-0.5 accent-[#3FE0AE]"
              />
              Permit scanning non-private address space (requires explicit authorization)
            </label>
          </details>

          <label className="flex items-start gap-2 rounded-xl border border-line bg-raised/40 p-3 text-[11px] leading-relaxed text-muted">
            <input
              type="checkbox"
              checked={authorized}
              onChange={(event) => setAuthorized(event.target.checked)}
              className="mt-0.5 accent-[#3FE0AE]"
            />
            <span>
              I am authorized to scan this network. NetControl will not scan public address
              space unless the advanced option is enabled.
            </span>
          </label>

          {error && (
            <div className="mt-3 flex items-start gap-2 rounded-xl border border-rose/25 bg-rose/5 px-3 py-2.5 text-[11px] text-rose">
              <AlertTriangle size={14} className="mt-0.5 shrink-0" />
              <span>{error}</span>
            </div>
          )}

          <div className="mt-5 flex items-center justify-between">
            <span className="inline-flex items-center gap-1.5 text-[10px] text-faint">
              <ShieldCheck size={12} /> scope guard enforced
            </span>
            <div className="flex gap-2">
              <button className="btn-ghost" onClick={onClose} disabled={busy}>
                Cancel
              </button>
              <button className="btn-primary" onClick={run} disabled={busy || !authorized || !iface}>
                {busy ? <Loader2 size={15} className="animate-spin" /> : <ScanLine size={15} />}
                {busy ? "Scanning…" : "Start scan"}
              </button>
            </div>
          </div>
        </>
      )}
    </Modal>
  );
}
