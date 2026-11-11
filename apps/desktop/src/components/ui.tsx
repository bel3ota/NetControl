import { useEffect, useId, useMemo, useRef } from "react";
import { createPortal } from "react-dom";
import clsx from "clsx";
import {
  Activity,
  Ban,
  Box,
  Camera,
  CheckCircle2,
  CircleHelp,
  Cpu,
  Gamepad2,
  HardDrive,
  Laptop,
  Monitor,
  MonitorSmartphone,
  Network,
  Printer,
  Radio,
  Router,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Smartphone,
  Speaker,
  Tablet,
  Tv,
  Watch,
  X,
  Zap,
} from "lucide-react";
import type { DeviceCategory, EnforcementState, MonitoringSample } from "../types";
import { formatBps, formatKbps, relativeTime } from "../lib/format";

export function Logo({ size = 34, className }: { size?: number; className?: string }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 48 48"
      fill="none"
      className={className}
      aria-hidden
    >
      <path
        d="M24 2.5 42 9.6v12.7c0 10.9-7.1 19.4-18 23.2C13.1 41.7 6 33.2 6 22.3V9.6L24 2.5Z"
        stroke="currentColor"
        strokeWidth="1.6"
        opacity=".55"
      />
      <circle cx="24" cy="24" r="9.5" stroke="currentColor" strokeWidth="1.3" opacity=".35" />
      <circle cx="24" cy="24" r="4.6" stroke="currentColor" strokeWidth="1.6" />
      <path d="M24 24 35 13" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" />
      <circle cx="24" cy="24" r="1.8" fill="currentColor" />
      <circle cx="35" cy="13" r="2.4" fill="currentColor" />
    </svg>
  );
}

const GLYPHS: Record<string, React.ComponentType<{ size?: number; className?: string; strokeWidth?: number }>> = {
  smartphone: Smartphone,
  tablet: Tablet,
  laptop: Laptop,
  desktop: Monitor,
  server: HardDrive,
  printer: Printer,
  smart_tv: Tv,
  streaming: Tv,
  router: Router,
  switch: Network,
  access_point: Radio,
  camera: Camera,
  speaker: Speaker,
  game_console: Gamepad2,
  wearable: Watch,
  iot: Cpu,
  nas: Box,
  unknown: CircleHelp,
};

export function DeviceGlyph({
  category,
  size = 17,
  className,
}: {
  category: DeviceCategory | string;
  size?: number;
  className?: string;
}) {
  const Glyph = GLYPHS[category] ?? CircleHelp;
  return <Glyph size={size} strokeWidth={1.7} className={className} />;
}

export function CategoryGlyph({ category }: { category: DeviceCategory | string }) {
  return (
    <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg border border-line bg-raised text-muted">
      <DeviceGlyph category={category} />
    </span>
  );
}

export function Dot({ online, pulse = false }: { online: boolean; pulse?: boolean }) {
  return (
    <span className="relative flex h-2 w-2 shrink-0">
      {online && pulse && (
        <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-success opacity-40" />
      )}
      <span
        className={clsx(
          "relative inline-flex h-2 w-2 rounded-full",
          online ? "bg-success" : "bg-faint/60",
        )}
      />
    </span>
  );
}

export function Pill({
  children,
  tone = "neutral",
  className,
}: {
  children: React.ReactNode;
  tone?: "neutral" | "success" | "danger" | "warning" | "info" | "violet";
  className?: string;
}) {
  const tones = {
    neutral: "border-line bg-raised/70 text-muted",
    success: "border-success/25 bg-success/10 text-success",
    danger: "border-rose/25 bg-rose/10 text-rose",
    warning: "border-amber/25 bg-amber/10 text-amber",
    info: "border-azure/25 bg-azure/10 text-azure",
    violet: "border-violet/25 bg-violet/10 text-violet",
  };
  return (
    <span
      className={clsx(
        "inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-[11px] font-medium",
        tones[tone],
        className,
      )}
    >
      {children}
    </span>
  );
}

export function EnforcementBadge({ state }: { state: EnforcementState }) {
  switch (state) {
    case "applied":
      return (
        <Pill tone="success">
          <CheckCircle2 size={11} /> Enforced
        </Pill>
      );
    case "failed":
      return (
        <Pill tone="danger">
          <ShieldAlert size={11} /> Failed
        </Pill>
      );
    case "unsupported":
      return (
        <Pill tone="warning">
          <CircleHelp size={11} /> Unsupported
        </Pill>
      );
    case "pending":
      return (
        <Pill tone="info">
          <Activity size={11} /> Pending
        </Pill>
      );
    case "expired":
      return <Pill>Expired</Pill>;
    default:
      return <span className="text-xs text-faint">—</span>;
  }
}

export function AccessBadge({
  blocked,
  trusted,
}: {
  blocked: boolean;
  trusted: boolean;
}) {
  if (blocked)
    return (
      <Pill tone="danger">
        <Ban size={11} /> Blocked
      </Pill>
    );
  if (trusted)
    return (
      <Pill tone="success">
        <ShieldCheck size={11} /> Trusted
      </Pill>
    );
  return <Pill>Allowed</Pill>;
}

export function Sparkline({
  values,
  color = "#3FE0AE",
  className,
}: {
  values: number[];
  color?: string;
  className?: string;
}) {
  const id = useId().replace(/[:]/g, "");
  const points = useMemo(() => {
    if (values.length === 0) return "";
    const max = Math.max(...values, 1);
    return values
      .map((value, index) => {
        const x = (index / Math.max(values.length - 1, 1)) * 100;
        const y = 28 - (value / max) * 24;
        return `${x},${y}`;
      })
      .join(" ");
  }, [values]);
  return (
    <svg viewBox="0 0 100 30" preserveAspectRatio="none" className={clsx("h-8 w-full", className)}>
      <defs>
        <linearGradient id={`spark-${id}`} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity=".28" />
          <stop offset="100%" stopColor={color} stopOpacity="0" />
        </linearGradient>
      </defs>
      {points && (
        <>
          <polygon points={`0,30 ${points} 100,30`} fill={`url(#spark-${id})`} />
          <polyline points={points} fill="none" stroke={color} strokeWidth="1.6" vectorEffect="non-scaling-stroke" />
        </>
      )}
    </svg>
  );
}

export function TrafficChart({
  samples,
  height = 220,
  showLegend = true,
}: {
  samples: MonitoringSample[];
  height?: number;
  showLegend?: boolean;
}) {
  const rx = samples.map((s) => s.rx_bps);
  const tx = samples.map((s) => s.tx_bps);
  const max = Math.max(...rx, ...tx, 1);
  const width = 900;
  const h = 260;
  const pad = { top: 18, right: 8, bottom: 26, left: 8 };
  const toPath = (values: number[]) => {
    if (values.length === 0) return "";
    const usableW = width - pad.left - pad.right;
    const usableH = h - pad.top - pad.bottom;
    return values
      .map((value, index) => {
        const x = pad.left + (index / Math.max(values.length - 1, 1)) * usableW;
        const y = pad.top + usableH - (value / max) * usableH;
        return `${index === 0 ? "M" : "L"}${x.toFixed(1)},${y.toFixed(1)}`;
      })
      .join(" ");
  };
  const rxPath = toPath(rx);
  const txPath = toPath(tx);
  const areaPath =
    rxPath && `${rxPath} L${width - pad.right},${h - pad.bottom} L${pad.left},${h - pad.bottom} Z`;
  const id = useId().replace(/[:]/g, "");
  const labels = samples.length
    ? [samples[0], samples[Math.floor(samples.length / 2)], samples[samples.length - 1]]
    : [];
  return (
    <div>
      <div className="relative">
        <svg
          viewBox={`0 0 ${width} ${h}`}
          style={{ height }}
          className="w-full"
          preserveAspectRatio="none"
          role="img"
          aria-label="Measured network throughput"
        >
          <defs>
            <linearGradient id={`area-${id}`} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#3FE0AE" stopOpacity=".30" />
              <stop offset="100%" stopColor="#3FE0AE" stopOpacity="0" />
            </linearGradient>
            <linearGradient id={`line-${id}`} x1="0" y1="0" x2="1" y2="0">
              <stop offset="0%" stopColor="#2FD5A4" />
              <stop offset="100%" stopColor="#7CF0CE" />
            </linearGradient>
          </defs>
          {[0.25, 0.5, 0.75, 1].map((ratio) => {
            const y = pad.top + (h - pad.top - pad.bottom) * (1 - ratio);
            return (
              <g key={ratio}>
                <line
                  x1={pad.left}
                  x2={width - pad.right}
                  y1={y}
                  y2={y}
                  stroke="#1A2A38"
                  strokeDasharray="3 6"
                />
                <text x={pad.left} y={y - 4} fill="#5B7082" fontSize="9" fontFamily="JetBrains Mono">
                  {formatBps(max * ratio)}
                </text>
              </g>
            );
          })}
          {areaPath && <path d={areaPath} fill={`url(#area-${id})`} />}
          {txPath && (
            <path
              d={txPath}
              fill="none"
              stroke="#5C9DFF"
              strokeWidth="1.4"
              opacity=".8"
              vectorEffect="non-scaling-stroke"
            />
          )}
          {rxPath && (
            <path
              d={rxPath}
              fill="none"
              stroke={`url(#line-${id})`}
              strokeWidth="1.8"
              vectorEffect="non-scaling-stroke"
            />
          )}
          {rx.length > 0 && (
            <>
              <circle
                cx={width - pad.right}
                cy={pad.top + (h - pad.top - pad.bottom) * (1 - rx[rx.length - 1] / max)}
                r="3"
                fill="#3FE0AE"
              />
              <circle
                cx={width - pad.right}
                cy={pad.top + (h - pad.top - pad.bottom) * (1 - tx[tx.length - 1] / max)}
                r="2.5"
                fill="#5C9DFF"
              />
            </>
          )}
          {labels.map((sample, index) => (
            <text
              key={index}
              x={pad.left + (index / 2) * (width - pad.left - pad.right)}
              y={h - 7}
              textAnchor={index === 0 ? "start" : index === 2 ? "end" : "middle"}
              fill="#5B7082"
              fontSize="9"
              fontFamily="JetBrains Mono"
            >
              {new Date(sample.ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
            </text>
          ))}
        </svg>
        {samples.length < 2 && (
          <div className="absolute inset-0 flex items-center justify-center">
            <p className="text-xs text-faint">Collecting live samples…</p>
          </div>
        )}
      </div>
      {showLegend && (
        <div className="mt-1 flex items-center gap-5 text-[11px] text-muted">
          <span className="inline-flex items-center gap-1.5">
            <span className="h-1 w-4 rounded bg-mint" /> Download
          </span>
          <span className="inline-flex items-center gap-1.5">
            <span className="h-1 w-4 rounded bg-azure" /> Upload
          </span>
          <span className="ml-auto text-faint">measured interface counters</span>
        </div>
      )}
    </div>
  );
}

export function Skeleton({ className }: { className?: string }) {
  return <div className={clsx("skeleton", className)} />;
}

export function EmptyState({
  icon: Icon = Shield,
  title,
  description,
  action,
}: {
  icon?: React.ComponentType<{ size?: number; className?: string }>;
  title: string;
  description: string;
  action?: React.ReactNode;
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 px-6 py-14 text-center">
      <div className="flex h-12 w-12 items-center justify-center rounded-2xl border border-line bg-raised text-faint">
        <Icon size={22} />
      </div>
      <div>
        <h3 className="font-display text-sm font-semibold text-ink">{title}</h3>
        <p className="mt-1 max-w-sm text-xs leading-relaxed text-muted">{description}</p>
      </div>
      {action}
    </div>
  );
}

export function Modal({
  open,
  onClose,
  title,
  subtitle,
  children,
  width = "max-w-lg",
}: {
  open: boolean;
  onClose: () => void;
  title: string;
  subtitle?: string;
  children: React.ReactNode;
  width?: string;
}) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const handler = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    document.addEventListener("keydown", handler);
    document.body.style.overflow = "hidden";
    return () => {
      document.removeEventListener("keydown", handler);
      document.body.style.overflow = "";
    };
  }, [open, onClose]);
  if (!open) return null;
  return createPortal(
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div
        className="absolute inset-0 bg-[#02060A]/80 backdrop-blur-sm"
        onClick={() => onClose()}
      />
      <div
        ref={ref}
        className={clsx(
          "panel relative z-10 w-full animate-fade-up overflow-hidden border-line-strong",
          width,
        )}
        role="dialog"
        aria-modal="true"
      >
        <div className="flex items-start justify-between border-b border-line px-5 py-4">
          <div>
            <h2 className="font-display text-base font-semibold text-ink">{title}</h2>
            {subtitle && <p className="mt-0.5 text-xs text-muted">{subtitle}</p>}
          </div>
          <button
            className="rounded-lg p-1.5 text-faint transition hover:bg-raised hover:text-ink"
            onClick={onClose}
            aria-label="Close"
          >
            <X size={16} />
          </button>
        </div>
        <div className="max-h-[75vh] overflow-y-auto px-5 py-4">{children}</div>
      </div>
    </div>,
    document.body,
  );
}

export function ConfirmDialog({
  open,
  title,
  description,
  confirmLabel = "Confirm",
  danger = false,
  busy = false,
  onConfirm,
  onCancel,
  children,
}: {
  open: boolean;
  title: string;
  description: string;
  confirmLabel?: string;
  danger?: boolean;
  busy?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
  children?: React.ReactNode;
}) {
  return (
    <Modal open={open} onClose={onCancel} title={title} subtitle={description} width="max-w-md">
      {children}
      <div className="mt-5 flex justify-end gap-2">
        <button className="btn-ghost" onClick={onCancel} disabled={busy}>
          Cancel
        </button>
        <button
          className={danger ? "btn-danger" : "btn-primary"}
          onClick={onConfirm}
          disabled={busy}
        >
          {busy ? "Working…" : confirmLabel}
        </button>
      </div>
    </Modal>
  );
}

export function CapabilityRow({
  label,
  supported,
  detail,
}: {
  label: string;
  supported: boolean;
  detail?: string;
}) {
  return (
    <div className="flex items-center justify-between border-b border-line/60 py-2 last:border-0">
      <div>
        <p className="text-xs text-ink">{label}</p>
        {detail && <p className="mt-0.5 text-[11px] text-faint">{detail}</p>}
      </div>
      <span
        className={clsx(
          "inline-flex items-center gap-1 text-[11px]",
          supported ? "text-success" : "text-faint",
        )}
      >
        {supported ? <CheckCircle2 size={12} /> : <X size={12} />}
        {supported ? "Supported" : "Unavailable"}
      </span>
    </div>
  );
}

export function Rate({
  value,
  direction,
  className,
}: {
  value: number | null;
  direction: "down" | "up";
  className?: string;
}) {
  return (
    <span className={clsx("mono text-[11px]", direction === "down" ? "text-mint" : "text-azure", className)}>
      {direction === "down" ? "↓" : "↑"} {formatBps(value ?? 0)}
    </span>
  );
}

export function LimitLabel({ down, up }: { down: number | null; up: number | null }) {
  if (down === null && up === null) return <span className="text-xs text-faint">—</span>;
  return (
    <span className="mono text-[11px] text-muted">
      ↓ {formatKbps(down)} <span className="mx-1 text-faint">·</span> ↑ {formatKbps(up)}
    </span>
  );
}

export function ActivityIcon({ state }: { state: "success" | "warning" | "danger" | "info" }) {
  const icons = {
    success: ShieldCheck,
    warning: ShieldAlert,
    danger: Ban,
    info: Activity,
  };
  const colors = {
    success: "text-success",
    warning: "text-amber",
    danger: "text-rose",
    info: "text-azure",
  };
  const Icon = icons[state];
  return <Icon size={14} className={colors[state]} />;
}

export function LastSeen({ iso }: { iso: string | null }) {
  return <span className="text-[11px] text-faint">{relativeTime(iso)}</span>;
}

export { MonitorSmartphone, Zap };
