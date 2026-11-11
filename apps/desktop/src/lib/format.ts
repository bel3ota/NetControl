export const CATEGORY_LABEL: Record<string, string> = {
  smartphone: "Smartphone",
  tablet: "Tablet",
  laptop: "Laptop",
  desktop: "Desktop",
  server: "Server",
  printer: "Printer",
  smart_tv: "Smart TV",
  streaming: "Streaming",
  router: "Router",
  switch: "Switch",
  access_point: "Access point",
  camera: "Camera",
  speaker: "Speaker",
  game_console: "Console",
  wearable: "Wearable",
  iot: "IoT",
  nas: "NAS",
  unknown: "Unknown",
};

export function formatBytes(bytes: number | null | undefined, perSecond = false): string {
  if (bytes === null || bytes === undefined || !Number.isFinite(bytes)) return "-";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = Math.max(0, bytes);
  let idx = 0;
  while (value >= 1000 && idx < units.length - 1) {
    value /= 1000;
    idx += 1;
  }
  const suffix = perSecond ? "/s" : "";
  return idx === 0 ? `${value.toFixed(0)} B${suffix}` : `${value.toFixed(2)} ${units[idx]}${suffix}`;
}

export function formatBps(bps: number | null | undefined): string {
  if (bps === null || bps === undefined || !Number.isFinite(bps)) return "-";
  const units = ["bps", "Kbps", "Mbps", "Gbps", "Tbps"];
  let value = Math.max(0, bps);
  let idx = 0;
  while (value >= 1000 && idx < units.length - 1) {
    value /= 1000;
    idx += 1;
  }
  return idx === 0 ? `${value.toFixed(0)} bps` : `${value.toFixed(2)} ${units[idx]}`;
}

export function formatKbps(kbps: number | null | undefined): string {
  if (kbps === null || kbps === undefined || kbps <= 0) return "Unlimited";
  if (kbps >= 1_000_000) return `${(kbps / 1_000_000).toFixed(2)} Gbps`;
  if (kbps >= 1_000) return `${(kbps / 1_000).toFixed(2)} Mbps`;
  return `${kbps} Kbps`;
}

export function relativeTime(iso: string | null | undefined): string {
  if (!iso) return "-";
  const then = new Date(iso).getTime();
  if (!Number.isFinite(then)) return "-";
  const seconds = Math.max(0, Math.floor((Date.now() - then) / 1000));
  if (seconds < 10) return "just now";
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

export function formatDate(iso: string | null | undefined): string {
  if (!iso) return "-";
  const date = new Date(iso);
  if (!Number.isFinite(date.getTime())) return iso;
  return date.toLocaleString(undefined, {
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function formatDuration(seconds: number): string {
  if (seconds >= 86400 && seconds % 86400 === 0) return `${seconds / 86400}d`;
  if (seconds >= 3600 && seconds % 3600 === 0) return `${seconds / 3600}h`;
  if (seconds >= 60 && seconds % 60 === 0) return `${seconds / 60}m`;
  return `${seconds}s`;
}

export function deviceName(device: {
  custom_name: string | null;
  hostname: string | null;
  ip: string | null;
  mac: string | null;
}): string {
  return device.custom_name || device.hostname || device.ip || device.mac || "Unnamed device";
}

export function categoryIconName(category: string): string {
  return category;
}

export function bpsToKbps(value: string, unit: string): number | null {
  const parsed = Number.parseFloat(value);
  if (!Number.isFinite(parsed) || parsed < 0) return null;
  const multiplier = unit === "Gbps" ? 1_000_000 : unit === "Mbps" ? 1_000 : 1;
  const kbps = Math.round(parsed * multiplier);
  return kbps > 0 ? kbps : null;
}
