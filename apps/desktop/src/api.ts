import type {
  ActionResult,
  AccessRule,
  AppSettings,
  AuditLog,
  AuthSession,
  BandwidthRequest,
  BandwidthRule,
  DashboardSummary,
  Device,
  DeviceDetail,
  DeviceFilter,
  EnforcementResult,
  GatewayInput,
  GatewayProbe,
  GatewayView,
  MonitoringSample,
  NetworkInterface,
  Paged,
  RestrictionRequest,
  ScanRequest,
  ScanResult,
  SystemStatus,
  TrafficOverview,
  UserSummary,
} from "./types";

const TOKEN_KEY = "netcontrol.token";
const SERVER_KEY = "netcontrol.server";
const DEFAULT_SERVER = import.meta.env.VITE_API_URL || "http://127.0.0.1:8787/api/v1";

export const isTauri = (): boolean =>
  typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

function tauriInvoke<T>(command: string, args?: Record<string, unknown>): Promise<T> {
  const internals = (window as unknown as {
    __TAURI_INTERNALS__: { invoke: (cmd: string, args?: unknown) => Promise<unknown> };
  }).__TAURI_INTERNALS__;
  return internals.invoke(command, args) as Promise<T>;
}

export class ApiError extends Error {
  status: number;
  constructor(message: string, status = 0) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

export function getToken(): string | null {
  return sessionStorage.getItem(TOKEN_KEY);
}

export function clearToken() {
  sessionStorage.removeItem(TOKEN_KEY);
}

export function getServer(): string {
  return localStorage.getItem(SERVER_KEY) || DEFAULT_SERVER;
}

export function setServer(server: string) {
  localStorage.setItem(SERVER_KEY, server.replace(/\/+$/, ""));
}

async function request<T>(
  path: string,
  options: { method?: string; body?: unknown; auth?: boolean } = {},
): Promise<T> {
  const token = getToken();
  const headers: Record<string, string> = { Accept: "application/json" };
  if (options.body !== undefined) headers["Content-Type"] = "application/json";
  if (token) headers.Authorization = `Bearer ${token}`;
  const response = await fetch(`${getServer()}${path}`, {
    method: options.method ?? "GET",
    headers,
    body: options.body !== undefined ? JSON.stringify(options.body) : undefined,
  });
  if (response.status === 401 && options.auth !== false) {
    clearToken();
  }
  if (!response.ok) {
    let message = `Request failed (HTTP ${response.status})`;
    try {
      const parsed = await response.json();
      message = parsed?.error?.message || message;
    } catch {
      /* keep default */
    }
    throw new ApiError(message, response.status);
  }
  if (response.status === 204) return undefined as T;
  const text = await response.text();
  if (!text) return undefined as T;
  return JSON.parse(text) as T;
}

function local<T>(command: string, args?: Record<string, unknown>): Promise<T> {
  return tauriInvoke<T>(command, args).catch((error) => {
    throw new ApiError(typeof error === "string" ? error : String(error));
  });
}

function queryString(filter: DeviceFilter): string {
  const params = new URLSearchParams();
  if (filter.query) params.set("query", filter.query);
  if (filter.online !== undefined) params.set("online", String(filter.online));
  if (filter.blocked !== undefined) params.set("blocked", String(filter.blocked));
  if (filter.trusted !== undefined) params.set("trusted", String(filter.trusted));
  if (filter.category) params.set("category", filter.category);
  if (filter.interface) params.set("interface", filter.interface);
  if (filter.sort) params.set("sort", filter.sort);
  if (filter.order) params.set("order", filter.order);
  if (filter.limit) params.set("limit", String(filter.limit));
  if (filter.offset) params.set("offset", String(filter.offset));
  const qs = params.toString();
  return qs ? `?${qs}` : "";
}

export const api = {
  localMode: isTauri(),

  async login(username: string, password: string, server?: string): Promise<AuthSession> {
    if (server) setServer(server);
    if (isTauri()) {
      return {
        token: "local",
        expires_at: "",
        user: {
          id: "local",
          username: "local administrator",
          role: "admin",
          created_at: new Date().toISOString(),
          disabled: false,
        },
      };
    }
    const session = await request<AuthSession>("/auth/login", {
      method: "POST",
      body: { username, password },
      auth: false,
    });
    sessionStorage.setItem(TOKEN_KEY, session.token);
    return session;
  },

  async logout(): Promise<void> {
    if (isTauri()) return;
    try {
      await request("/auth/logout", { method: "POST" });
    } finally {
      clearToken();
    }
  },

  async me(): Promise<UserSummary | null> {
    if (isTauri()) {
      return {
        id: "local",
        username: "local administrator",
        role: "admin",
        created_at: "",
        disabled: false,
      };
    }
    if (!getToken()) return null;
    try {
      return await request<UserSummary>("/auth/me");
    } catch {
      return null;
    }
  },

  async dashboard(): Promise<DashboardSummary> {
    if (isTauri()) return local<DashboardSummary>("local_dashboard");
    return request<DashboardSummary>("/dashboard");
  },

  async interfaces(): Promise<NetworkInterface[]> {
    if (isTauri()) return local<NetworkInterface[]>("local_interfaces");
    return request<NetworkInterface[]>("/interfaces");
  },

  async devices(filter: DeviceFilter = {}): Promise<Paged<Device>> {
    if (isTauri()) return local<Paged<Device>>("local_devices", { filter });
    return request<Paged<Device>>(`/devices${queryString(filter)}`);
  },

  async deviceDetail(id: string): Promise<DeviceDetail> {
    if (isTauri()) return local<DeviceDetail>("local_device_detail", { id });
    return request<DeviceDetail>(`/devices/${encodeURIComponent(id)}`);
  },

  async scan(body: ScanRequest): Promise<ScanResult> {
    if (isTauri()) return local<ScanResult>("local_scan", { request: body });
    return request<ScanResult>("/scans", { method: "POST", body });
  },

  async updateDevice(
    id: string,
    patch: { custom_name?: string | null; category?: string; notes?: string | null; is_trusted?: boolean },
  ): Promise<Device> {
    if (isTauri()) return local<Device>("local_update_device", { id, patch });
    return request<Device>(`/devices/${encodeURIComponent(id)}`, {
      method: "PATCH",
      body: patch,
    });
  },

  async trust(id: string, trusted: boolean): Promise<Device> {
    if (isTauri()) return local<Device>("local_trust_device", { id, trusted });
    return request<Device>(`/devices/${encodeURIComponent(id)}/trust`, {
      method: "POST",
      body: { trusted },
    });
  },

  async block(id: string, body: RestrictionRequest): Promise<ActionResult> {
    if (isTauri()) return local<ActionResult>("local_block_device", { id, request: body });
    return request<ActionResult>(`/devices/${encodeURIComponent(id)}/block`, {
      method: "POST",
      body,
    });
  },

  async pause(id: string, body: RestrictionRequest): Promise<ActionResult> {
    if (isTauri()) return local<ActionResult>("local_pause_device", { id, request: body });
    return request<ActionResult>(`/devices/${encodeURIComponent(id)}/pause`, {
      method: "POST",
      body,
    });
  },

  async unblock(id: string): Promise<ActionResult> {
    if (isTauri()) return local<ActionResult>("local_unblock_device", { id });
    return request<ActionResult>(`/devices/${encodeURIComponent(id)}/unblock`, {
      method: "POST",
      body: { confirm: true },
    });
  },

  async setLimit(id: string, body: BandwidthRequest): Promise<ActionResult> {
    if (isTauri()) return local<ActionResult>("local_set_limit", { id, request: body });
    return request<ActionResult>(`/devices/${encodeURIComponent(id)}/bandwidth`, {
      method: "POST",
      body,
    });
  },

  async clearLimit(id: string): Promise<ActionResult> {
    if (isTauri()) return local<ActionResult>("local_clear_limit", { id });
    return request<ActionResult>(`/devices/${encodeURIComponent(id)}/bandwidth`, {
      method: "DELETE",
      body: { confirm: true },
    });
  },

  async accessRules(): Promise<AccessRule[]> {
    if (isTauri()) return local<AccessRule[]>("local_access_rules");
    return request<AccessRule[]>("/access-rules");
  },

  async bandwidthRules(): Promise<BandwidthRule[]> {
    if (isTauri()) return local<BandwidthRule[]>("local_bandwidth_rules");
    return request<BandwidthRule[]>("/bandwidth-rules");
  },

  async monitoringOverview(): Promise<TrafficOverview> {
    if (isTauri()) return local<TrafficOverview>("local_monitoring_overview");
    return request<TrafficOverview>("/monitoring/overview");
  },

  async monitoringHistory(minutes = 60, limit = 1200, iface?: string): Promise<MonitoringSample[]> {
    if (isTauri()) {
      return local<MonitoringSample[]>("local_monitoring_history", { minutes, limit, iface });
    }
    const params = new URLSearchParams({ minutes: String(minutes), limit: String(limit) });
    if (iface) params.set("interface", iface);
    return request<MonitoringSample[]>(`/monitoring/history?${params.toString()}`);
  },

  async gateways(): Promise<GatewayView[]> {
    if (isTauri()) return local<GatewayView[]>("local_gateways");
    return request<GatewayView[]>("/gateways");
  },

  async gatewayStatus(): Promise<GatewayProbe | null> {
    if (isTauri()) return local<GatewayProbe | null>("local_gateway_status");
    return request<GatewayProbe | null>("/gateway/status");
  },

  async createGateway(input: GatewayInput): Promise<GatewayView> {
    if (isTauri()) return local<GatewayView>("local_create_gateway", { input });
    return request<GatewayView>("/gateways", { method: "POST", body: input });
  },

  async updateGateway(id: string, input: GatewayInput): Promise<GatewayView> {
    if (isTauri()) return local<GatewayView>("local_update_gateway", { id, input });
    return request<GatewayView>(`/gateways/${encodeURIComponent(id)}`, {
      method: "PUT",
      body: input,
    });
  },

  async deleteGateway(id: string): Promise<void> {
    if (isTauri()) {
      await local<void>("local_delete_gateway", { id });
      return;
    }
    await request<void>(`/gateways/${encodeURIComponent(id)}`, { method: "DELETE" });
  },

  async testGateway(id: string): Promise<GatewayProbe> {
    if (isTauri()) return local<GatewayProbe>("local_test_gateway", { id });
    return request<GatewayProbe>(`/gateways/${encodeURIComponent(id)}/test`, { method: "POST" });
  },

  async activateGateway(id: string): Promise<void> {
    if (isTauri()) {
      await local<void>("local_activate_gateway", { id });
      return;
    }
    await request<void>(`/gateways/${encodeURIComponent(id)}/activate`, { method: "POST" });
  },

  async settings(): Promise<AppSettings> {
    if (isTauri()) return local<AppSettings>("local_settings");
    return request<AppSettings>("/settings");
  },

  async saveSettings(settings: AppSettings): Promise<AppSettings> {
    if (isTauri()) return local<AppSettings>("local_save_settings", { settings });
    return request<AppSettings>("/settings", { method: "PUT", body: settings });
  },

  async audit(limit = 100): Promise<AuditLog[]> {
    if (isTauri()) return local<AuditLog[]>("local_audit", { limit });
    return request<AuditLog[]>(`/audit?limit=${limit}`);
  },

  async systemStatus(): Promise<SystemStatus> {
    if (isTauri()) return local<SystemStatus>("local_system_status");
    return request<SystemStatus>("/system/status");
  },

  eventStreamUrl(): string | null {
    const token = getToken();
    if (!token) return null;
    return `${getServer()}/events?token=${encodeURIComponent(token)}`;
  },
};

export type { EnforcementResult };
