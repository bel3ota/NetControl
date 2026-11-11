import { useCallback, useEffect, useRef, useState } from "react";
import type { DashboardSummary, UserSummary } from "./types";
import { api, ApiError } from "./api";
import { Layout, type Page } from "./components/Layout";
import { ScanDialog } from "./components/ScanDialog";
import { Logo } from "./components/ui";
import { Login } from "./pages/Login";
import { Dashboard } from "./pages/Dashboard";
import { Devices } from "./pages/Devices";
import { Monitoring } from "./pages/Monitoring";
import { AccessControl } from "./pages/AccessControl";
import { Gateways } from "./pages/Gateways";
import { Settings } from "./pages/Settings";

function pageFromHash(): Page {
  const raw = window.location.hash.replace(/^#\/?/, "");
  return (["dashboard", "devices", "monitoring", "access", "gateways", "settings"] as Page[]).includes(
    raw as Page,
  )
    ? (raw as Page)
    : "dashboard";
}

export default function App() {
  const [user, setUser] = useState<UserSummary | null | undefined>(undefined);
  const [page, setPage] = useState<Page>(pageFromHash());

  useEffect(() => {
    let active = true;
    api.me().then((session) => {
      if (!active) return;
      if (session && !api.localMode && !sessionStorage.getItem("netcontrol.token")) {
        setUser(null);
      } else {
        setUser(session);
      }
    });
    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    const listener = () => setPage(pageFromHash());
    window.addEventListener("hashchange", listener);
    return () => window.removeEventListener("hashchange", listener);
  }, []);

  const navigate = (next: Page) => {
    window.location.hash = `#/${next}`;
    setPage(next);
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

  if (user === undefined) {
    return (
      <div className="flex min-h-screen flex-col items-center justify-center gap-4">
        <span className="animate-pulse-soft text-mint">
          <Logo size={46} />
        </span>
        <p className="font-mono text-[10px] uppercase tracking-[0.25em] text-faint">
          Connecting to NetControl
        </p>
      </div>
    );
  }

  if (!user) {
    return <Login onLogin={(session) => setUser(session)} />;
  }

  return (
    <Shell
      user={user}
      page={page}
      onNavigate={navigate}
      onLogout={async () => {
        await api.logout();
        setUser(null);
      }}
    />
  );
}

function Shell({
  user,
  page,
  onNavigate,
  onLogout,
}: {
  user: UserSummary;
  page: Page;
  onNavigate: (page: Page) => void;
  onLogout: () => void;
}) {
  const [dashboard, setDashboard] = useState<DashboardSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [live, setLive] = useState(false);
  const [scanOpen, setScanOpen] = useState(false);
  const [serviceError, setServiceError] = useState<string | null>(null);
  const lastUpdate = useRef<number>(0);
  const debounce = useRef<number | null>(null);

  const load = useCallback(async (silent = false) => {
    if (!silent) setRefreshing(true);
    try {
      const data = await api.dashboard();
      setDashboard(data);
      setServiceError(null);
      lastUpdate.current = Date.now();
      if (Date.now() - lastUpdate.current < 15000) {
        // A successful poll is our liveness signal in Tauri mode.
        setLive(true);
      }
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        onLogout();
        return;
      }
      setServiceError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [onLogout]);

  useEffect(() => {
    load();
    const timer = window.setInterval(() => load(true), 6000);
    return () => window.clearInterval(timer);
  }, [load]);

  useEffect(() => {
    const interval = window.setInterval(() => {
      if (Date.now() - lastUpdate.current > 20000) setLive(false);
    }, 5000);
    return () => window.clearInterval(interval);
  }, []);

  useEffect(() => {
    if (api.localMode) return;
    const url = api.eventStreamUrl();
    if (!url) return;
    const source = new EventSource(url);
    source.addEventListener("netcontrol", (event) => {
      lastUpdate.current = Date.now();
      setLive(true);
      try {
        const payload = JSON.parse((event as MessageEvent).data) as {
          type: string;
          overview?: DashboardSummary["traffic"];
        };
        if (payload.type === "monitoring" && payload.overview) {
          setDashboard((current) =>
            current ? { ...current, traffic: payload.overview! } : current,
          );
          return;
        }
        if (debounce.current) window.clearTimeout(debounce.current);
        debounce.current = window.setTimeout(() => load(true), 1200);
      } catch {
        /* ignore malformed stream frames */
      }
    });
    source.onerror = () => {
      setLive(false);
    };
    return () => {
      source.close();
      if (debounce.current) window.clearTimeout(debounce.current);
    };
  }, [load]);

  const onChanged = useCallback(() => {
    load(true);
  }, [load]);

  return (
    <>
      <Layout
        page={page}
        onNavigate={onNavigate}
        dashboard={dashboard}
        user={user}
        onLogout={onLogout}
        onScan={() => setScanOpen(true)}
        onRefresh={() => load()}
        refreshing={refreshing}
        live={live}
      >
        {serviceError && (
          <div className="mb-4 flex items-center justify-between gap-3 rounded-xl border border-rose/25 bg-rose/5 px-3.5 py-2.5 text-[11px] text-rose">
            <span>Management service: {serviceError}</span>
            <button className="font-medium underline" onClick={() => load()}>
              Retry
            </button>
          </div>
        )}
        {page === "dashboard" && (
          <Dashboard
            dashboard={dashboard}
            loading={loading}
            onNavigate={onNavigate}
            onScan={() => setScanOpen(true)}
            onRefresh={() => load()}
          />
        )}
        {page === "devices" && (
          <Devices
            dashboard={dashboard}
            onChanged={onChanged}
            onScan={() => setScanOpen(true)}
          />
        )}
        {page === "monitoring" && <Monitoring dashboard={dashboard} />}
        {page === "access" && <AccessControl dashboard={dashboard} onChanged={onChanged} />}
        {page === "gateways" && <Gateways onChanged={onChanged} />}
        {page === "settings" && <Settings dashboard={dashboard} user={user} />}
      </Layout>

      <ScanDialog
        open={scanOpen}
        onClose={() => setScanOpen(false)}
        dashboard={dashboard}
        onComplete={() => {
          load(true);
          onChanged();
        }}
      />
    </>
  );
}

