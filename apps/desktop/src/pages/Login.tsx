import { useState } from "react";
import { ArrowRight, Loader2, LockKeyhole, Server, ShieldCheck } from "lucide-react";
import { api, ApiError } from "../api";
import type { UserSummary } from "../types";
import { Logo } from "../components/ui";

export function Login({ onLogin }: { onLogin: (user: UserSummary) => void }) {
  const [server, setServer] = useState(
    localStorage.getItem("netcontrol.server") || "http://127.0.0.1:8787/api/v1",
  );
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const session = await api.login(username, password, server.trim());
      onLogin(session.user);
    } catch (err) {
      setError(
        err instanceof ApiError
          ? err.message
          : err instanceof Error
            ? err.message
            : "Unable to sign in",
      );
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="grid min-h-screen lg:grid-cols-[1.05fr_.95fr]">
      <section className="relative hidden overflow-hidden border-r border-line bg-[#060B11] p-12 lg:flex lg:flex-col">
        <div
          className="pointer-events-none absolute inset-0 bg-grid-fade opacity-40"
          style={{ backgroundSize: "52px 52px" }}
        />
        <div className="pointer-events-none absolute -left-24 top-1/3 h-[420px] w-[420px] rounded-full border border-mint/10" />
        <div className="pointer-events-none absolute -left-10 top-1/3 h-[300px] w-[300px] rounded-full border border-mint/15" />
        <div className="pointer-events-none absolute left-[80px] top-1/3 h-[180px] w-[180px] animate-sweep rounded-full border border-mint/30" />
        <div className="relative z-10 flex items-center gap-3">
          <span className="text-mint">
            <Logo size={38} />
          </span>
          <div>
            <p className="font-display text-lg font-semibold tracking-wide text-ink">NETCONTROL</p>
            <p className="font-mono text-[9px] uppercase tracking-[0.24em] text-faint">
              network authority
            </p>
          </div>
        </div>

        <div className="relative z-10 mt-auto max-w-lg">
          <p className="eyebrow mb-3">Authorized access only</p>
          <h1 className="font-display text-4xl font-semibold leading-[1.1] tracking-tight text-ink">
            See every device.
            <br />
            Control the ones
            <br />
            <span className="text-mint">that matter.</span>
          </h1>
          <p className="mt-5 max-w-md text-sm leading-relaxed text-muted">
            One shared discovery and enforcement engine for Windows, Linux and Android.
            Real ARP, ICMP and mDNS discovery. Real router-enforced access control - never
            simulated.
          </p>
          <div className="mt-8 grid max-w-md grid-cols-3 gap-3">
            {[
              ["Discovery", "ARP · ICMP · mDNS"],
              ["Enforcement", "OpenWrt · RouterOS"],
              ["Audit", "Every action"],
            ].map(([label, value]) => (
              <div key={label} className="rounded-xl border border-line bg-panel/50 p-3">
                <p className="eyebrow">{label}</p>
                <p className="mt-1.5 text-[11px] leading-snug text-ink">{value}</p>
              </div>
            ))}
          </div>
        </div>

        <div className="relative z-10 mt-10 flex items-center gap-2 font-mono text-[9px] uppercase tracking-wider text-faint">
          <ShieldCheck size={11} className="text-mint" />
          encrypted credentials · scoped probing · verified enforcement
        </div>
      </section>

      <section className="flex items-center justify-center px-5 py-10">
        <div className="w-full max-w-sm">
          <div className="mb-8 flex items-center gap-3 lg:hidden">
            <span className="text-mint">
              <Logo size={34} />
            </span>
            <p className="font-display text-base font-semibold tracking-wide text-ink">NETCONTROL</p>
          </div>
          <p className="eyebrow mb-2">Management console</p>
          <h2 className="font-display text-2xl font-semibold tracking-tight text-ink">
            Connect to a NetControl service
          </h2>
          <p className="mt-1.5 text-xs leading-relaxed text-muted">
            Use the local service or an authorized gateway host. Remote connections should
            use HTTPS.
          </p>

          <form onSubmit={submit} className="mt-7 space-y-4">
            <div>
              <label className="label" htmlFor="server">
                Service URL
              </label>
              <div className="relative">
                <Server
                  size={15}
                  className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-faint"
                />
                <input
                  id="server"
                  className="input pl-9"
                  value={server}
                  onChange={(event) => setServer(event.target.value)}
                  placeholder="https://127.0.0.1:8787/api/v1"
                  spellCheck={false}
                  autoComplete="url"
                />
              </div>
            </div>
            <div>
              <label className="label" htmlFor="username">
                Username
              </label>
              <input
                id="username"
                className="input"
                value={username}
                onChange={(event) => setUsername(event.target.value)}
                autoComplete="username"
              />
            </div>
            <div>
              <label className="label" htmlFor="password">
                Password
              </label>
              <div className="relative">
                <LockKeyhole
                  size={15}
                  className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-faint"
                />
                <input
                  id="password"
                  type="password"
                  className="input pl-9"
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  autoComplete="current-password"
                  autoFocus
                />
              </div>
            </div>

            {error && (
              <div className="rounded-xl border border-rose/25 bg-rose/5 px-3 py-2.5 text-[11px] leading-relaxed text-rose">
                {error}
              </div>
            )}

            <button className="btn-primary w-full" disabled={busy || !password}>
              {busy ? <Loader2 size={15} className="animate-spin" /> : <ArrowRight size={15} />}
              {busy ? "Connecting…" : "Sign in"}
            </button>
          </form>

          <p className="mt-6 text-center text-[10px] leading-relaxed text-faint">
            On first start the service writes a one-time administrator password to
            <span className="mono px-1 text-muted">~/.config/netcontrol/initial-admin-password.txt</span>
            with mode 0600. It is removed after the first admin login.
          </p>
        </div>
      </section>
    </div>
  );
}
