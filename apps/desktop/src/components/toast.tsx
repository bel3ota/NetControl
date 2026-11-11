import { createContext, useCallback, useContext, useMemo, useRef, useState } from "react";
import { CheckCircle2, Info, TriangleAlert, X } from "lucide-react";
import clsx from "clsx";

type ToastTone = "success" | "error" | "info";

interface ToastItem {
  id: number;
  tone: ToastTone;
  title: string;
  message?: string;
}

interface ToastApi {
  success: (title: string, message?: string) => void;
  error: (title: string, message?: string) => void;
  info: (title: string, message?: string) => void;
}

const ToastContext = createContext<ToastApi | null>(null);

export function useToast(): ToastApi {
  const context = useContext(ToastContext);
  if (!context) throw new Error("useToast must be used inside ToastProvider");
  return context;
}

export function ToastProvider({ children }: { children: React.ReactNode }) {
  const [items, setItems] = useState<ToastItem[]>([]);
  const counter = useRef(0);

  const push = useCallback((tone: ToastTone, title: string, message?: string) => {
    const id = ++counter.current;
    setItems((current) => [...current, { id, tone, title, message }]);
    window.setTimeout(() => {
      setItems((current) => current.filter((item) => item.id !== id));
    }, 6000);
  }, []);

  const api = useMemo<ToastApi>(
    () => ({
      success: (title, message) => push("success", title, message),
      error: (title, message) => push("error", title, message),
      info: (title, message) => push("info", title, message),
    }),
    [push],
  );

  return (
    <ToastContext.Provider value={api}>
      {children}
      <div className="pointer-events-none fixed bottom-5 right-5 z-[70] flex w-[min(380px,calc(100vw-2.5rem))] flex-col gap-2">
        {items.map((item) => {
          const Icon = item.tone === "success" ? CheckCircle2 : item.tone === "error" ? TriangleAlert : Info;
          return (
            <div
              key={item.id}
              className={clsx(
                "pointer-events-auto flex animate-fade-up items-start gap-3 rounded-xl border bg-panel/95 p-3.5 shadow-panel backdrop-blur",
                item.tone === "success" && "border-success/30",
                item.tone === "error" && "border-rose/30",
                item.tone === "info" && "border-azure/30",
              )}
            >
              <span
                className={clsx(
                  "mt-0.5",
                  item.tone === "success" && "text-success",
                  item.tone === "error" && "text-rose",
                  item.tone === "info" && "text-azure",
                )}
              >
                <Icon size={16} />
              </span>
              <div className="min-w-0 flex-1">
                <p className="text-xs font-semibold text-ink">{item.title}</p>
                {item.message && (
                  <p className="mt-0.5 break-words text-[11px] leading-relaxed text-muted">{item.message}</p>
                )}
              </div>
              <button
                className="text-faint transition hover:text-ink"
                onClick={() => setItems((current) => current.filter((entry) => entry.id !== item.id))}
                aria-label="Dismiss"
              >
                <X size={14} />
              </button>
            </div>
          );
        })}
      </div>
    </ToastContext.Provider>
  );
}
