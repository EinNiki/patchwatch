"use client";

import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import { Icon } from "@/components/Icons";
import type { IconName } from "./status";

/** Live-Ereignis vom Server (server/src/live.rs); die UI lädt Daten danach über die REST-API nach. */
export interface LiveEvent {
  type: string;
  host_id?: number;
  cve_id?: string;
  title?: string;
  body?: string;
  level?: "info" | "warn" | "crit";
}

export type LiveState = "connecting" | "live" | "offline";

export interface Toast {
  id: number;
  title: string;
  body: string;
  level: "info" | "warn" | "crit";
}

interface LiveValue {
  state: LiveState;
  subscribe: (fn: (e: LiveEvent) => void) => () => void;
  toasts: Toast[];
  dismiss: (id: number) => void;
}

const Ctx = createContext<LiveValue | null>(null);

const MAX_TOASTS = 3;
const TOAST_MS = 8000;

/** Produktion: gleiche Origin (Reverse-Proxy leitet /api inkl. Upgrade). Dev: `NEXT_PUBLIC_PATCHWATCH_LIVE_PORT` = Port der API. */
function liveUrl(): string {
  const { protocol, hostname, host } = window.location;
  const scheme = protocol === "https:" ? "wss" : "ws";
  const devPort = process.env.NEXT_PUBLIC_PATCHWATCH_LIVE_PORT;
  return `${scheme}://${devPort ? `${hostname}:${devPort}` : host}/api/v1/live`;
}

export function LiveProvider({ children }: { children: React.ReactNode }) {
  const [state, setState] = useState<LiveState>("connecting");
  const [toasts, setToasts] = useState<Toast[]>([]);
  const listeners = useRef(new Set<(e: LiveEvent) => void>());
  const nextId = useRef(1);

  const dismiss = useCallback((id: number) => setToasts((t) => t.filter((x) => x.id !== id)), []);
  const subscribe = useCallback((fn: (e: LiveEvent) => void) => {
    listeners.current.add(fn);
    return () => void listeners.current.delete(fn);
  }, []);

  useEffect(() => {
    let ws: WebSocket | null = null;
    let retry: ReturnType<typeof setTimeout> | undefined;
    let attempt = 0;
    let stopped = false;

    const emit = (e: LiveEvent) => listeners.current.forEach((fn) => fn(e));

    const connect = () => {
      setState("connecting");
      ws = new WebSocket(liveUrl());
      ws.onopen = () => {
        attempt = 0;
        setState("live");
        // Zwischenzeitlich Verpasstes nachladen.
        emit({ type: "resync" });
      };
      ws.onmessage = (m) => {
        let e: LiveEvent;
        try {
          e = JSON.parse(String(m.data)) as LiveEvent;
        } catch {
          return;
        }
        if (typeof e.type !== "string") return;
        if (e.type === "notification" && e.title) {
          const id = nextId.current++;
          setToasts((t) => [...t, { id, title: e.title ?? "", body: e.body ?? "", level: e.level ?? "info" }].slice(-MAX_TOASTS));
          setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), TOAST_MS);
        }
        emit(e);
      };
      ws.onclose = (ev) => {
        ws = null;
        if (stopped) return;
        setState("offline");
        // 4401: Sitzung abgelaufen. Ein REST-Aufruf führt dann zur Anmeldung.
        if (ev.code === 4401) window.dispatchEvent(new Event("pw:unauthorized"));
        // Exponentiell bis 30 s, mit Streuung.
        const delay = Math.min(30_000, 1000 * 2 ** attempt++) * (0.75 + Math.random() * 0.5);
        retry = setTimeout(connect, delay);
      };
    };
    // Verzögert starten: React StrictMode (Dev) räumt den ersten Effekt sofort wieder ab, ohne dass ein Socket entsteht.
    retry = setTimeout(connect, 0);
    return () => {
      stopped = true;
      clearTimeout(retry);
      ws?.close();
    };
  }, []);

  const value = useMemo(() => ({ state, subscribe, toasts, dismiss }), [state, subscribe, toasts, dismiss]);
  return (
    <Ctx.Provider value={value}>
      {children}
      <ToastRegion toasts={toasts} dismiss={dismiss} />
    </Ctx.Provider>
  );
}

export function useLiveState(): LiveState {
  return useContext(Ctx)?.state ?? "offline";
}

/** Ruft `fn` bei Live-Ereignissen der angegebenen Arten (`resync` immer). Ohne Provider passiert nichts. */
export function useLiveEvents(types: readonly string[], fn: (e: LiveEvent) => void) {
  const ctx = useContext(Ctx);
  const latest = useRef(fn);
  useEffect(() => {
    latest.current = fn;
  });
  const key = types.join(",");
  useEffect(() => {
    if (!ctx || key === "") return;
    const wanted = new Set(key.split(","));
    return ctx.subscribe((e) => {
      if (e.type === "resync" || wanted.has(e.type)) latest.current(e);
    });
  }, [ctx, key]);
}

const TOAST_ICON: Record<Toast["level"], IconName> = { info: "ok", warn: "warn", crit: "crit" };
const TOAST_TONE: Record<Toast["level"], string> = {
  info: "border-line",
  warn: "border-warn",
  crit: "border-crit",
};


function ToastRegion({ toasts, dismiss }: { toasts: Toast[]; dismiss: (id: number) => void }) {
  return (
    <div className="pointer-events-none fixed bottom-4 right-4 z-50 flex w-[min(24rem,calc(100vw-2rem))] flex-col gap-2" role="region" aria-label="Benachrichtigungen">
      {toasts.map((t) => (
        <div
          key={t.id}
          role={t.level === "crit" ? "alert" : "status"}
          className={`pointer-events-auto flex items-start gap-2 border-l-4 border-y border-r bg-surface px-3 py-2 shadow-lg ${TOAST_TONE[t.level]}`}
        >
          <span className={`mt-0.5 ${t.level === "crit" ? "text-crit" : t.level === "warn" ? "text-warn" : "text-ok"}`}>
            <Icon name={TOAST_ICON[t.level]} />
          </span>
          <div className="min-w-0 flex-1">
            <p className="font-semibold">{t.title}</p>
            {t.body ? <p className="line-clamp-3 text-[13px] text-fg2">{t.body}</p> : null}
          </div>
          <button
            type="button"
            onClick={() => dismiss(t.id)}
            className="-my-1 -mr-1 inline-flex min-h-8 min-w-8 items-center justify-center rounded-[3px] text-fg2 hover:bg-sunk hover:text-fg max-md:min-h-11 max-md:min-w-11"
          >
            <span aria-hidden="true">×</span>
            <span className="sr-only">Meldung schließen</span>
          </button>
        </div>
      ))}
    </div>
  );
}
