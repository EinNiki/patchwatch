"use client";

import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import { toast } from "./toastStore";

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

interface LiveValue {
  state: LiveState;
  subscribe: (fn: (e: LiveEvent) => void) => () => void;
}

const Ctx = createContext<LiveValue | null>(null);

/** Produktion: gleiche Origin (Reverse-Proxy leitet /api inkl. Upgrade). Dev: `NEXT_PUBLIC_PATCHWATCH_LIVE_PORT` = Port der API. */
function liveUrl(): string {
  const { protocol, hostname, host } = window.location;
  const scheme = protocol === "https:" ? "wss" : "ws";
  const devPort = process.env.NEXT_PUBLIC_PATCHWATCH_LIVE_PORT;
  return `${scheme}://${devPort ? `${hostname}:${devPort}` : host}/api/v1/live`;
}

export function LiveProvider({ children }: { children: React.ReactNode }) {
  const [state, setState] = useState<LiveState>("connecting");
  const listeners = useRef(new Set<(e: LiveEvent) => void>());

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
          // Server-Benachrichtigungen verschwinden wie bisher nach 8 s, auch kritische (sie stehen zusätzlich im Verlauf).
          const lvl = e.level ?? "info";
          const make = lvl === "crit" ? toast.error : lvl === "warn" ? toast.warning : toast.info;
          if (e.body) make(e.body, { title: e.title, duration: 8000 });
          else make(e.title, { duration: 8000 });
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

  const value = useMemo(() => ({ state, subscribe }), [state, subscribe]);
  return (
    <Ctx.Provider value={value}>
      {children}
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
