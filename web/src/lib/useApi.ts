"use client";

import { useCallback, useEffect, useRef, useState, useSyncExternalStore } from "react";
import { api, ApiError } from "./api";
import { cacheAge, cacheGet, cacheSet, cacheSubscribe } from "./apiCache";
import { useLiveEvents, type LiveEvent } from "./live";

export interface ApiState<T> {
  data: T | undefined;
  error: string | null;
  /** Noch keine Antwort (weder Daten noch Fehler). */
  loading: boolean;
  /** Zeigt noch die Daten des vorigen Pfads (nur mit `keepPrevious`), bis die neue Antwort da ist. */
  stale: boolean;
  reload: () => Promise<void>;
  /** Ändert die gecachten Daten lokal (optimistische Updates); `undefined` im Updater lässt sie unverändert. */
  mutate: (updater: (current: T) => T) => void;
}

type Result<T> = { data: T } | { error: string };

/** Läuft für einen Pfad schon eine Anfrage, hängen sich weitere Aufrufer daran (Shell und Seite fragen oft dasselbe). */
const inflight = new Map<string, Promise<Result<unknown>>>();

function fetchResult<T>(path: string): Promise<Result<T>> {
  const running = inflight.get(path);
  if (running) return running as Promise<Result<T>>;
  const p = api.get<T>(path).then(
    (data): Result<T> => ({ data }),
    (e: unknown): Result<T> => ({ error: e instanceof ApiError ? e.message : "Server nicht erreichbar" }),
  );
  inflight.set(path, p);
  void p.finally(() => inflight.delete(path));
  return p;
}

/** Daten, die jünger sind, werden beim Einhängen nicht erneut geladen (Seitenwechsel hin und zurück). */
const FRESH_MS = 5000;
/** Live-Ereignisse kurz hintereinander werden gebündelt. */
const LIVE_BATCH_MS = 400;

export interface LivePatch<T> {
  /** Alle Ereignisse des Bündels. */
  events: LiveEvent[];
  mutate: (updater: (current: T) => T) => void;
  reload: () => Promise<void>;
}

const noData = () => undefined;

/**
 * Lädt `path` und aktualisiert optional alle `refreshMs`. Stale-while-revalidate: Beim Wiederbesuch erscheinen
 * gecachte Daten sofort (ohne Skeleton), der Abruf läuft im Hintergrund; vorhandene Daten bleiben beim Neuladen stehen.
 * `liveTypes`: Live-Ereignisse (siehe lib/live.tsx), bei denen neu geladen wird, ohne dass die Ansicht springt.
 */
export function useApi<T>(
  path: string | null,
  refreshMs = 0,
  liveTypes: readonly string[] = [],
  /** Statt die ganze Liste neu zu laden, nur das Betroffene aktualisieren. Ohne Angabe wird neu geladen. */
  onLive?: (p: LivePatch<T>) => void,
  /** `keepPrevious`: beim Wechsel des Pfads (Filter) die bisherige Liste stehen lassen, statt ein Skeleton zu zeigen. */
  opts: { keepPrevious?: boolean } = {},
): ApiState<T> {
  const fresh = useSyncExternalStore(cacheSubscribe, () => cacheGet<T>(path), noData);
  // Letzter vorhandener Stand (Zustand statt Ref: wird beim Rendern gelesen).
  const [previous, setPrevious] = useState<{ data: T } | undefined>(undefined);
  if (fresh !== undefined && previous?.data !== fresh) setPrevious({ data: fresh });
  const stale = opts.keepPrevious === true && fresh === undefined && previous !== undefined;
  const data = fresh ?? (opts.keepPrevious ? previous?.data : undefined);
  const [errorFor, setErrorFor] = useState<{ path: string | null; message: string } | null>(null);
  const mounted = useRef(true);
  const error = errorFor && errorFor.path === path ? errorFor.message : null;

  const apply = useCallback(
    (p: string, r: Result<T>) => {
      if (!mounted.current) return;
      if ("data" in r) {
        cacheSet(p, r.data);
        setErrorFor(null);
      } else {
        setErrorFor({ path: p, message: r.error });
      }
    },
    [],
  );

  useEffect(() => {
    mounted.current = true;
    if (path === null) return;
    const run = () => void fetchResult<T>(path).then((r) => apply(path, r));
    // Frische Daten aus dem Cache genügen; der Abruf im Hintergrund entfällt.
    if (cacheAge(path) >= FRESH_MS) run();
    const timer = refreshMs > 0 ? setInterval(() => cacheAge(path) >= refreshMs / 2 && run(), refreshMs) : undefined;
    return () => {
      mounted.current = false;
      if (timer) clearInterval(timer);
    };
  }, [path, refreshMs, apply]);

  const reload = useCallback(async () => {
    if (path !== null) apply(path, await fetchResult<T>(path));
  }, [path, apply]);

  const mutate = useCallback(
    (updater: (current: T) => T) => {
      const cur = cacheGet<T>(path);
      if (path !== null && cur !== undefined) cacheSet(path, updater(cur));
    },
    [path],
  );

  // Mehrere Ereignisse kurz hintereinander (z. B. Massen-Anforderung) lösen nur einen Abruf bzw. eine Aktualisierung aus.
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  const batch = useRef<LiveEvent[]>([]);
  const patch = useRef(onLive);
  useEffect(() => {
    patch.current = onLive;
  });
  useLiveEvents(liveTypes, (e) => {
    batch.current.push(e);
    clearTimeout(timer.current);
    timer.current = setTimeout(() => {
      const events = batch.current.splice(0);
      if (patch.current) patch.current({ events, mutate, reload });
      else void reload();
    }, LIVE_BATCH_MS);
  });
  useEffect(() => () => clearTimeout(timer.current), []);

  return { data, error, loading: data === undefined && error === null, stale, reload, mutate };
}

/** Wärmt den Cache vor (Hover/Fokus auf einem Link); vorhandene Daten bleiben, Fehler werden still ignoriert. */
export function prefetchApi(...paths: string[]) {
  for (const path of paths) {
    if (cacheGet(path) === undefined) void api.get<unknown>(path).then((d) => cacheSet(path, d), () => undefined);
  }
}
