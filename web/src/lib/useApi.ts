"use client";

import { useCallback, useEffect, useRef, useState, useSyncExternalStore } from "react";
import { api, ApiError } from "./api";
import { cacheGet, cacheSet, cacheSubscribe } from "./apiCache";
import { useLiveEvents } from "./live";

export interface ApiState<T> {
  data: T | undefined;
  error: string | null;
  /** Noch keine Antwort (weder Daten noch Fehler). */
  loading: boolean;
  reload: () => Promise<void>;
  /** Ändert die gecachten Daten lokal (optimistische Updates); `undefined` im Updater lässt sie unverändert. */
  mutate: (updater: (current: T) => T) => void;
}

type Result<T> = { data: T } | { error: string };

function fetchResult<T>(path: string): Promise<Result<T>> {
  return api.get<T>(path).then(
    (data) => ({ data }),
    (e: unknown) => ({ error: e instanceof ApiError ? e.message : "Server nicht erreichbar" }),
  );
}

const noData = () => undefined;

/**
 * Lädt `path` und aktualisiert optional alle `refreshMs`. Stale-while-revalidate: Beim Wiederbesuch erscheinen
 * gecachte Daten sofort (ohne Skeleton), der Abruf läuft im Hintergrund; vorhandene Daten bleiben beim Neuladen stehen.
 * `liveTypes`: Live-Ereignisse (siehe lib/live.tsx), bei denen neu geladen wird, ohne dass die Ansicht springt.
 */
export function useApi<T>(path: string | null, refreshMs = 0, liveTypes: readonly string[] = []): ApiState<T> {
  const data = useSyncExternalStore(cacheSubscribe, () => cacheGet<T>(path), noData);
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
    run();
    const timer = refreshMs > 0 ? setInterval(run, refreshMs) : undefined;
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

  // Mehrere Ereignisse kurz hintereinander (z. B. Massen-Anforderung) lösen nur einen Abruf aus.
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  useLiveEvents(liveTypes, () => {
    clearTimeout(timer.current);
    timer.current = setTimeout(() => void reload(), 250);
  });
  useEffect(() => () => clearTimeout(timer.current), []);

  return { data, error, loading: data === undefined && error === null, reload, mutate };
}

/** Wärmt den Cache vor (Hover/Fokus auf einem Link); vorhandene Daten bleiben, Fehler werden still ignoriert. */
export function prefetchApi(...paths: string[]) {
  for (const path of paths) {
    if (cacheGet(path) === undefined) void api.get<unknown>(path).then((d) => cacheSet(path, d), () => undefined);
  }
}
