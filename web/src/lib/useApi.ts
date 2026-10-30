"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { api, ApiError } from "./api";

export interface ApiState<T> {
  data: T | undefined;
  error: string | null;
  /** Noch keine Antwort (weder Daten noch Fehler). */
  loading: boolean;
  reload: () => Promise<void>;
}

type Result<T> = { data: T } | { error: string };

function fetchResult<T>(path: string): Promise<Result<T>> {
  return api.get<T>(path).then(
    (data) => ({ data }),
    (e: unknown) => ({ error: e instanceof ApiError ? e.message : "Server nicht erreichbar" }),
  );
}

/** Lädt `path` und aktualisiert optional alle `refreshMs`; vorhandene Daten bleiben beim Neuladen stehen. */
export function useApi<T>(path: string | null, refreshMs = 0): ApiState<T> {
  const [data, setData] = useState<T | undefined>(undefined);
  const [error, setError] = useState<string | null>(null);
  const mounted = useRef(true);

  const apply = useCallback((r: Result<T>) => {
    if (!mounted.current) return;
    if ("data" in r) {
      setData(r.data);
      setError(null);
    } else {
      setError(r.error);
    }
  }, []);

  useEffect(() => {
    mounted.current = true;
    if (path === null) return;
    const run = () => void fetchResult<T>(path).then(apply);
    run();
    const timer = refreshMs > 0 ? setInterval(run, refreshMs) : undefined;
    return () => {
      mounted.current = false;
      if (timer) clearInterval(timer);
    };
  }, [path, refreshMs, apply]);

  const reload = useCallback(async () => {
    if (path !== null) apply(await fetchResult<T>(path));
  }, [path, apply]);

  return { data, error, loading: data === undefined && error === null, reload };
}
