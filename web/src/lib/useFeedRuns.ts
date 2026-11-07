"use client";

import { useCallback } from "react";
import { useApi } from "./useApi";
import { applyLive, isActive, type FeedRun } from "./feedRuns";

interface Active {
  runs: FeedRun[];
}

/**
 * Aktive und gerade beendete Läufe (Server: queued/running + beendet <30 s). Live-Ereignisse „feed_run“ aktualisieren
 * den Zustand sofort; solange ein Lauf aktiv ist, fragt ein 3-s-Takt als Rückfall nach (falls der Live-Kanal ausfällt).
 */
export function useFeedRuns() {
  // Takt hängt vom Zustand ab; useApi liest `refreshMs` bei jedem Rendern.
  const probe = useApi<Active>("/feeds/runs?active=true", 0);
  const anyActive = probe.data?.runs.some(isActive) ?? false;
  const onLive = useCallback((p: { events: { type: string }[]; mutate: (u: (c: Active) => Active) => void; reload: () => Promise<void> }) => {
    let unknown = false;
    p.mutate((cur) => {
      let runs = cur.runs;
      for (const e of p.events) {
        if (e.type !== "feed_run") continue;
        const next = applyLive(runs, e as never);
        if (next === null) unknown = true;
        else runs = next;
      }
      return { runs };
    });
    // Ein neuer Lauf (unbekannte ID) oder ein Endstand: vollständige Zeile vom Server holen.
    if (unknown || p.events.some((e) => e.type === "resync" || (e as { status?: string }).status !== "running")) void p.reload();
  }, []);
  const api = useApi<Active>("/feeds/runs?active=true", anyActive ? 3000 : 30_000, ["feed_run"], onLive);
  return { runs: api.data?.runs ?? [], reload: api.reload, loading: api.loading };
}
