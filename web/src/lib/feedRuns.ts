// Abruf-Läufe der CVE-Quellen: Typen, Schritte und Zusammenfassungen (reine Logik, ohne React).

export const PHASES = ["connect", "download", "parse", "store", "evaluate", "done"] as const;
export type RunPhase = (typeof PHASES)[number];

export type RunStatus = "queued" | "running" | "ok" | "not_modified" | "incomplete" | "failed" | "skipped" | "interrupted";

export interface FeedRun {
  id: number;
  source: string;
  trigger: string;
  started_by: string | null;
  status: RunStatus;
  phase: RunPhase;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  bytes: number;
  items: number | null;
  hosts: number | null;
  error: string | null;
  /** Dauer je Phase in Millisekunden. */
  phases: Partial<Record<RunPhase, number>>;
}

export const PHASE_LABEL: Record<RunPhase, string> = {
  connect: "Verbinden",
  download: "Herunterladen",
  parse: "Auswerten der Daten",
  store: "Speichern",
  evaluate: "Hosts prüfen",
  done: "Fertig",
};

export type StepState = "done" | "active" | "pending" | "failed" | "skipped" | "partial";

export function isActive(r: Pick<FeedRun, "status">): boolean {
  return r.status === "queued" || r.status === "running";
}

export function isFailure(r: Pick<FeedRun, "status">): boolean {
  return r.status === "failed" || r.status === "interrupted";
}

/** Meldungen des Servers, wenn ein Lauf nicht von selbst endete, sondern vom Wächter beendet wurde. */
const HUNG_ERRORS = ["Zeitüberschreitung beim Verbinden", "Lauf ohne Fortschritt"];

/** Der Lauf hing und wurde abgebrochen (Verbinden-Zeitlimit oder Fortschrittswächter), er ist nicht regulär fehlgeschlagen. */
export function isHung(r: Pick<FeedRun, "status" | "error">): boolean {
  return r.status === "failed" && r.error !== null && HUNG_ERRORS.some((m) => r.error!.startsWith(m));
}

/** Wie lange der Lauf in seiner aktuellen Phase steht: Laufzeit minus die Dauer der abgeschlossenen Phasen (Näherung). */
export function phaseElapsedMs(r: Pick<FeedRun, "started_at" | "created_at" | "phase" | "phases">, nowMs: number): number {
  const from = Date.parse(r.started_at ?? r.created_at);
  if (Number.isNaN(from)) return 0;
  const done = Object.entries(r.phases).reduce((a, [k, v]) => (k === r.phase ? a : a + (v ?? 0)), 0);
  return Math.max(0, nowMs - from - done);
}

/** Eine Phase ist ungewöhnlich langsam: mehr als das Dreifache ihres Medians (und mindestens 10 s, damit kurze Phasen nicht warnen). */
export function isSlow(r: Pick<FeedRun, "status" | "started_at" | "created_at" | "phase" | "phases">, nowMs: number, medians: Record<string, number> | undefined): boolean {
  if (r.status !== "running") return false;
  const med = medians?.[r.phase];
  if (!med) return false;
  const el = phaseElapsedMs(r, nowMs);
  return el >= 10_000 && el > 3 * med;
}

/** „seit 30 Sekunden“ / „seit 2 Minuten“ für einen laufenden Lauf; ohne Startzeit leer. */
export function runningSince(r: Pick<FeedRun, "started_at" | "created_at">, nowMs: number): string {
  const from = Date.parse(r.started_at ?? r.created_at);
  if (Number.isNaN(from)) return "";
  const s = Math.max(0, Math.floor((nowMs - from) / 1000));
  if (s < 60) return `seit ${s} ${s === 1 ? "Sekunde" : "Sekunden"}`;
  const m = Math.floor(s / 60);
  return `seit ${m} ${m === 1 ? "Minute" : "Minuten"}`;
}

/** Kurzer Statustext zu einem Lauf (für Screenreader und Mini-Stepper). Läuft er, steht die Dauer dabei. */
export function runText(r: FeedRun, nowMs?: number): string {
  if (r.status === "queued") return "Wartet auf freien Platz";
  if (r.status === "running") {
    if (nowMs === undefined) return PHASE_LABEL[r.phase];
    const since = runningSince(r, nowMs);
    const phase = `${PHASE_LABEL[r.phase]}, ${Math.round(phaseElapsedMs(r, nowMs) / 1000)} s`;
    return since ? `${phase} · läuft ${since}` : phase;
  }
  if (r.status === "not_modified") return "Erfolgreich beendet, unverändert";
  if (r.status === "incomplete") return "Teilweise beendet";
  if (r.status === "interrupted") return "Abgebrochen (Server beendet oder neu gestartet)";
  if (isHung(r)) return `Abgebrochen, der Lauf hing (bei „${PHASE_LABEL[r.phase]}“)`;
  if (r.status === "failed") return `Fehlgeschlagen bei „${PHASE_LABEL[r.phase]}“`;
  return "Erfolgreich beendet";
}

/** Zustand jedes Schritts. Fehlschlag: die Phase, in der er auftrat, ist „failed“, danach „pending“. */
export function stepStates(r: Pick<FeedRun, "status" | "phase">): StepState[] {
  const at = PHASES.indexOf(r.phase);
  return PHASES.map((_, i): StepState => {
    if (r.status === "queued") return "pending";
    if (isFailure(r)) return i < at ? "done" : i === at ? "failed" : "pending";
    if (r.status === "running") return i < at ? "done" : i === at ? "active" : "pending";
    // Teilweise beendet: alle Schritte liefen, das Ergebnis (letzter Schritt) ist aber nur teilweise (Warnfarbe, nie grün).
    if (r.status === "incomplete") return i === PHASES.length - 1 ? "partial" : "done";
    // Erfolgreich beendet: alles erledigt (nicht geänderte Quelle überspringt die Zwischenschritte).
    if (r.status === "not_modified" || r.status === "skipped") return i === 0 || i === PHASES.length - 1 ? "done" : "skipped";
    return "done";
  });
}

/** Fortschritt 0..1 für den Mini-Stepper. */
export function progress(r: Pick<FeedRun, "status" | "phase">): number {
  if (r.status === "queued") return 0;
  if (!isActive(r)) return 1;
  return Math.min(PHASES.indexOf(r.phase) / (PHASES.length - 1), 1);
}

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  return n >= 1024 * 1024 ? `${(n / 1024 / 1024).toFixed(1)} MB` : `${Math.round(n / 1024)} KB`;
}

export function formatDuration(ms: number): string {
  return ms < 1000 ? `${Math.max(0, Math.round(ms))} ms` : `${(ms / 1000).toFixed(1)} s`;
}

/** Kurzer Text zur laufenden bzw. beendeten Phase (Zähler nur, wenn der Server sie gemeldet hat). */
export function detail(r: FeedRun): string {
  const parts: string[] = [];
  if (r.bytes > 0) parts.push(formatBytes(r.bytes));
  if (r.items !== null) parts.push(`${r.items} Einträge`);
  if (r.hosts !== null) parts.push(`${r.hosts} Hosts`);
  return parts.join(" · ");
}

/** Eine Zeile für das Zusammenfassungs-Toast nach einem erfolgreichen Lauf. */
export function summary(label: string, r: FeedRun): string {
  if (r.status === "not_modified") return `${label}: unverändert (keine neuen Daten).`;
  const d = detail(r);
  const total = Object.values(r.phases).reduce((a, b) => a + (b ?? 0), 0);
  return `${label}: aktualisiert${d ? ` (${d})` : ""} in ${formatDuration(total)}.`;
}

/** Läufe je Quelle: der jüngste gewinnt (höchste ID). */
export function latestBySource(runs: readonly FeedRun[]): Map<string, FeedRun> {
  const m = new Map<string, FeedRun>();
  for (const r of runs) {
    const cur = m.get(r.source);
    if (!cur || r.id > cur.id) m.set(r.source, r);
  }
  return m;
}

/** Wendet ein Live-Ereignis auf einen bekannten Lauf an; unbekannte Läufe liefern `null` (dann neu laden). */
export function applyLive(
  runs: readonly FeedRun[],
  e: { run_id?: unknown; status?: unknown; phase?: unknown; bytes?: unknown; items?: unknown; hosts?: unknown },
): FeedRun[] | null {
  if (typeof e.run_id !== "number") return null;
  const i = runs.findIndex((r) => r.id === e.run_id);
  if (i < 0) return null;
  const cur = runs[i]!;
  // Nie rückwärts: ein verspätetes Ereignis überschreibt keinen Endstand.
  if (!isActive(cur)) return runs.slice();
  const next: FeedRun = { ...cur };
  if (typeof e.status === "string") next.status = e.status as RunStatus;
  if (typeof e.phase === "string" && PHASES.includes(e.phase as RunPhase) && PHASES.indexOf(e.phase as RunPhase) >= PHASES.indexOf(cur.phase)) next.phase = e.phase as RunPhase;
  if (typeof e.bytes === "number") next.bytes = Math.max(cur.bytes, e.bytes);
  if (typeof e.items === "number") next.items = e.items;
  if (typeof e.hosts === "number") next.hosts = e.hosts;
  const out = runs.slice();
  out[i] = next;
  return out;
}
