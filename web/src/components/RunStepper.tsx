"use client";

import { useEffect, useState } from "react";
import { Icon } from "@/components/Icons";
import { PHASES, PHASE_LABEL, detail, formatDuration, isActive, isFailure, isSlow, runText, stepStates, type FeedRun, type StepState } from "@/lib/feedRuns";

/** Eigene Symbole (SVG, currentColor): Haken, Kreuz, Strich (übersprungen), drehender Ring (aktiv), leerer Kreis (offen). */
function StepIcon({ state }: { state: StepState }) {
  const common = { width: 16, height: 16, viewBox: "0 0 16 16", fill: "none", stroke: "currentColor", strokeWidth: 1.75, strokeLinecap: "round", strokeLinejoin: "round", "aria-hidden": true, focusable: false } as const;
  if (state === "done")
    return (
      <svg {...common}>
        <circle cx="8" cy="8" r="6.5" fill="currentColor" fillOpacity="0.15" />
        <path d="M5 8.4 7.1 10.5 11 5.8" />
      </svg>
    );
  if (state === "failed")
    return (
      <svg {...common}>
        <circle cx="8" cy="8" r="6.5" fill="currentColor" fillOpacity="0.15" />
        <path d="M5.8 5.8 10.2 10.2M10.2 5.8 5.8 10.2" />
      </svg>
    );
  if (state === "skipped")
    return (
      <svg {...common}>
        <circle cx="8" cy="8" r="6.5" strokeDasharray="2 2.4" />
        <path d="M5.5 8h5" />
      </svg>
    );
  if (state === "active")
    return (
      <svg {...common} className="run-spin">
        <circle cx="8" cy="8" r="6.5" strokeOpacity="0.25" />
        <path d="M14.5 8A6.5 6.5 0 0 0 8 1.5" />
      </svg>
    );
  return (
    <svg {...common}>
      <circle cx="8" cy="8" r="6.5" strokeOpacity="0.5" />
    </svg>
  );
}

const TONE: Record<StepState, string> = {
  done: "text-ok",
  active: "text-accent",
  failed: "text-crit",
  skipped: "text-fg3",
  pending: "text-fg3",
};

const STATE_WORD: Record<StepState, string> = { done: "erledigt", active: "läuft", failed: "fehlgeschlagen", skipped: "übersprungen", pending: "ausstehend" };

/** Sekundentakt, solange ein Lauf aktiv ist (für „läuft seit N Sekunden“); sonst kein Timer. */
function useNow(active: boolean): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (!active) return;
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, [active]);
  return now;
}

/** Vollständiger Stepper: sechs Schritte mit Dauer, darunter Zähler und bei Fehlern die Meldung samt Aktionen. */
export function RunStepper({ run, label, phaseMedians, onRetry, onClose }: { run: FeedRun; label: string; phaseMedians?: Record<string, number>; onRetry?: () => void; onClose?: () => void }) {
  const states = stepStates(run);
  const failed = isFailure(run);
  const d = detail(run);
  const now = useNow(run.status === "running");
  return (
    <div className="rounded-[3px] border border-line bg-sunk px-3 py-2" role="group" aria-label={`Abruf ${label}`}>
      <ol className="flex flex-wrap gap-x-4 gap-y-1 text-sm">
        {PHASES.map((p, i) => {
          const s = states[i]!;
          const ms = run.phases[p];
          return (
            <li key={p} className={`flex items-center gap-1.5 ${TONE[s]}`} aria-current={s === "active" ? "step" : undefined}>
              <StepIcon state={s} />
              <span className={s === "active" || s === "failed" ? "font-semibold" : "text-fg2"}>{PHASE_LABEL[p]}</span>
              <span className="sr-only">: {STATE_WORD[s]}</span>
              {ms !== undefined && s !== "pending" && p !== "done" ? <span className="text-xs text-fg3">{formatDuration(ms)}</span> : null}
            </li>
          );
        })}
      </ol>
      <p className="mt-1 text-xs tabular-nums text-fg2" role="status">
        {runText(run, now)}
        {d ? ` · ${d}` : ""}
      </p>
      {isSlow(run, now, phaseMedians) ? (
        <p className="mt-1 flex items-center gap-1.5 text-sm text-warn" role="status">
          <Icon name="clock" />
          Langsamer als sonst, {label} antwortet träge.
        </p>
      ) : null}
      {failed && run.error ? <p className="mt-1 text-sm text-crit">{run.error}</p> : null}
      {!isActive(run) && (onRetry || onClose) ? (
        <div className="mt-2 flex flex-wrap gap-2">
          {failed && onRetry ? (
            <button type="button" className="min-h-8 rounded-[3px] border border-control bg-surface px-3 text-sm font-semibold hover:bg-sunk max-md:min-h-11" onClick={onRetry}>
              Erneut versuchen
            </button>
          ) : null}
          {onClose ? (
            <button type="button" className="min-h-8 rounded-[3px] border border-control bg-surface px-3 text-sm hover:bg-sunk max-md:min-h-11" onClick={onClose}>
              Schließen
            </button>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}

/** Mini-Stepper in der Tabellenzeile: sechs Segmente und der aktuelle Schritt als Text. */
export function MiniStepper({ run, onToggle, open }: { run: FeedRun; onToggle: () => void; open: boolean }) {
  const states = stepStates(run);
  const now = useNow(run.status === "running");
  return (
    <button type="button" onClick={onToggle} aria-expanded={open} className="mt-1 flex min-h-6 flex-col items-start gap-1 text-left max-md:min-h-11" aria-label={`Abruf-Details: ${runText(run, now)}`}>
      <span className="flex gap-0.5" aria-hidden="true">
        {states.map((s, i) => (
          <span
            key={i}
            className={`h-1.5 w-4 rounded-full ${s === "done" ? "bg-ok" : s === "active" ? "run-pulse bg-accent" : s === "failed" ? "bg-crit" : s === "skipped" ? "bg-fg3/40" : "bg-line"}`}
          />
        ))}
      </span>
      <span className={`text-xs tabular-nums ${isFailure(run) ? "text-crit" : "text-fg2"}`}>{runText(run, now)}</span>
    </button>
  );
}
