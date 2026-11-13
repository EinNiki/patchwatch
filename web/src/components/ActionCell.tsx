"use client";

import { useLayoutEffect, useRef, useState } from "react";
import { Button } from "@/components/Controls";
import { NavIcon, type NavIconName } from "@/components/Icons";
import { RowMenu } from "@/components/RowMenu";

export interface CellAction {
  key: string;
  label: string;
  /** Zugänglicher Name mit Bezug auf die Zeile (z. B. „Agent web-01 löschen“). */
  aria: string;
  icon: NavIconName;
  run: () => void;
  danger?: boolean;
  disabled?: boolean;
  /** Erklärung, warum die Aktion nicht verfügbar ist (Tooltip bei deaktiviert). */
  why?: string;
}

const W = 132; // Textknopf (size="action" = 8,5 rem: „Daten jetzt abrufen“ passt ohne Abschneiden)
const ICON = 32; // Symbolknopf
const GAP = 8;

/** Stufe nach verfügbarer Breite der Zelle: 1 = alle als Textknöpfe, 2 = erster Text, Rest Symbol, 3 = „…“-Menü. */
export function stageFor(width: number, n: number): 1 | 2 | 3 {
  if (n <= 1 || width >= n * W + (n - 1) * GAP) return 1;
  if (width >= W + (n - 1) * (ICON + GAP)) return 2;
  return 3;
}

/**
 * Aktionsspalte aller Tabellen: gleich große Knöpfe nebeneinander; bei Platzmangel (Breite der Zelle, nicht des
 * Fensters) erst Symbolknöpfe mit Tooltip, zuletzt ein „…“-Menü. Gefahraktionen öffnen nur ihr Bestätigungsfenster (run).
 */
export function ActionCell({ actions, name }: { actions: CellAction[]; name: string }) {
  const ref = useRef<HTMLDivElement>(null);
  const [stage, setStage] = useState<1 | 2 | 3>(1);
  const n = actions.length;
  useLayoutEffect(() => {
    const el = ref.current;
    if (!el) return;
    const update = () => setStage(stageFor(el.clientWidth, n));
    update();
    const ro = new ResizeObserver(update);
    ro.observe(el);
    return () => ro.disconnect();
  }, [n]);

  const btn = (a: CellAction, asIcon: boolean) => (
    <Button
      key={a.key}
      size={asIcon ? "icon" : "action"}
      variant={a.danger ? "danger" : "default"}
      // Mit Grund: aria-disabled statt disabled, damit der Knopf fokussierbar bleibt und der Tooltip mit dem Grund erscheint.
      onClick={a.disabled && a.why ? undefined : a.run}
      disabled={a.disabled && !a.why}
      aria-disabled={a.disabled && a.why ? true : undefined}
      className={a.disabled && a.why ? "cursor-not-allowed opacity-50" : undefined}
      aria-label={a.aria}
      title={a.disabled && a.why ? a.why : asIcon ? a.label : undefined}
      data-stage={stage}
    >
      {asIcon ? <NavIcon name={a.icon} /> : a.label}
    </Button>
  );

  return (
    <div ref={ref} className="flex w-full min-w-0 items-center justify-start gap-2 [container-type:inline-size]" data-action-cell>
      {n === 0 ? null : stage === 3 ? (
        <RowMenu
          label={`Aktionen für ${name}`}
          items={actions.filter((a) => !a.disabled).map((a) => ({ label: a.label, aria: a.aria, run: a.run, danger: a.danger }))}
        />
      ) : (
        actions.map((a, i) => btn(a, stage === 2 && i > 0))
      )}
    </div>
  );
}
