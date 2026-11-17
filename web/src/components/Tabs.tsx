"use client";

import { useRef } from "react";

/**
 * Reiter (WAI-ARIA-Muster): Pfeiltasten wechseln, nur der aktive Reiter ist per Tab erreichbar. Die Leiste und der Inhalt
 * gehören zusammen; `idPrefix` trennt mehrere Gruppen auf einer Seite. Höhe 32 px, Touch 44 px.
 */
export function Tabs<T extends string>({
  label,
  tabs,
  value,
  onChange,
  idPrefix = "",
  children,
}: {
  label: string;
  tabs: readonly { id: T; label: string }[];
  value: T;
  onChange: (id: T) => void;
  idPrefix?: string;
  children: React.ReactNode;
}) {
  const refs = useRef<Record<string, HTMLButtonElement | null>>({});
  function onKey(e: React.KeyboardEvent, i: number) {
    const d = e.key === "ArrowRight" ? 1 : e.key === "ArrowLeft" ? -1 : 0;
    if (!d) return;
    e.preventDefault();
    const next = tabs[(i + d + tabs.length) % tabs.length]!;
    onChange(next.id);
    refs.current[next.id]?.focus();
  }
  return (
    <>
      <div role="tablist" aria-label={label} className="mb-4 flex gap-1 border-b border-line">
        {tabs.map((t, i) => (
          <button
            key={t.id}
            ref={(el) => {
              refs.current[t.id] = el;
            }}
            type="button"
            role="tab"
            id={`${idPrefix}tab-${t.id}`}
            aria-selected={value === t.id}
            aria-controls={`${idPrefix}panel-${t.id}`}
            tabIndex={value === t.id ? 0 : -1}
            onClick={() => onChange(t.id)}
            onKeyDown={(e) => onKey(e, i)}
            className={`-mb-px min-h-8 border-b-2 px-3 text-sm font-semibold max-md:min-h-11 ${value === t.id ? "border-accent text-fg" : "border-transparent text-fg2 hover:text-fg"}`}
          >
            {t.label}
          </button>
        ))}
      </div>
      <div role="tabpanel" id={`${idPrefix}panel-${value}`} aria-labelledby={`${idPrefix}tab-${value}`}>
        {children}
      </div>
    </>
  );
}
