"use client";

import { NavIcon } from "@/components/Icons";
import { Popover } from "@/components/Popover";

export interface RowMenuItem {
  label: string;
  /** Zugänglicher Name mit Bezug auf die Zeile (z. B. „web-01 löschen“). */
  aria: string;
  run: () => void;
  /** Zerstörerische Aktion: Fehlerfarbe, kein Standardknopf. */
  danger?: boolean;
}

/** „…“-Menü einer Tabellenzeile (32 px, mobil 44 px) für seltene Aktionen; Popover-Logik wie überall (Escape, Klick daneben, Fokus zurück). */
export function RowMenu({ label, items }: { label: string; items: RowMenuItem[] }) {
  return (
    <Popover
      label={label}
      width={176}
      align="end"
      sheet={false}
      trigger={(t) => (
        <button
          type="button"
          ref={t.ref}
          aria-haspopup={t["aria-haspopup"]}
          aria-expanded={t["aria-expanded"]}
          aria-controls={t["aria-controls"]}
          aria-label={label}
          title="Weitere Aktionen"
          onClick={t.toggle}
          className="inline-flex size-8 shrink-0 items-center justify-center rounded-[3px] border border-control bg-surface text-fg hover:bg-sunk max-md:size-11"
        >
          <NavIcon name="more" />
        </button>
      )}
    >
      {(close) => (
        <ul className="m-0 -mx-1.5 -my-1.5 flex list-none flex-col gap-0.5 p-0">
          {items.map((it) => (
            <li key={it.label}>
              <button
                type="button"
                aria-label={it.aria}
                onClick={() => {
                  close();
                  it.run();
                }}
                className={`flex min-h-8 w-full items-center rounded-xs px-2 text-left hover:bg-sunk max-md:min-h-11 ${it.danger ? "text-crit" : "text-fg"}`}
              >
                {it.label}
              </button>
            </li>
          ))}
        </ul>
      )}
    </Popover>
  );
}
