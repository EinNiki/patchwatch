"use client";
import { useRouter } from "next/navigation";
import type { MouseEvent } from "react";

import { INTERACTIVE, rowClickAction, type ClickInfo } from "./rowClick";

/** Nur sichtbare Fenster zählen: das mobile Menü bleibt im DOM und ist geschlossen nur per `visibility: hidden` (mobil) bzw. `display: none` (Desktop) ausgeblendet. */
function overlayOpen(): boolean {
  if (typeof document === "undefined") return false;
  return [...document.querySelectorAll("dialog[open], [aria-modal='true']")].some((e) => (e.checkVisibility ? e.checkVisibility({ visibilityProperty: true }) : (e as HTMLElement).offsetParent !== null));
}

function infoFrom(e: MouseEvent<HTMLElement>): ClickInfo {
  const target = e.target instanceof Element ? e.target : null;
  const control = target?.closest(INTERACTIVE) ?? null;
  const sel = typeof window !== "undefined" ? window.getSelection() : null;
  return {
    button: e.button,
    defaultPrevented: e.defaultPrevented,
    modifier: e.ctrlKey || e.metaKey || e.shiftKey,
    // Ereignisse aus einem Portal (z. B. Popover „+N“) erreichen die Zeile nur über den React-Baum, nicht über das DOM: kein Zeilenklick.
    onControl: (control !== null && e.currentTarget.contains(control)) || (target !== null && !e.currentTarget.contains(target)),
    selecting: !!sel && !sel.isCollapsed && sel.toString().trim() !== "",
    overlayOpen: overlayOpen(),
  };
}

/**
 * Ganze Tabellenzeile als Verweis. Der Name in der Zeile bleibt ein echter Link (Tastatur, Screenreader, Kontextmenü);
 * die Zeile ergänzt nur Maus und Touch. Eine Zelle mit `data-href` führt zu einem eigenen Ziel (z. B. gefilterte CVE-Liste).
 * Zeilen mit eigenen Aktionen (Token erneuern, Löschen) nutzen das nicht.
 */
export function useRowLink(href: string) {
  const router = useRouter();
  const go = (e: MouseEvent<HTMLElement>, forceTab: boolean) => {
    const cell = e.target instanceof Element ? e.target.closest("td[data-href]") : null;
    const to = cell?.getAttribute("data-href") || href;
    const act = rowClickAction(infoFrom(e));
    if (act === "none") return;
    if (act === "tab" || forceTab) {
      e.preventDefault();
      window.open(to, "_blank", "noopener");
    } else router.push(to);
  };
  return {
    "data-rowlink": "",
    onClick: (e: MouseEvent<HTMLElement>) => go(e, false),
    // Mittelklick löst `click` nicht aus; hier öffnet er den neuen Tab.
    onAuxClick: (e: MouseEvent<HTMLElement>) => {
      if (e.button === 1) go(e, true);
    },
  };
}
