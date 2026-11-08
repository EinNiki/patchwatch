// Reine Entscheidung für klickbare Tabellenzeilen (ohne React/Next, damit sie sich einzeln testen lässt).

/** Bedienelemente in einer Zeile behalten ihre eigene Aktion; ein Klick darauf navigiert nie zusätzlich. */
export const INTERACTIVE = "a,button,input,select,textarea,summary,label,[role=button],[role=menuitem],[contenteditable=true]";

export interface ClickInfo {
  button: number;
  defaultPrevented: boolean;
  modifier: boolean;
  /** Ziel liegt in einem Bedienelement (INTERACTIVE) innerhalb der Zeile. */
  onControl: boolean;
  /** Der Nutzer hat gerade Text markiert. */
  selecting: boolean;
  /** Ein Fenster oder Menü liegt über der Seite. */
  overlayOpen: boolean;
}

/** Reine Entscheidung (testbar): "none" = nichts tun, "same" = in diesem Tab, "tab" = neuer Tab. */
export function rowClickAction(i: ClickInfo): "none" | "same" | "tab" {
  if (i.defaultPrevented || i.onControl || i.overlayOpen) return "none";
  if (i.button === 1) return "tab";
  if (i.button !== 0) return "none";
  if (i.modifier) return "tab";
  if (i.selecting) return "none";
  return "same";
}
