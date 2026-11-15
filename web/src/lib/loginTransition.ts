// Kleiner globaler Zustand für die Übergänge bei An- und Abmeldung.
// Anmeldung: "cover" (Overlay deckt alles, nach dem Zusammenziehen) -> "reveal" (Loch wächst von der Mitte) -> "idle".
// Abmeldung: "out" (Kreis wächst von der Abmelden-Taste aus) -> "away" (Anmeldeseite lädt darunter) -> "fade" -> "idle".
export type LoginPhase = "idle" | "cover" | "reveal" | "out" | "away" | "fade";
let phase: LoginPhase = "idle";
let origin = { x: 0, y: 0 };
const subs = new Set<() => void>();
export const getLoginPhase = () => phase;
export const getOrigin = () => origin;
export const subscribeLoginPhase = (f: () => void) => {
  subs.add(f);
  return () => {
    subs.delete(f);
  };
};
export function setLoginPhase(p: LoginPhase) {
  phase = p;
  subs.forEach((f) => f());
}
/** Startet den Abmelde-Übergang am Mittelpunkt der Abmelden-Taste (Fensterkoordinaten). */
export function startLogoutTransition(at: { x: number; y: number }) {
  origin = at;
  setLoginPhase("out");
}
