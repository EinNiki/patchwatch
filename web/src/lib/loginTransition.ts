// Kleiner globaler Zustand für die Übergänge bei An- und Abmeldung.
// Anmeldung: "cover" (Overlay deckt alles, nach dem Zusammenziehen) -> "reveal" (Loch wächst von der Mitte) -> "idle".
// Abmeldung: "out" (Kreis wächst von der Abmelden-Taste aus) -> "away" (Anmeldeseite lädt darunter) -> "fade" -> "idle".
export type LoginPhase = "idle" | "cover" | "reveal" | "out" | "away" | "fade";
let phase: LoginPhase = "idle";
let origin = { x: 0, y: 0 };
let logoutDone = false;
let onReady: (() => void) | null = null;
/** Die Abmelde-Anfrage ist beantwortet (oder gescheitert): der Seitenwechsel darf folgen. */
export function markLogoutDone() {
  logoutDone = true;
  const f = onReady;
  onReady = null;
  f?.();
}
/** Führt `f` aus, sobald die Abmeldung beim Server durch ist (sofort, wenn schon geschehen). */
export function whenLogoutDone(f: () => void) {
  if (logoutDone) f();
  else onReady = f;
}
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
  logoutDone = false;
  onReady = null;
  setLoginPhase("out");
}
