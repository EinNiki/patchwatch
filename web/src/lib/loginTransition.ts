// Kleiner globaler Zustand für den Übergang nach der Anmeldung (Logos ziehen sich zusammen, dann öffnet sich das Dashboard).
// "cover": Overlay deckt alles (nach dem Zusammenziehen), "reveal": Loch wächst von der Mitte, "idle": nichts.
export type LoginPhase = "idle" | "cover" | "reveal";
let phase: LoginPhase = "idle";
const subs = new Set<() => void>();
export const getLoginPhase = () => phase;
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
