// Sperrt das Scrollen der Seite hinter modalen Fenstern (zählt mit, damit verschachtelte Fenster sauber freigeben).

let locks = 0;
let saved: { overflow: string; paddingRight: string } | null = null;

/** Sperrt die Seite und liefert die Funktion zum Freigeben (mehrfaches Freigeben schadet nicht). */
export function lockScroll(): () => void {
  if (typeof document === "undefined") return () => {};
  const el = document.documentElement;
  if (locks === 0) {
    saved = { overflow: el.style.overflow, paddingRight: el.style.paddingRight };
    // Die Breite der verschwindenden Scrollleiste ausgleichen, damit der Inhalt nicht springt.
    const bar = window.innerWidth - el.clientWidth;
    if (bar > 0) el.style.paddingRight = `${bar}px`;
    el.style.overflow = "hidden";
  }
  locks += 1;
  let done = false;
  return () => {
    if (done) return;
    done = true;
    locks = Math.max(0, locks - 1);
    if (locks === 0 && saved) {
      el.style.overflow = saved.overflow;
      el.style.paddingRight = saved.paddingRight;
      saved = null;
    }
  };
}

/** Nur für Tests: wie viele Sperren gerade aktiv sind. */
export function activeLocks(): number {
  return locks;
}

/** Liegt der Punkt außerhalb des Rechtecks? Für <dialog> heißt das: Klick auf den abgedunkelten Hintergrund. */
export function isOutside(r: { left: number; right: number; top: number; bottom: number }, x: number, y: number): boolean {
  return x < r.left || x > r.right || y < r.top || y > r.bottom;
}
