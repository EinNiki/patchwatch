import { useEffect, useState } from "react";

const NONE: ReadonlySet<string | number> = new Set();

interface State {
  sigs: Map<string | number, string> | null;
  flashed: ReadonlySet<string | number>;
}

/**
 * Meldet die Zeilen, deren Signatur sich seit dem letzten Stand geändert hat (neue Zeilen zählen nicht,
 * der erste Stand auch nicht). Der Satz wird nach kurzer Zeit geleert, damit dieselbe Zeile erneut blitzen kann.
 */
export function useFlash<T>(items: readonly T[] | undefined, id: (t: T) => string | number, sig: (t: T) => string): ReadonlySet<string | number> {
  const [state, setState] = useState<State>({ sigs: null, flashed: NONE });

  if (items) {
    const next = new Map(items.map((t) => [id(t), sig(t)] as const));
    const prev = state.sigs;
    const same = prev !== null && prev.size === next.size && [...next].every(([k, v]) => prev.get(k) === v);
    if (!same) {
      const changed = prev ? [...next].filter(([k, v]) => prev.has(k) && prev.get(k) !== v).map(([k]) => k) : [];
      setState({ sigs: next, flashed: changed.length ? new Set(changed) : NONE });
    }
  }

  const flashed = state.flashed;
  useEffect(() => {
    if (flashed.size === 0) return;
    const t = setTimeout(() => setState((s) => (s.flashed === flashed ? { ...s, flashed: NONE } : s)), 800);
    return () => clearTimeout(t);
  }, [flashed]);

  return flashed;
}
