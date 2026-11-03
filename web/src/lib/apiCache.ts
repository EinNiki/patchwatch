// Modulweiter Cache für stale-while-revalidate: Erstanzeige aus dem Cache, Abruf im Hintergrund.
// Er enthält Serverdaten der angemeldeten Sitzung und wird bei Logout und bei jedem 401 vollständig geleert.

const MAX_ENTRIES = 60;
const entries = new Map<string, unknown>();
const listeners = new Set<() => void>();

function emit() {
  for (const l of listeners) l();
}

export function cacheGet<T>(path: string | null): T | undefined {
  return path === null ? undefined : (entries.get(path) as T | undefined);
}

/** Zeitpunkt der letzten erfolgreichen Antwort je Pfad (für "noch frisch"). */
const stamps = new Map<string, number>();

export function cacheAge(path: string | null): number {
  const t = path === null ? undefined : stamps.get(path);
  return t === undefined ? Infinity : Date.now() - t;
}

export function cacheSet<T>(path: string, data: T) {
  stamps.set(path, Date.now());
  entries.delete(path); // neu einsortieren, damit der älteste Eintrag zuerst fällt
  entries.set(path, data);
  if (entries.size > MAX_ENTRIES) {
    const oldest = entries.keys().next().value as string;
    entries.delete(oldest);
    stamps.delete(oldest);
  }
  emit();
}

/**
 * Laufnummer der Sitzung. Jede Leerung (Logout, 401) erhöht sie. Eine Antwort, die vor der Leerung angefragt wurde
 * (Anfrage noch unterwegs), trägt die alte Nummer und darf den Cache nicht mehr füllen: sonst stünden die Daten der
 * beendeten Sitzung nach dem Abmelden wieder im Cache und wären für den nächsten Benutzer sichtbar.
 */
let generation = 0;

export function cacheGeneration(): number {
  return generation;
}

/** Wie `cacheSet`, aber nur, wenn die Anfrage in der aktuellen Sitzung gestartet wurde. */
export function cacheSetIfCurrent<T>(path: string, data: T, requestedIn: number): boolean {
  if (requestedIn !== generation) return false;
  cacheSet(path, data);
  return true;
}

export function clearApiCache() {
  generation += 1;
  if (entries.size === 0) return;
  entries.clear();
  stamps.clear();
  emit();
}

export function cacheSubscribe(l: () => void) {
  listeners.add(l);
  return () => void listeners.delete(l);
}
