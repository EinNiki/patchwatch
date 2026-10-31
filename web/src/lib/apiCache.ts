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

export function cacheSet<T>(path: string, data: T) {
  entries.delete(path); // neu einsortieren, damit der älteste Eintrag zuerst fällt
  entries.set(path, data);
  if (entries.size > MAX_ENTRIES) entries.delete(entries.keys().next().value as string);
  emit();
}

export function clearApiCache() {
  if (entries.size === 0) return;
  entries.clear();
  emit();
}

export function cacheSubscribe(l: () => void) {
  listeners.add(l);
  return () => void listeners.delete(l);
}
