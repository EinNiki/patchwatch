import { api } from "./api";
import type { Host } from "./types";
import type { LivePatch } from "./useApi";

/** Live-Ereignisse in der Host-Liste: nur die betroffenen Zeilen nachladen statt der ganzen Liste (bei vielen Hosts oder ohne Host-ID: neu laden). */
export function patchHostRows({ events, mutate, reload }: LivePatch<Host[]>) {
  const ids = new Set<number>();
  for (const e of events) {
    if (e.type === "resync" || e.host_id === undefined) return void reload();
    ids.add(e.host_id);
  }
  if (ids.size > 5) return void reload();
  for (const id of ids) {
    api.get<Host>(`/hosts/${id}`).then(
      (fresh) => {
        let found = false;
        mutate((list) => list.map((h) => (h.id === id ? ((found = true), fresh) : h)));
        if (!found) void reload(); // neuer Host
      },
      () => void reload(),
    );
  }
}
