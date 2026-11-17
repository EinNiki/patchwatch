// Reine Logik der Paketansicht (ohne React, damit sie mit `npm test` geprüft werden kann).
import type { PackageRow, PackagesResponse } from "./types.ts";

export type PackageFilter = "updates" | "security" | "all";
const FILTERS: readonly string[] = ["updates", "security", "all"];

/** Erlaubte Werte von `?filter=`; alles andere ergibt den Standard „nur mit Update“. */
export function parsePackageFilter(v: string | null): PackageFilter {
  return v !== null && FILTERS.includes(v) ? (v as PackageFilter) : "updates";
}

/** Abfrageteil der API für den gewählten Filter. */
export function filterQuery(f: PackageFilter): string {
  return f === "updates" ? "&update=1" : f === "security" ? "&security=1" : "";
}

/** Ab diesem Alter der apt-Paketlisten warnt die Oberfläche (Updates sind dann womöglich veraltet). */
export const STALE_LISTS_DAYS = 7;

export type ListsAge = { text: string; stale: boolean };

/** Alter der Paketlisten in Worten; fehlt die Angabe, steht „unbekannt“ (nie geraten). */
export function listsAge(iso: string | null, now = Date.now()): ListsAge {
  if (!iso) return { text: "unbekannt", stale: false };
  const days = Math.floor((now - new Date(iso).getTime()) / 86_400_000);
  if (days < 1) return { text: "heute aktualisiert", stale: false };
  return { text: days === 1 ? "vor 1 Tag" : `vor ${days} Tagen`, stale: days >= STALE_LISTS_DAYS };
}

export const KIND_LABEL: Record<NonNullable<PackageRow["kind"]>, string> = {
  upgrade: "Update",
  new: "neu",
  remove: "wird entfernt",
};

/** Hinweis über der Tabelle, wenn die Liste unvollständig oder nicht da ist. */
export function listNotice(h: PackagesResponse["host"]): string | null {
  if (h.truncated) return `Die Liste ist auf ${h.installed.toLocaleString("de-DE")} Pakete begrenzt; der Host meldet mehr.`;
  if (!h.updates_listed) return "Dieser Agent schickt noch keine Update-Liste. Mit dem neuesten Agent (install.sh erneut ausführen) erscheint sie nach der nächsten Datenmeldung.";
  return null;
}
