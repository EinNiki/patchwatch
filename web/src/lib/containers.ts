// Reine Logik der Container-Ansicht (ohne React, damit sie mit `npm test` geprüft werden kann).
import type { StatusInfo } from "./status.ts";
import type { ContainerItem, ContainerVerdict, HostContainersResponse } from "./types.ts";

/** Gruppen für den Filter: was der Nutzer unterscheiden will (aktuell, neues Image, neue Version, gepinnt, nicht prüfbar, Fehler). */
export type VerdictGroup = "current" | "image" | "version" | "pinned" | "unchecked" | "error";

export function verdictGroup(v: ContainerVerdict): VerdictGroup {
  switch (v.status) {
    case "current":
      return "current";
    case "update_available":
      return "image";
    case "newer_version":
      return "version";
    case "pinned":
      return "pinned";
    case "error":
      return "error";
    default:
      return "unchecked";
  }
}

export const GROUP_LABEL: Record<VerdictGroup, string> = {
  current: "Aktuell",
  image: "Neueres Image",
  version: "Neuere Version",
  pinned: "Gepinnt",
  unchecked: "Nicht prüfbar",
  error: "Fehler",
};

export type ContainerFilter = "all" | "updates" | VerdictGroup;

export const FILTER_OPTIONS: readonly { id: ContainerFilter; label: string }[] = [
  { id: "all", label: "Alle" },
  { id: "updates", label: "Mit Update" },
  { id: "current", label: GROUP_LABEL.current },
  { id: "pinned", label: GROUP_LABEL.pinned },
  { id: "unchecked", label: GROUP_LABEL.unchecked },
  { id: "error", label: GROUP_LABEL.error },
];

export function matchesFilter(v: ContainerVerdict, f: ContainerFilter): boolean {
  if (f === "all") return true;
  const g = verdictGroup(v);
  return f === "updates" ? g === "image" || g === "version" : g === f;
}

/** Die höchste angebotene Version (Major vor Minor vor Patch). */
function newest(v: Extract<ContainerVerdict, { status: "newer_version" }>): string | null {
  return v.major ?? v.minor ?? v.patch;
}

/** Warum ein Eintrag nicht bewertet werden kann (kurzer Klartext, nie geraten). */
const UNCHECKED_REASON: Record<string, string> = {
  unsupported: "Registry wird nicht geprüft (nur Docker Hub, ghcr.io und quay.io).",
  pending: "Noch nicht geprüft.",
  deferred: "Wegen des Abruflimits später geprüft.",
  incomparable: "Der Tag ist keine vergleichbare Version (Datum, Hash oder Vorabversion).",
  incomplete: "Die Tag-Liste der Registry ist unvollständig; ein Vergleich wäre unsicher.",
  no_local_digest: "Lokal ist kein Registry-Digest bekannt (selbst gebaut oder nie gezogen).",
};

export interface VerdictView {
  info: StatusInfo;
  /** Ergänzung unter oder neben dem Chip. */
  detail: string | null;
}

/** Chip und Erklärung zu einer Bewertung. Unbekanntes ist nie „aktuell“ und nie rot. */
export function verdictView(v: ContainerVerdict): VerdictView {
  const chip = (label: string, tone: StatusInfo["tone"], icon: StatusInfo["icon"], rank: number): StatusInfo => ({ label, tone, icon, rank });
  switch (v.status) {
    case "current":
      return { info: chip("Aktuell", "ok", "ok", 6), detail: null };
    case "update_available":
      return {
        info: chip("Neueres Image für diesen Tag", "warn", "warn", 1),
        detail: v.platform_confirmed ? null : "Für die Plattform des Hosts nicht bestätigt (nur der Digest weicht ab).",
      };
    case "newer_version": {
      const parts = [v.patch && `Patch ${v.patch}`, v.minor && `Minor ${v.minor}`, v.major && `Major ${v.major}`].filter(Boolean);
      return { info: chip(`Neuere Version ${newest(v) ?? ""}`.trim(), "warn", "warn", 1), detail: parts.join(" · ") || null };
    }
    case "pinned":
      return { info: chip("Gepinnt", "unknown", "pending", 5), detail: "Mit Digest festgelegt, wird bewusst nicht verglichen." };
    case "error":
      return { info: chip("Fehler", "warn", "warn", 2), detail: v.text };
    default:
      return { info: chip("Nicht prüfbar", "unknown", "unknown", 4), detail: UNCHECKED_REASON[v.status] ?? null };
  }
}

/** Hinweis, wenn Docker auf dem Host aus oder nicht erreichbar ist; `null`, wenn alles läuft. */
export function dockerNotice(d: HostContainersResponse["docker"]): { title: string; text: string } | null {
  if (!d) {
    return {
      title: "Docker-Erfassung ist nicht aktiviert",
      text: "Der Agent liest Container nur, wenn es auf dem Host ausdrücklich eingeschaltet ist (docker_enabled in der agent.toml, oder install.sh erneut mit --docker=proxy ausführen). Die Anleitung steht im Abschnitt „Docker-Container“ der README.",
    };
  }
  if (d.state === "ok") return null;
  const why: Record<string, string> = {
    socket_missing: "Der Docker-Socket wurde nicht gefunden. Läuft Docker auf dem Host, und stimmt der Endpunkt in der agent.toml?",
    no_permission: "Der Agent darf den Docker-Socket nicht lesen. Ein Socket-Proxy (nur Lesen) ist der empfohlene Weg; die README beschreibt ihn.",
    timeout: "Docker hat nicht rechtzeitig geantwortet.",
    bad_response: "Docker hat unerwartet geantwortet; die Antwort wurde verworfen.",
  };
  return { title: "Docker ist nicht erreichbar", text: (d.reason && why[d.reason]) || "Der Agent konnte Docker nicht lesen." };
}

export function countOutdated(items: ContainerItem[]): number {
  return items.filter((c) => matchesFilter(c.verdict, "updates")).length;
}
