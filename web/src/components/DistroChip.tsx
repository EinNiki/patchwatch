import { Icon } from "./Icons";
import type { IconName, Tone } from "@/lib/status";
import { absTime } from "@/lib/format";
import type { Distro } from "@/lib/types";

const DISTRO_NAME: Record<string, string> = { debian: "Debian", ubuntu: "Ubuntu", osv: "OSV" };
export const distroName = (source: string): string => DISTRO_NAME[source] ?? source;

const STATUS: Record<string, { word: string; tone: Tone; icon: IconName; muted?: boolean }> = {
  fixed: { word: "gefixt", tone: "ok", icon: "ok" },
  not_affected: { word: "nicht betroffen", tone: "ok", icon: "ok", muted: true },
  fix_pending: { word: "verwundbar, Fix in Arbeit", tone: "crit", icon: "crit" },
  vulnerable: { word: "verwundbar", tone: "crit", icon: "crit" },
  unknown: { word: "unbekannt", tone: "unknown", icon: "unknown" },
};

/**
 * Chip je Quelle und Release: Icon + Text + Farbe (nie nur Farbe). Release in Graustufe, Statuswort in der Statusfarbe,
 * Fix-Version in Mono, kein Trennzeichen. Umriss statt Fläche (viele Chips nebeneinander bleiben ruhig);
 * gestrichelt = Release läuft auf keinem Host.
 */
export function DistroChip({ d, allScope = false }: { d: Distro; allScope?: boolean }) {
  const s = STATUS[d.status] ?? STATUS.unknown!;
  // Zählt für den aktuellen Umfang: Release läuft auf einem Host oder der Umfang ist „Alle Releases“.
  const counts = allScope || d.mine;
  const title = `${distroName(d.source)} ${d.release}: ${s.word}${d.fix_version ? ` ab ${d.fix_version}` : ""} (Paket ${d.package}${
    d.packages > 1 ? ` und ${d.packages - 1} weitere` : ""
  }, Stand ${absTime(d.updated_at)})${counts ? " – zählt für den Filter" : " – läuft auf keinem deiner Hosts, zählt nicht für den Filter"}`;
  return (
    <span
      title={title}
      className={`chip-fade inline-flex h-(--chip-h) items-center gap-1 whitespace-nowrap rounded-xs border pl-1 pr-1.5 text-xs ${
        counts ? "border-line" : "border-dashed border-line bg-sunk"
      }`}
      data-counts={counts ? "yes" : "no"}
    >
      <span className={s.muted ? "text-fg3" : TONE_TEXT[s.tone]}>
        <Icon name={s.icon} />
      </span>
      <span className="text-fg2">
        {distroName(d.source)} {d.release}
      </span>
      <span className={`font-medium ${s.muted ? "text-fg3" : TONE_TEXT[s.tone]}`}>{s.word}</span>
      {d.fix_version ? <span className="mono text-fg2">{d.fix_version}</span> : null}
      <ScopeMark counts={counts} />
    </span>
  );
}

/** Kennzeichnung „zählt“ (gefüllter Punkt) bzw. „zählt nicht“ (durchgestrichener Ring): Icon plus Text, nie nur Farbe. */
export function ScopeMark({ counts }: { counts: boolean }) {
  return (
    <span className={`inline-flex items-center gap-0.5 border-l border-line pl-1 text-[0.6875rem] ${counts ? "text-fg2" : "text-fg3"}`}>
      <svg width="9" height="9" viewBox="0 0 10 10" aria-hidden="true" focusable="false">
        {counts ? (
          <circle cx="5" cy="5" r="3" fill="currentColor" />
        ) : (
          <>
            <circle cx="5" cy="5" r="3.5" fill="none" stroke="currentColor" strokeWidth="1.2" />
            <path d="M2.5 7.5l5-5" stroke="currentColor" strokeWidth="1.2" />
          </>
        )}
      </svg>
      {counts ? "zählt" : "zählt nicht"}
    </span>
  );
}

/** Legende zu den Chips: erklärt Rahmen und Kennzeichnung (Umfang des Filters). */
export function ChipLegend({ allScope }: { allScope: boolean }) {
  return (
    <p className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-fg3">
      <span className="inline-flex items-center gap-1">
        <span className="inline-block h-3 w-6 rounded-xs border border-line" aria-hidden="true" />
        <ScopeMark counts /> Release läuft auf einem deiner Hosts{allScope ? " (bei „Alle Releases“ zählt jeder Chip)" : ""}
      </span>
      <span className="inline-flex items-center gap-1">
        <span className="inline-block h-3 w-6 rounded-xs border border-dashed border-line bg-sunk" aria-hidden="true" />
        <ScopeMark counts={false} /> läuft auf keinem deiner Hosts, zählt nicht für den Filter (außer bei „Alle Releases“)
      </span>
    </p>
  );
}

const TONE_TEXT: Record<Tone, string> = { ok: "text-ok", warn: "text-warn", crit: "text-crit", unknown: "text-unknown" };

/** Gedämpfter Marker (Umriss statt Fläche), z. B. „Watchlist“, „Proxmox“. Gleiche Höhe wie die Chips. */
export function Marker({ children }: { children: React.ReactNode }) {
  return <span className="inline-flex h-(--chip-h) items-center whitespace-nowrap rounded-xs border border-line px-1.5 text-xs text-fg2">{children}</span>;
}
