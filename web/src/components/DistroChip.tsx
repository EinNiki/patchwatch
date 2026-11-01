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
export function DistroChip({ d }: { d: Distro }) {
  const s = STATUS[d.status] ?? STATUS.unknown!;
  const title = `${distroName(d.source)} ${d.release}: ${s.word}${d.fix_version ? ` ab ${d.fix_version}` : ""} (Paket ${d.package}${
    d.packages > 1 ? ` und ${d.packages - 1} weitere` : ""
  }, Stand ${absTime(d.updated_at)})${d.mine ? "" : " – läuft auf keinem Host"}`;
  return (
    <span
      title={title}
      className={`chip-fade inline-flex h-(--chip-h) items-center gap-1 whitespace-nowrap rounded-xs border pl-1 pr-1.5 text-xs ${
        d.mine ? "border-line" : "border-dashed border-line"
      }`}
    >
      <span className={s.muted ? "text-fg3" : TONE_TEXT[s.tone]}>
        <Icon name={s.icon} />
      </span>
      <span className="text-fg2">
        {distroName(d.source)} {d.release}
      </span>
      <span className={`font-medium ${s.muted ? "text-fg3" : TONE_TEXT[s.tone]}`}>{s.word}</span>
      {d.fix_version ? <span className="mono text-fg2">{d.fix_version}</span> : null}
    </span>
  );
}

const TONE_TEXT: Record<Tone, string> = { ok: "text-ok", warn: "text-warn", crit: "text-crit", unknown: "text-unknown" };

/** Gedämpfter Marker (Umriss statt Fläche), z. B. „Watchlist“, „Proxmox“. Gleiche Höhe wie die Chips. */
export function Marker({ children }: { children: React.ReactNode }) {
  return <span className="inline-flex h-(--chip-h) items-center whitespace-nowrap rounded-xs border border-line px-1.5 text-xs text-fg2">{children}</span>;
}
