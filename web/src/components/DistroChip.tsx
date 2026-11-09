import { Icon } from "./Icons";
import type { IconName, Tone } from "@/lib/status";
import type { Distro } from "@/lib/types";
import { chipTitle, distroName, STATUS, SUITE_WORD, suiteParts } from "@/lib/chips";

export { distroName };

const SUITE_TONE: Record<string, { tone: Tone; icon: IconName; muted?: boolean }> = {
  fixed: { tone: "ok", icon: "ok" },
  vulnerable: { tone: "crit", icon: "crit" },
  not_affected: { tone: "ok", icon: "ok", muted: true },
  unknown: { tone: "unknown", icon: "unknown" },
};

/**
 * Chip je Quelle und Release: Icon + Text + Farbe (nie nur Farbe). Release in Graustufe, Statuswort in der Statusfarbe,
 * Fix-Version in Mono. Umriss statt Fläche; gestrichelt und gedämpft = Release läuft auf keinem deiner Hosts
 * (Release ohne Host). Debian zeigt Security und Archiv getrennt, wenn sie sich unterscheiden.
 */
export function DistroChip({ d }: { d: Distro }) {
  const s = STATUS[d.status] ?? STATUS.unknown!;
  const outside = !d.mine;
  const parts = suiteParts(d);
  return (
    <span
      title={chipTitle(d)}
      className={`chip-fade inline-flex min-h-(--chip-h) max-w-full flex-wrap items-center gap-x-1 whitespace-normal rounded-xs border pl-1 pr-1.5 text-xs ${
        outside ? "border-dashed border-line bg-sunk opacity-80" : "border-line"
      }`}
      data-outside={outside ? "yes" : "no"}
    >
      {parts ? null : (
        <span className={s.muted ? "text-fg3" : TONE_TEXT[s.tone]}>
          <Icon name={s.icon} />
        </span>
      )}
      <span className="text-fg2">
        {distroName(d.source)} {d.release}
      </span>
      {parts ? (
        parts.map((p, i) => {
          const t = SUITE_TONE[p.status] ?? SUITE_TONE.unknown!;
          return (
            <span key={p.label || "x"} className="inline-flex items-center gap-1">
              {i > 0 ? <span aria-hidden="true" className="text-fg3">·</span> : null}
              <span className={t.muted ? "text-fg3" : TONE_TEXT[t.tone]}>
                <Icon name={t.icon} />
              </span>
              {p.label ? <span className="text-fg2">{p.label}</span> : null}
              <span className={`font-medium ${t.muted ? "text-fg3" : TONE_TEXT[t.tone]}`}>{SUITE_WORD[p.status] ?? p.status}</span>
              {p.version ? <span className="mono text-fg2">{p.version}</span> : null}
            </span>
          );
        })
      ) : (
        <>
          <span className={`font-medium ${s.muted ? "text-fg3" : TONE_TEXT[s.tone]}`}>{s.word}</span>
          {d.fix_version ? <span className="mono text-fg2">{d.fix_version}</span> : null}
        </>
      )}
    </span>
  );
}

/**
 * Legende zu den Chips in einer Zeile. Sie erscheint nur, wenn auf der Seite ein abgesetzter Chip steht
 * (`data-outside="yes"`), per CSS `:has()`.
 */
export function ChipLegend() {
  return (
    <p className="chip-legend mt-2 hidden items-center gap-1.5 text-xs text-fg3" role="note">
      <span className="inline-block h-3 w-6 rounded-xs border border-dashed border-line bg-sunk" aria-hidden="true" />
      Gestrichelt: Release läuft auf keinem deiner Hosts
    </p>
  );
}

const TONE_TEXT: Record<Tone, string> = { ok: "text-ok", warn: "text-warn", crit: "text-crit", unknown: "text-unknown" };

/** Gedämpfter Marker (Umriss statt Fläche), z. B. „Watchlist“, „Proxmox“. Gleiche Höhe wie die Chips. */
export function Marker({ children }: { children: React.ReactNode }) {
  return <span className="inline-flex h-(--chip-h) items-center whitespace-nowrap rounded-xs border border-line px-1.5 text-xs text-fg2">{children}</span>;
}
