import { Icon } from "./Icons";
import { TONE_CLASS, type IconName, type Tone } from "@/lib/status";
import { absTime } from "@/lib/format";
import type { Distro } from "@/lib/types";

const DISTRO_NAME: Record<string, string> = { debian: "Debian", ubuntu: "Ubuntu", osv: "OSV" };
export const distroName = (source: string): string => DISTRO_NAME[source] ?? source;

const STATUS: Record<string, { word: string; tone: Tone; icon: IconName; muted?: boolean }> = {
  fixed: { word: "gefixt", tone: "ok", icon: "ok" },
  not_affected: { word: "nicht betroffen", tone: "ok", icon: "ok", muted: true },
  fix_pending: { word: "Fix in Arbeit", tone: "warn", icon: "clock" },
  vulnerable: { word: "verwundbar", tone: "crit", icon: "crit" },
  unknown: { word: "unbekannt", tone: "unknown", icon: "unknown" },
};

/** Chip je Quelle und Release: Icon + Text + Farbe (nie nur Farbe), Fix-Version in Mono. */
export function DistroChip({ d }: { d: Distro }) {
  const s = STATUS[d.status] ?? STATUS.unknown!;
  const title = `${distroName(d.source)} ${d.release}: ${s.word}${d.fix_version ? ` ab ${d.fix_version}` : ""} (Paket ${d.package}${
    d.packages > 1 ? ` und ${d.packages - 1} weitere` : ""
  }, Stand ${absTime(d.updated_at)})${d.mine ? "" : " – läuft auf keinem Host"}`;
  return (
    <span
      title={title}
      className={`inline-flex items-center gap-1.5 whitespace-nowrap rounded-[2px] px-1.5 py-0.5 text-[12px] font-medium leading-tight ${
        s.muted ? "bg-unknown-soft text-fg2" : TONE_CLASS[s.tone]
      } ${d.mine ? "" : "border border-dashed border-current"}`}
    >
      <Icon name={s.icon} />
      <span>
        {distroName(d.source)} {d.release} · {s.word}
        {d.fix_version ? (
          <>
            {" "}
            <span className="font-mono text-[11px]">{d.fix_version}</span>
          </>
        ) : null}
      </span>
    </span>
  );
}

/** Gedämpfter Marker (Rahmen statt Fläche), z. B. „Watchlist“. */
export function Marker({ children }: { children: React.ReactNode }) {
  return <span className="inline-flex items-center whitespace-nowrap rounded-[2px] border border-line px-1.5 py-0.5 text-[12px] leading-tight text-fg2">{children}</span>;
}
