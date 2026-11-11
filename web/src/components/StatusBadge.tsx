import { Icon } from "./Icons";
import { TONE_CLASS, type StatusInfo } from "@/lib/status";

/** Status immer als Icon + Text + Farbe (DESIGN.md): nie nur Farbe. 22 px hoch, `chip-fade` blendet Wechsel weich ein. */
export function StatusBadge({ info, label }: { info: StatusInfo; label?: string }) {
  return (
    <span className={`chip-fade inline-flex h-(--chip-h) items-center gap-1 whitespace-nowrap rounded-xs pl-1 pr-1.5 text-xs font-medium ${TONE_CLASS[info.tone]}`}>
      <Icon name={info.icon} />
      {label ?? info.label}
    </span>
  );
}
