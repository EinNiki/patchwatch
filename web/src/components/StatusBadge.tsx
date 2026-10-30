import { Icon } from "./Icons";
import { TONE_CLASS, type StatusInfo } from "@/lib/status";

/** Status immer als Icon + Text + Farbe (DESIGN.md): nie nur Farbe. */
export function StatusBadge({ info, label }: { info: StatusInfo; label?: string }) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 whitespace-nowrap rounded-[2px] px-1.5 py-0.5 text-[12px] font-semibold leading-tight ${TONE_CLASS[info.tone]}`}
    >
      <Icon name={info.icon} />
      {label ?? info.label}
    </span>
  );
}
