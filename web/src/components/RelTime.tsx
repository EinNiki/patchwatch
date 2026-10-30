import { absTime, relTime } from "@/lib/format";

/** Relative Zeit; absoluter Wert als `title` und `dateTime`. */
export function RelTime({ iso, className = "" }: { iso: string | null; className?: string }) {
  if (!iso) return <span className={`text-fg3 ${className}`}>nie</span>;
  return (
    <time dateTime={iso} title={absTime(iso)} className={className}>
      {relTime(iso)}
    </time>
  );
}
