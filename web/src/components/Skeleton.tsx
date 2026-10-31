/** Platzhalter beim Laden: ruhiges Pulsieren, keine Verläufe. Die Region meldet sich einmal als „lädt“. */
export function Skeleton({ className = "" }: { className?: string }) {
  return <div aria-hidden="true" className={`skeleton ${className}`} />;
}

/** Tabellenrahmen aus Zeilen mit unterschiedlich breiten Balken (Breiten fest, damit nichts zufällig springt). */
export function TableSkeleton({ rows = 6, what = "Daten" }: { rows?: number; what?: string }) {
  const widths = ["w-24", "w-40", "w-20", "w-28", "w-16"];
  return (
    <div role="status" aria-busy="true" aria-label={`${what} werden geladen`} className="border-y border-line">
      <Skeleton className="h-8" />
      {Array.from({ length: rows }, (_, i) => (
        <div key={i} className="flex items-center gap-6 border-b border-line px-3 py-[13px] last:border-b-0">
          {widths.map((w, j) => (
            <Skeleton key={j} className={`h-3 ${w} ${j > 1 ? "max-md:hidden" : ""}`} />
          ))}
        </div>
      ))}
    </div>
  );
}
