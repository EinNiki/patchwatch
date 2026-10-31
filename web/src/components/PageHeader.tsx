/** Seitenkopf: Titel, Zählung in text-3, rechts die Hauptaktion. */
export function PageHeader({ title, count, children }: { title: string; count?: string; children?: React.ReactNode }) {
  return (
    <div className="mb-5 flex flex-wrap items-center gap-x-4 gap-y-2">
      <h1 className="text-xl font-semibold">{title}</h1>
      {count ? <span className="text-fg3">{count}</span> : null}
      {children ? <div className="ml-auto flex flex-wrap items-center gap-2">{children}</div> : null}
    </div>
  );
}
