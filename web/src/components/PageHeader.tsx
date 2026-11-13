/**
 * Seitenkopf (überall gleich): Titel, Zählung, optional Marker und eine Beschreibungszeile, Linie darunter.
 * Enthält NIE Knöpfe: Aktionen stehen im SectionHeader darunter.
 */
export function PageHeader({
  title,
  count,
  badge,
  description,
}: {
  title: string;
  count?: React.ReactNode;
  badge?: React.ReactNode;
  description?: React.ReactNode;
}) {
  return (
    <header className="mb-3 border-b border-line pb-3" data-page-header>
      <div className="flex min-h-7 flex-wrap items-baseline gap-x-3 gap-y-1" data-page-title-row>
        <h1 className="text-xl font-semibold">{title}</h1>
        {count ? <span className="text-sm text-fg3">{count}</span> : null}
        {badge}
      </div>
      {description ? <div className="mt-1 text-xs text-fg2">{description}</div> : null}
    </header>
  );
}

/**
 * Bereichskopf (überall gleich): links Bereichstitel (oder Filter), rechts die Knöpfe des Bereichs.
 * Reihenfolge der Knöpfe: Nebenaktionen links, Hauptaktion ganz rechts; 8 px Abstand; mobil unter dem Titel.
 */
export function SectionHeader({
  id,
  title,
  children,
  actions,
  actionsClassName = "",
  testId,
}: {
  id?: string;
  actionsClassName?: string;
  testId?: string;
  title?: React.ReactNode;
  children?: React.ReactNode;
  actions?: React.ReactNode;
}) {
  return (
    <div className="mb-2 flex min-h-8 flex-wrap items-center gap-x-4 gap-y-2" data-section-header data-testid={testId}>
      {title ? (
        <h2 id={id} className="m-0 text-lg font-semibold">
          {title}
        </h2>
      ) : null}
      {children}
      {actions ? (
        <div className={`ml-auto flex max-w-full flex-wrap items-center justify-end gap-2 ${actionsClassName}`} data-section-actions>
          {actions}
        </div>
      ) : null}
    </div>
  );
}
