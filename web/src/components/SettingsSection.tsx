/** Einstellungsabschnitt: ab 1024 px links Titel und Text (15 rem), rechts das Formular; darunter untereinander. */
export function SettingsSection({ id, title, description, children }: { id: string; title: string; description?: React.ReactNode; children: React.ReactNode }) {
  return (
    <section aria-labelledby={id} className="border-t border-line py-6 first:border-t-0 first:pt-0 lg:grid lg:grid-cols-[15rem_minmax(0,1fr)] lg:gap-x-10">
      <div className="mb-3 lg:mb-0">
        <h2 id={id} className="text-lg font-semibold">
          {title}
        </h2>
        {description ? <p className="mt-1 max-w-prose text-sm text-fg2">{description}</p> : null}
      </div>
      <div className="min-w-0">{children}</div>
    </section>
  );
}
