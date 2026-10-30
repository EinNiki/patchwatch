/** Leerzustände und Fehler: sagen, was fehlt und was als Nächstes zu tun ist. */
export function Empty({ title, children }: { title: string; children?: React.ReactNode }) {
  return (
    <div className="border border-dashed border-line bg-surface px-4 py-8 text-center">
      <p className="font-semibold">{title}</p>
      {children ? <div className="mx-auto mt-1 max-w-prose text-fg2">{children}</div> : null}
    </div>
  );
}

export function ErrorNote({ message }: { message: string }) {
  return (
    <p role="alert" className="border-l-4 border-crit bg-crit-soft px-3 py-2 text-crit">
      <strong className="font-semibold">Fehler:</strong> {message}
    </p>
  );
}

export function Loading({ what }: { what: string }) {
  return (
    <p role="status" className="px-1 py-6 text-fg3">
      {what} werden geladen …
    </p>
  );
}
