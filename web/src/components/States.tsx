import { Skeleton } from "./Skeleton";

/** Leerzustände: knapp und sachlich, sagen was fehlt und was als Nächstes zu tun ist. */
export function Empty({ title, children }: { title: string; children?: React.ReactNode }) {
  return (
    <div className="border-y border-line px-4 py-8 text-center">
      <p className="font-semibold">{title}</p>
      {children ? <div className="mx-auto mt-1 max-w-prose text-fg2">{children}</div> : null}
    </div>
  );
}

export function ErrorNote({ message }: { message: string }) {
  return (
    <p role="alert" className="border-l-2 border-crit bg-crit-soft px-3 py-2 text-crit">
      <strong className="font-semibold">Fehler:</strong> {message}
    </p>
  );
}

/** Ladezustand als Skeleton (kein Spinner); `what` benennt, was lädt. */
export function Loading({ what }: { what: string }) {
  return (
    <div role="status" aria-busy="true" aria-label={`${what} werden geladen`} className="flex flex-col gap-3 py-2">
      <Skeleton className="h-4 w-40" />
      <Skeleton className="h-9" />
      <Skeleton className="h-9" />
      <Skeleton className="h-9 w-2/3" />
    </div>
  );
}
