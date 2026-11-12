import { Button } from "./Controls";

/**
 * Fehlerzustand ohne App-Rahmen (Sitzungsprüfung gescheitert, Render-Fehler): Ursache in einem Satz und „Erneut versuchen“.
 * Ruhig und ohne technische Details; `page` füllt die Seite (eigenes `main`), sonst steht er im Inhalt der App.
 */
export function ErrorScreen({ title, message, onRetry, page = false }: { title: string; message: string; onRetry: () => void; page?: boolean }) {
  const body = (
    <>
      <div role="alert" className="border-l-2 border-crit bg-crit-soft px-3 py-2">
        <h1 className="font-semibold text-crit">{title}</h1>
        <p className="mt-1 text-fg">{message}</p>
      </div>
      <p className="mt-3">
        <Button onClick={onRetry}>Erneut versuchen</Button>
      </p>
    </>
  );
  if (!page) return <div className="max-w-prose py-2">{body}</div>;
  return (
    <main id="main" tabIndex={-1} className="mx-auto flex min-h-dvh max-w-md flex-col justify-center px-4">
      <p className="mb-4 font-mono text-xl font-medium">patchwatch</p>
      {body}
    </main>
  );
}
