"use client";

import "./globals.css";
import { ErrorScreen } from "@/components/ErrorScreen";

/** Letzte Auffangstelle (Fehler im Seitenrahmen selbst): ersetzt das Root-Layout, daher eigenes `html`/`body`. */
export default function GlobalError({ reset }: { error: Error & { digest?: string }; reset: () => void }) {
  return (
    <html lang="de">
      <body>
        <ErrorScreen
          page
          title="patchwatch konnte nicht angezeigt werden"
          message="Beim Anzeigen ist ein unerwarteter Fehler aufgetreten. Die Daten sind davon nicht betroffen."
          onRetry={reset}
        />
      </body>
    </html>
  );
}
