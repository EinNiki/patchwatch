"use client";

import { useEffect } from "react";
import { ErrorScreen } from "@/components/ErrorScreen";

/** Render-Fehler einer Seite: bleibt im App-Rahmen (Navigation nutzbar), „Erneut versuchen“ rendert die Seite neu. */
export default function AppError({ error, reset }: { error: Error & { digest?: string }; reset: () => void }) {
  useEffect(() => {
    // Nur in die Browser-Konsole, nie in die Oberfläche.
    console.error(error);
  }, [error]);
  return (
    <ErrorScreen
      title="Diese Seite konnte nicht angezeigt werden"
      message="Beim Anzeigen ist ein unerwarteter Fehler aufgetreten. Die Daten sind davon nicht betroffen."
      onRetry={reset}
    />
  );
}
