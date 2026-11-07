/** Deutsche Fehlertexte für API-Antworten. Der Server-Text wird nur bei Eingabe-/Konfliktfehlern übernommen (er enthält nie Geheimnisse). */
export function describeApiError(status: number, serverMessage?: string, retryAfter?: number): string {
  const msg = serverMessage?.trim();
  switch (status) {
    case 0:
      return "Server nicht erreichbar.";
    case 400:
    case 422:
      return msg || "Ungültige Eingabe.";
    case 401:
      return "Die Sitzung ist abgelaufen. Bitte neu anmelden.";
    case 403:
      return "Dafür fehlt die Berechtigung.";
    case 404:
      return "Nicht gefunden.";
    case 409:
      return msg || "Das ist mit dem aktuellen Stand nicht vereinbar.";
    case 413:
      return "Die Eingabe ist zu groß.";
    case 429:
      return `Zu viele Anfragen. Erneut möglich in ${retryAfter ?? 60} Sek.`;
    default:
      return status >= 500 ? `Serverfehler (HTTP ${status}). Details stehen im Server-Log.` : msg || `Unerwarteter Fehler (HTTP ${status}).`;
  }
}

/** Meldung für einen fehlgeschlagenen Schreibzugriff: optional mit Kontext ("Token konnte nicht erneuert werden: …"). */
export function writeFailure(what: string | undefined, status: number, serverMessage?: string, retryAfter?: number): string {
  const reason = describeApiError(status, serverMessage, retryAfter);
  return what ? `${what}: ${reason}` : reason;
}
