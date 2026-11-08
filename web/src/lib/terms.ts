/**
 * Sichtbare Begriffe für die Meldungen der Agents. Intern (API, Felder, Routen, Logs) heißen sie weiter "Report" und
 * "Check-in"; die Oberfläche sagt, was passiert.
 */
export const DATA_LABEL = "Daten zuletzt";
export const DATA_TIP =
  "Der Agent hat zuletzt vollständige Daten gemeldet (Kernel, Pakete, Updates). Das passiert einmal täglich und wenn du „Daten jetzt abrufen“ drückst.";
export const ACTIVE_LABEL = "Agent zuletzt aktiv";
export const ACTIVE_TIP =
  "Der Agent hat sich zuletzt kurz gemeldet, um zu fragen, ob neue Daten gewünscht sind. Das passiert alle paar Minuten und überträgt keine Daten.";
export const FETCH_ACTION = "Daten jetzt abrufen";
export const FETCH_ALL_ACTION = "Alle Daten abrufen";
