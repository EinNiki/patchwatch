import { describeApiError } from "./apiErrors.ts";

/** Ergebnis einer fehlgeschlagenen Sitzungsprüfung (`GET /auth/me`). */
export type SessionFailure = { kind: "login" } | { kind: "error"; message: string };

/**
 * Nur 401 heißt "nicht angemeldet" und führt zur Anmeldung. Alles andere (Netzfehler, 5xx, 503 bei nicht erreichbarer
 * Datenbank) ist ein vorübergehender Fehler: die Sitzung kann noch gültig sein, also Fehlerzustand mit „Erneut versuchen“.
 */
export function sessionFailure(err: unknown): SessionFailure {
  const e = err as { status?: unknown; message?: unknown; retryAfter?: unknown } | null;
  const status = typeof e?.status === "number" ? e.status : 0;
  if (status === 401) return { kind: "login" };
  const retryAfter = typeof e?.retryAfter === "number" ? e.retryAfter : undefined;
  return { kind: "error", message: describeApiError(status, undefined, retryAfter) };
}
