import { clearApiCache } from "./apiCache";
import { writeFailure } from "./apiErrors";
import { toast } from "./toastStore";

// Dünner Client für die Rust-API. Ein Backend im Sinne von Next.js gibt es nicht.

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
    /** Sekunden bis zum nächsten erlaubten Versuch (Header Retry-After bei 429). */
    public retryAfter?: number,
  ) {
    super(message);
  }
}

/** Optionen für Schreibzugriffe. Fehler erscheinen automatisch als Fehler-Toast, außer mit `silent`. */
export interface WriteOptions {
  /** Kein automatischer Fehler-Toast: für Feldfehler im Formular und Aufrufer mit eigener Behandlung. */
  silent?: boolean;
  /** Kontext für den Toast, z. B. "Token konnte nicht erneuert werden" (ergibt "…: <Grund>"). */
  what?: string;
}

let csrf: string | null = null;

export function setCsrf(token: string | null) {
  csrf = token;
}

async function request<T>(method: string, path: string, body?: unknown, opts: WriteOptions = {}): Promise<T> {
  const headers: Record<string, string> = {};
  if (body !== undefined) headers["content-type"] = "application/json";
  if (method !== "GET" && csrf) headers["x-csrf-token"] = csrf;
  // Schreibzugriffe zeigen ihren Fehler selbst als Toast; Lesezugriffe zeigen Fehler an der Stelle, die sie braucht.
  const notify = (status: number, message?: string, retryAfter?: number) => {
    // Login und Logout zeigen ihre Fehler im Formular bzw. gar nicht.
    if (method === "GET" || opts.silent || typeof window === "undefined" || path === "/auth/login" || path === "/auth/logout") return;
    // 401: die App leitet zur Anmeldung; der Login zeigt seine Fehler im Formular.
    if (status === 401) return;
    toast.error(writeFailure(opts.what, status, message, retryAfter));
  };
  let res: Response;
  try {
    res = await fetch(`/api/v1${path}`, {
      method,
      headers,
      credentials: "same-origin",
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch {
    notify(0);
    throw new ApiError(0, "Server nicht erreichbar");
  }
  if (!res.ok) {
    let message = res.statusText;
    try {
      message = ((await res.json()) as { error?: string }).error ?? message;
    } catch {
      /* keine JSON-Antwort */
    }
    // Abgelaufene Sitzung: App leitet zur Anmeldung. Der Login selbst ist ausgenommen.
    if (res.status === 401 && path !== "/auth/login" && typeof window !== "undefined") {
      clearApiCache();
      window.dispatchEvent(new Event("pw:unauthorized"));
    }
    const ra = Number(res.headers.get("retry-after"));
    const retryAfter = Number.isFinite(ra) && ra > 0 ? ra : undefined;
    notify(res.status, message, retryAfter);
    throw new ApiError(res.status, message, retryAfter);
  }
  if (res.status === 204 || res.status === 202) return undefined as T;
  // Leere 2xx-Antworten (z. B. 201 ohne Body) sind ein Erfolg, kein Parse-Fehler.
  const text = await res.text();
  return (text ? JSON.parse(text) : undefined) as T;
}

export const api = {
  get: <T>(path: string) => request<T>("GET", path),
  post: <T>(path: string, body?: unknown, opts?: WriteOptions) => request<T>("POST", path, body ?? {}, opts),
  put: <T>(path: string, body?: unknown, opts?: WriteOptions) => request<T>("PUT", path, body, opts),
  del: <T>(path: string, opts?: WriteOptions) => request<T>("DELETE", path, undefined, opts),
};
