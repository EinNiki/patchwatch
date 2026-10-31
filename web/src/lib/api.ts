import { clearApiCache } from "./apiCache";

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

let csrf: string | null = null;

export function setCsrf(token: string | null) {
  csrf = token;
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = {};
  if (body !== undefined) headers["content-type"] = "application/json";
  if (method !== "GET" && csrf) headers["x-csrf-token"] = csrf;
  const res = await fetch(`/api/v1${path}`, {
    method,
    headers,
    credentials: "same-origin",
    body: body === undefined ? undefined : JSON.stringify(body),
  });
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
    throw new ApiError(res.status, message, Number.isFinite(ra) && ra > 0 ? ra : undefined);
  }
  if (res.status === 204 || res.status === 202) return undefined as T;
  return (await res.json()) as T;
}

export const api = {
  get: <T>(path: string) => request<T>("GET", path),
  post: <T>(path: string, body?: unknown) => request<T>("POST", path, body ?? {}),
  put: <T>(path: string, body?: unknown) => request<T>("PUT", path, body),
  del: <T>(path: string) => request<T>("DELETE", path),
};
