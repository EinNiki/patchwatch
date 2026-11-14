"use client";

import { createContext, useCallback, useContext, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { api, setCsrf } from "@/lib/api";
import { clearApiCache } from "@/lib/apiCache";
import type { Me } from "@/lib/types";
import { ForcedPasswordChange } from "@/components/ForcedPasswordChange";
import { ErrorScreen } from "@/components/ErrorScreen";
import { sessionFailure } from "@/lib/session";

interface AuthValue {
  me: Me;
  logout: () => Promise<void>;
  /** Neuer Cache-Schlüssel des Profilbilds nach Hochladen (Zahl) oder Entfernen (`null`). */
  setAvatar: (v: number | null) => void;
  /** Neuer Anzeigename nach dem Speichern in den Einstellungen. */
  setDisplayName: (v: string) => void;
}

const Ctx = createContext<AuthValue | null>(null);

export function useAuth(): AuthValue {
  const v = useContext(Ctx);
  if (!v) throw new Error("useAuth außerhalb des AuthProvider");
  return v;
}

/**
 * Prüft die Sitzung. Nur ohne gültige Sitzung (401) geht es zur Anmeldung; ist Server oder Datenbank nicht erreichbar,
 * erscheint ein Fehlerzustand mit „Erneut versuchen“ (die Sitzung kann weiter gelten).
 */
export function AuthProvider({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const [me, setMe] = useState<Me | null>(null);
  const [checked, setChecked] = useState(false);
  const [failure, setFailure] = useState<string | null>(null);
  const [attempt, setAttempt] = useState(0);
  const retry = useCallback(() => {
    setFailure(null);
    setChecked(false);
    setAttempt((n) => n + 1);
  }, []);

  useEffect(() => {
    let alive = true;
    api
      .get<Me>("/auth/me")
      .then((m) => {
        if (!alive) return;
        setCsrf(m.csrf_token);
        setMe(m);
      })
      .catch((e: unknown) => {
        if (!alive) return;
        const f = sessionFailure(e);
        if (f.kind === "login") router.replace("/login");
        else setFailure(f.message);
      })
      .finally(() => {
        if (alive) setChecked(true);
      });
    const onUnauthorized = () => router.replace("/login");
    window.addEventListener("pw:unauthorized", onUnauthorized);
    return () => {
      alive = false;
      window.removeEventListener("pw:unauthorized", onUnauthorized);
    };
  }, [router, attempt]);

  if (!checked) {
    return (
      <p role="status" className="p-6 text-fg3">
        Sitzung wird geprüft …
      </p>
    );
  }
  if (failure) return <ErrorScreen page title="Anmeldung kann gerade nicht geprüft werden" message={failure} onRetry={retry} />;
  if (!me) return null;

  const logout = async () => {
    // Schon vor der Abmeldung leeren und die Sitzungsnummer erhöhen: Anfragen, die jetzt noch laufen, füllen den Cache nicht mehr.
    clearApiCache();
    try {
      await api.post("/auth/logout");
    } finally {
      setCsrf(null);
      clearApiCache();
      router.replace("/login");
    }
  };
  // Start-Passwort: nur der Passwortwechsel ist erlaubt (der Server sperrt alles andere mit 403).
  if (me.must_change_password) {
    return <ForcedPasswordChange username={me.username} onDone={() => setMe({ ...me, must_change_password: false })} onLogout={() => void logout()} />;
  }
  return <Ctx.Provider value={{ me, logout, setAvatar: (v) => setMe({ ...me, avatar: v }), setDisplayName: (v) => setMe({ ...me, display_name: v }) }}>{children}</Ctx.Provider>;
}
