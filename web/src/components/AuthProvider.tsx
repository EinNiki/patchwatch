"use client";

import { createContext, useContext, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { api, setCsrf } from "@/lib/api";
import type { Me } from "@/lib/types";

interface AuthValue {
  me: Me;
  logout: () => Promise<void>;
}

const Ctx = createContext<AuthValue | null>(null);

export function useAuth(): AuthValue {
  const v = useContext(Ctx);
  if (!v) throw new Error("useAuth außerhalb des AuthProvider");
  return v;
}

/** Prüft die Sitzung; ohne gültige Sitzung geht es zur Anmeldung. */
export function AuthProvider({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const [me, setMe] = useState<Me | null>(null);
  const [checked, setChecked] = useState(false);

  useEffect(() => {
    let alive = true;
    api
      .get<Me>("/auth/me")
      .then((m) => {
        if (!alive) return;
        setCsrf(m.csrf_token);
        setMe(m);
      })
      .catch(() => {
        if (alive) router.replace("/login");
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
  }, [router]);

  if (!checked) {
    return (
      <p role="status" className="p-6 text-fg3">
        Sitzung wird geprüft …
      </p>
    );
  }
  if (!me) return null;

  const logout = async () => {
    try {
      await api.post("/auth/logout");
    } finally {
      setCsrf(null);
      router.replace("/login");
    }
  };
  return <Ctx.Provider value={{ me, logout }}>{children}</Ctx.Provider>;
}
