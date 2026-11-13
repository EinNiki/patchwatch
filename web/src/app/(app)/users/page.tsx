"use client";

import { useEffect, useRef, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useApi } from "@/lib/useApi";
import { PageHeader } from "@/components/PageHeader";
import { useAuth } from "@/components/AuthProvider";
import { can, type RolesResponse } from "@/lib/roles";
import { UsersTab } from "@/components/users/UsersTab";
import { AuditTab } from "@/components/users/AuditTab";

const TABS = [
  { id: "users", label: "Benutzer" },
  { id: "audit", label: "Aktivität" },
] as const;
type TabId = (typeof TABS)[number]["id"];

/** 403-Seite bei direktem Aufruf ohne Recht. Der Server verweigert die Daten ohnehin. */
function Forbidden() {
  return (
    <div className="max-w-prose py-2">
      <div role="alert" className="border-l-2 border-crit bg-crit-soft px-3 py-2">
        <h1 className="font-semibold text-crit">Kein Zugriff (403)</h1>
        <p className="mt-1 text-fg">Die Benutzerverwaltung ist Administratoren vorbehalten. Dir fehlt dafür die Berechtigung.</p>
      </div>
      <p className="mt-3">
        <Link href="/">Zur Übersicht</Link>
      </p>
    </div>
  );
}

export default function UsersPage() {
  const { me } = useAuth();
  const allowed = can(me.permissions, "users.manage");
  // Nur mit Recht laden (der Server würde sonst mit 403 antworten).
  const roles = useApi<RolesResponse>(allowed ? "/roles" : null);
  const [tab, setTab] = useState<TabId>("users");
  const router = useRouter();
  // OIDC liegt jetzt unter Einstellungen: alte Lesezeichen auf /users#oidc führen dorthin.
  useEffect(() => {
    const go = () => {
      if (window.location.hash === "#oidc") router.replace("/settings#oidc");
    };
    go();
    window.addEventListener("hashchange", go);
    return () => window.removeEventListener("hashchange", go);
  }, [router]);
  const refs = useRef<Record<string, HTMLButtonElement | null>>({});
  if (!allowed) return <Forbidden />;

  function onKey(e: React.KeyboardEvent, i: number) {
    const d = e.key === "ArrowRight" ? 1 : e.key === "ArrowLeft" ? -1 : 0;
    if (!d) return;
    e.preventDefault();
    const next = TABS[(i + d + TABS.length) % TABS.length];
    setTab(next.id);
    refs.current[next.id]?.focus();
  }

  return (
    <>
      <PageHeader title="Benutzer" />
      <div role="tablist" aria-label="Bereiche der Benutzerverwaltung" className="mb-4 flex gap-1 border-b border-line">
        {TABS.map((t, i) => (
          <button
            key={t.id}
            ref={(el) => {
              refs.current[t.id] = el;
            }}
            type="button"
            role="tab"
            id={`tab-${t.id}`}
            aria-selected={tab === t.id}
            aria-controls={`panel-${t.id}`}
            tabIndex={tab === t.id ? 0 : -1}
            onClick={() => setTab(t.id)}
            onKeyDown={(e) => onKey(e, i)}
            className={`-mb-px min-h-8 border-b-2 px-3 text-sm font-semibold max-md:min-h-11 ${tab === t.id ? "border-accent text-fg" : "border-transparent text-fg2 hover:text-fg"}`}
          >
            {t.label}
          </button>
        ))}
      </div>
      <div role="tabpanel" id={`panel-${tab}`} aria-labelledby={`tab-${tab}`}>
        {tab === "users" ? <UsersTab roles={roles.data} /> : <AuditTab />}
      </div>
    </>
  );
}
