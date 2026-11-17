"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useApi } from "@/lib/useApi";
import { PageHeader } from "@/components/PageHeader";
import { Tabs } from "@/components/Tabs";
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
  if (!allowed) return <Forbidden />;

  return (
    <>
      <PageHeader title="Benutzer" />
      <Tabs label="Bereiche der Benutzerverwaltung" tabs={TABS} value={tab} onChange={setTab}>
        {tab === "users" ? <UsersTab roles={roles.data} /> : <AuditTab />}
      </Tabs>
    </>
  );
}
