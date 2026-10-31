"use client";

import Link from "next/link";
import { useApi } from "@/lib/useApi";
import { CHANNELS, EVENTS } from "@/lib/channels";
import type { NotificationsResponse } from "@/lib/types";
import { PageHeader } from "@/components/PageHeader";
import { RelTime } from "@/components/RelTime";
import { ErrorNote, Loading } from "@/components/States";
import { StatusBadge } from "@/components/StatusBadge";
import { Mono } from "@/components/Version";

export default function NotificationsPage() {
  const n = useApi<NotificationsResponse>("/notifications", 60_000);
  return (
    <>
      <PageHeader title="Benachrichtigungen" />
      <p className="mb-4 max-w-prose text-fg2">
        Jeder Kanal hat eigene Zugangsdaten und eigene Ereignisse. Zugangsdaten werden verschlüsselt gespeichert und nach dem Speichern nie wieder angezeigt.
      </p>
      {n.data && !n.data.secret_storage ? (
        <p className="mb-4 max-w-prose border-l-4 border-warn bg-warn-soft px-3 py-2 text-warn">
          Auf dem Server ist <Mono>PATCHWATCH_SECRET_KEY</Mono> nicht gesetzt. Ohne ihn lassen sich keine Tokens und Webhook-URLs speichern; nur Kanäle ohne Geheimnis
          (Live im Browser, ntfy ohne Token) funktionieren.
        </p>
      ) : null}
      {n.error && !n.data ? <ErrorNote message={n.error} /> : null}
      {!n.data ? (
        n.error ? null : <Loading what="Kanäle" />
      ) : (
        <div className="overflow-x-auto border border-line">
          <table className="tbl stack">
            <caption>Benachrichtigungskanäle mit Zustand</caption>
            <thead>
              <tr>
                <th scope="col"><span className="th-pad">Kanal</span></th>
                <th scope="col"><span className="th-pad">Zustand</span></th>
                <th scope="col"><span className="th-pad">Ereignisse</span></th>
                <th scope="col"><span className="th-pad">Letztes Ergebnis</span></th>
              </tr>
            </thead>
            <tbody>
              {CHANNELS.map((c) => {
                const ch = n.data!.channels.find((x) => x.kind === c.kind);
                return (
                  <tr key={c.kind}>
                    <td data-label="Kanal">
                      <Link href={`/notifications/${c.kind}`} className="font-semibold">
                        {c.label}
                      </Link>
                      {ch?.from_env ? <div className="text-xs text-fg3">aus Umgebungsvariablen</div> : null}
                    </td>
                    <td data-label="Zustand">
                      {ch?.enabled ? (
                        <StatusBadge info={{ label: "", tone: "ok", icon: "ok", rank: 0 }} label="Aktiv" />
                      ) : (
                        <StatusBadge info={{ label: "", tone: "unknown", icon: "pending", rank: 0 }} label="Aus" />
                      )}
                    </td>
                    <td data-label="Ereignisse" className="max-w-[28rem] text-fg2">
                      {ch && ch.events.length > 0 ? ch.events.map((e) => EVENTS.find((x) => x.id === e)?.label ?? e).join(", ") : <span className="text-fg3">keine</span>}
                    </td>
                    <td data-label="Letztes Ergebnis">
                      {ch?.last_error ? (
                        <span className="text-warn">Fehler: {ch.last_error}</span>
                      ) : ch?.last_ok_at ? (
                        <span>
                          Gesendet <RelTime iso={ch.last_ok_at} />
                        </span>
                      ) : (
                        <span className="text-fg3">noch nichts gesendet</span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}
