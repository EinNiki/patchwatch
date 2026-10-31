"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useApi } from "@/lib/useApi";
import { CHANNELS } from "@/lib/channels";
import type { NotificationsResponse } from "@/lib/types";
import { Icon } from "@/components/Icons";

/** Ab 1024 px: Kanalliste links, Inhalt (Übersicht oder Formular) rechts. Darunter nur der Inhalt (Liste steht auf /notifications). */
export default function NotificationsLayout({ children }: { children: React.ReactNode }) {
  const n = useApi<NotificationsResponse>("/notifications", 60_000);
  const path = usePathname();
  return (
    <div className="lg:grid lg:grid-cols-[17rem_minmax(0,1fr)] lg:gap-x-8">
      <nav aria-label="Kanäle" className="hidden lg:block">
        <ul className="sticky top-4 border-y border-line">
          {CHANNELS.map((c) => {
            const ch = n.data?.channels.find((x) => x.kind === c.kind);
            const href = `/notifications/${c.kind}`;
            const current = path === href;
            return (
              <li key={c.kind} className="border-b border-line last:border-b-0">
                <Link
                  href={href}
                  aria-current={current ? "page" : undefined}
                  className={`flex min-h-12 items-center gap-2 px-2 py-1.5 text-fg no-underline hover:bg-sunk ${current ? "bg-sunk shadow-[inset_2px_0_0_var(--accent)]" : ""}`}
                >
                  <span className={ch?.last_error ? "text-warn" : ch?.enabled ? "text-ok" : "text-fg3"}>
                    <Icon name={ch?.last_error ? "warn" : ch?.enabled ? "ok" : "pending"} />
                  </span>
                  <span className="min-w-0 flex-1">
                    <span className="block truncate font-semibold">{c.label}</span>
                    <span className="block truncate text-xs text-fg3" title={ch?.last_error ?? undefined}>
                      {ch?.last_error ? `Fehler: ${ch.last_error}` : ch?.enabled ? "aktiv" : "aus"}
                    </span>
                  </span>
                </Link>
              </li>
            );
          })}
        </ul>
      </nav>
      <div className="min-w-0 lg:max-w-[60rem]">{children}</div>
    </div>
  );
}
