"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useApi } from "@/lib/useApi";
import type { Feed } from "@/lib/types";
import { useAuth } from "./AuthProvider";
import { feedSummary } from "./FeedStatus";
import { StatusBadge } from "./StatusBadge";
import { ThemeSelect } from "./ThemeSelect";
import { Button } from "./Controls";

const NAV = [
  { href: "/", label: "Hosts" },
  { href: "/cves", label: "CVEs" },
  { href: "/settings", label: "Einstellungen" },
] as const;

function FeedStrip() {
  const { data } = useApi<Feed[]>("/feeds", 60_000);
  const s = feedSummary(data);
  if (!s) return null;
  return (
    <Link href="/cves#feeds" className="no-underline" title="Zustand der CVE-Feeds anzeigen">
      <StatusBadge info={s.info} label={s.label} />
    </Link>
  );
}

export function Shell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const { me, logout } = useAuth();
  const current = (href: string) => (href === "/" ? pathname === "/" || pathname.startsWith("/hosts") : pathname.startsWith(href));

  return (
    <>
      <header className="border-b border-line bg-surface">
        <div className="mx-auto flex max-w-[1440px] flex-wrap items-center gap-x-6 gap-y-2 px-4 py-2 md:px-6">
          <Link href="/" className="font-mono text-[15px] font-medium text-fg no-underline">
            patchwatch
          </Link>
          <nav aria-label="Hauptnavigation" className="-mx-1 flex min-w-0 flex-1 items-center gap-1 overflow-x-auto">
            {NAV.slice(0, 2).map((n) => (
              <NavLink key={n.href} href={n.href} active={current(n.href)}>
                {n.label}
              </NavLink>
            ))}
            {/* Platz für die spätere Matrix-Ansicht: sichtbar, aber nicht anklickbar. */}
            <span aria-disabled="true" className="flex items-center gap-1.5 whitespace-nowrap px-2 py-1.5 text-fg3">
              Matrix
              <span className="rounded-[2px] border border-line px-1 text-[11px] leading-4">bald</span>
            </span>
            <NavLink href="/settings" active={current("/settings")}>
              Einstellungen
            </NavLink>
          </nav>
          <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
            <FeedStrip />
            <ThemeSelect />
            <span className="text-[12px] text-fg2">
              <span className="sr-only">Angemeldet als </span>
              {me.username}
            </span>
            <Button onClick={() => void logout()}>Abmelden</Button>
          </div>
        </div>
      </header>
      <main id="main" tabIndex={-1} className="mx-auto max-w-[1440px] px-4 py-5 md:px-6">
        {children}
      </main>
    </>
  );
}

function NavLink({ href, active, children }: { href: string; active: boolean; children: React.ReactNode }) {
  return (
    <Link
      href={href}
      aria-current={active ? "page" : undefined}
      className={`whitespace-nowrap border-b-2 px-2 py-1.5 font-semibold no-underline max-md:py-3 ${
        active ? "border-accent text-fg" : "border-transparent text-fg2 hover:text-fg"
      }`}
    >
      {children}
    </Link>
  );
}
