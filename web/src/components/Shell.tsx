"use client";

import { useEffect, useRef, useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useApi } from "@/lib/useApi";
import { CHANNELS } from "@/lib/channels";
import { useLiveState } from "@/lib/live";
import type { Feed } from "@/lib/types";
import { useAuth } from "./AuthProvider";
import { feedSummary } from "./FeedStatus";
import { Icon, NavIcon, type NavIconName } from "./Icons";
import { Button } from "./Controls";

interface Item {
  href: string;
  label: string;
  icon: NavIconName;
  /** Pfadpräfixe, bei denen der Eintrag aktiv ist. */
  match: (p: string) => boolean;
}

const NAV: Item[] = [
  { href: "/", label: "Hosts", icon: "hosts", match: (p) => p === "/" || p.startsWith("/hosts") },
  { href: "/cves", label: "CVEs", icon: "cves", match: (p) => p.startsWith("/cves") },
  { href: "/agents", label: "Agents", icon: "agents", match: (p) => p.startsWith("/agents") },
  { href: "/notifications", label: "Benachrichtigungen", icon: "bell", match: (p) => p.startsWith("/notifications") },
  { href: "/settings", label: "Einstellungen", icon: "settings", match: (p) => p.startsWith("/settings") },
];

function pageName(pathname: string): string {
  if (pathname.startsWith("/notifications/")) {
    const kind = pathname.split("/")[2];
    return CHANNELS.find((c) => c.kind === kind)?.label ?? "Benachrichtigungen";
  }
  return NAV.find((n) => n.match(pathname))?.label ?? "patchwatch";
}

function FeedStrip() {
  const { data } = useApi<Feed[]>("/feeds", 60_000);
  const s = feedSummary(data);
  if (!s) return null;
  return (
    <Link href="/cves#feeds" className="flex items-start gap-1.5 text-xs text-fg2 no-underline hover:text-fg" title="Zustand der CVE-Feeds anzeigen">
      <span className={s.ok ? "text-ok" : s.info.tone === "warn" ? "text-warn" : "text-unknown"}>
        <Icon name={s.info.icon} />
      </span>
      <span>{s.label}</span>
    </Link>
  );
}

function LiveIndicator() {
  const state = useLiveState();
  const text = state === "live" ? "Live" : state === "connecting" ? "Verbinde …" : "Getrennt, verbinde neu …";
  return (
    <p className="flex items-center gap-1.5 text-xs text-fg2" role="status">
      <span aria-hidden="true" className={`inline-block size-2 rounded-full ${state === "live" ? "bg-ok" : "border border-fg3"}`} />
      {text}
    </p>
  );
}

function NavLinks({ pathname }: { pathname: string }) {
  return (
    <nav aria-label="Hauptnavigation" className="flex flex-col gap-0.5">
      {NAV.map((n) => {
        const active = n.match(pathname);
        const exactNotifications = n.href === "/notifications" && pathname === "/notifications";
        return (
          <div key={n.href}>
            <Link
              href={n.href}
              aria-current={exactNotifications || (active && n.href !== "/notifications") ? "page" : undefined}
              className={`flex min-h-9 items-center gap-2.5 border-l-[3px] px-3 py-1.5 font-semibold no-underline max-[899px]:min-h-11 ${
                active ? "border-accent bg-accent-soft text-fg" : "border-transparent text-fg2 hover:bg-sunk hover:text-fg"
              }`}
            >
              <NavIcon name={n.icon} />
              {n.label}
            </Link>
            {n.href === "/notifications" && active ? (
              <ul className="mb-1 mt-0.5 flex flex-col gap-0.5">
                {CHANNELS.map((c) => {
                  const href = `/notifications/${c.kind}`;
                  const here = pathname === href;
                  return (
                    <li key={c.kind}>
                      <Link
                        href={href}
                        aria-current={here ? "page" : undefined}
                        className={`flex min-h-8 items-center border-l-[3px] py-1 pl-[2.6rem] pr-3 no-underline max-[899px]:min-h-11 ${
                          here ? "border-accent bg-accent-soft font-semibold text-fg" : "border-transparent text-fg2 hover:bg-sunk hover:text-fg"
                        }`}
                      >
                        {c.label}
                      </Link>
                    </li>
                  );
                })}
              </ul>
            ) : null}
          </div>
        );
      })}
    </nav>
  );
}

function SidebarBody({ pathname }: { pathname: string }) {
  const { me, logout } = useAuth();
  return (
    <div className="flex h-full flex-col gap-4 py-4">
      <Link href="/" className="flex min-h-8 items-center px-4 font-mono text-[15px] font-medium text-fg no-underline max-[899px]:min-h-11 max-[899px]:pr-14">
        patchwatch
      </Link>
      <div className="flex-1 overflow-y-auto">
        <NavLinks pathname={pathname} />
      </div>
      <div className="flex flex-col gap-2 border-t border-line px-4 pt-3">
        <FeedStrip />
        <LiveIndicator />
        <p className="text-xs text-fg2">
          <span className="sr-only">Angemeldet als </span>
          {me.username}
        </p>
        <Button onClick={() => void logout()} className="self-start">
          Abmelden
        </Button>
      </div>
    </div>
  );
}

const FOCUSABLE = 'a[href], button:not([disabled]), input, select, textarea, [tabindex]:not([tabindex="-1"])';

export function Shell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const [open, setOpen] = useState(false);
  const [prevPath, setPrevPath] = useState(pathname);
  const menuBtn = useRef<HTMLButtonElement>(null);
  const drawer = useRef<HTMLDivElement>(null);

  // Navigieren schließt das Menü.
  if (prevPath !== pathname) {
    setPrevPath(pathname);
    setOpen(false);
  }

  // Off-Canvas: Fokus hinein, Tab bleibt gefangen, Esc schließt, Fokus kehrt zurück.
  useEffect(() => {
    if (!open) return;
    const root = drawer.current;
    const btn = menuBtn.current;
    root?.querySelector<HTMLElement>(FOCUSABLE)?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        setOpen(false);
        return;
      }
      if (e.key !== "Tab" || !root) return;
      const els = [...root.querySelectorAll<HTMLElement>(FOCUSABLE)];
      const first = els[0];
      const last = els[els.length - 1];
      if (!first || !last) return;
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    };
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("keydown", onKey);
      btn?.focus();
    };
  }, [open]);

  return (
    <>
      {/* Desktop: feste Seitenleiste */}
      <aside className="fixed inset-y-0 left-0 z-20 hidden w-[232px] border-r border-line bg-surface min-[900px]:block">
        <SidebarBody pathname={pathname} />
      </aside>

      {/* Mobil: Kopfzeile mit Menü-Button und Off-Canvas */}
      <header className="sticky top-0 z-30 flex h-12 items-center gap-3 border-b border-line bg-surface px-3 min-[900px]:hidden">
        <button
          ref={menuBtn}
          type="button"
          aria-expanded={open}
          aria-controls="mobile-menu"
          onClick={() => setOpen(true)}
          className="inline-flex min-h-11 items-center gap-2 rounded-[3px] border border-control bg-surface px-3 font-semibold text-fg hover:bg-sunk"
        >
          <NavIcon name="menu" />
          Menü
        </button>
        <span className="font-semibold">{pageName(pathname)}</span>
      </header>
      {open ? (
        <div className="fixed inset-0 z-40 min-[900px]:hidden">
          <button type="button" tabIndex={-1} aria-hidden="true" onClick={() => setOpen(false)} className="absolute inset-0 bg-black/40" />
          <div id="mobile-menu" ref={drawer} role="dialog" aria-modal="true" aria-label="Navigation" className="absolute inset-y-0 left-0 w-[272px] max-w-[85vw] border-r border-line bg-bg">
            <button
              type="button"
              onClick={() => setOpen(false)}
              className="absolute right-2 top-2 inline-flex min-h-11 min-w-11 items-center justify-center rounded-[3px] text-fg2 hover:bg-sunk hover:text-fg"
            >
              <NavIcon name="close" />
              <span className="sr-only">Menü schließen</span>
            </button>
            <SidebarBody pathname={pathname} />
          </div>
        </div>
      ) : null}

      <main id="main" tabIndex={-1} className="min-[900px]:pl-[232px]">
        <div className="mx-auto max-w-[1440px] px-4 py-5 md:px-6">{children}</div>
      </main>
    </>
  );
}
