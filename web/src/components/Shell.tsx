"use client";

import { useEffect, useId, useRef, useState, ViewTransition } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useApi } from "@/lib/useApi";
import { CHANNELS } from "@/lib/channels";
import { useLiveState } from "@/lib/live";
import { useStoredFlag } from "@/lib/useStoredFlag";
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

/** Nur in der Icon-Rail (768–1023 px) ausgeblendet: Text bleibt für Screenreader erhalten. */
const RAIL_SR = "md:max-lg:sr-only";

function FeedStrip() {
  const { data } = useApi<Feed[]>("/feeds", 60_000);
  const s = feedSummary(data);
  if (!s) return null;
  return (
    <Link
      href="/cves#feeds"
      className="flex items-start gap-1.5 text-xs text-fg2 no-underline hover:text-fg md:max-lg:justify-center"
      title="Zustand der CVE-Feeds anzeigen"
    >
      <span className={s.ok ? "text-ok" : s.info.tone === "warn" ? "text-warn" : "text-unknown"}>
        <Icon name={s.info.icon} size={16} />
      </span>
      <span className={RAIL_SR}>{s.label}</span>
    </Link>
  );
}

function LiveIndicator() {
  const state = useLiveState();
  const text = state === "live" ? "Live" : state === "connecting" ? "Verbinde …" : "Getrennt, verbinde neu …";
  return (
    <p className="flex items-center gap-1.5 text-xs text-fg2 md:max-lg:justify-center" role="status" title={text}>
      <span aria-hidden="true" className={`inline-block size-2 rounded-full ${state === "live" ? "bg-ok" : "border border-fg3"}`} />
      <span className={RAIL_SR}>{text}</span>
    </p>
  );
}

/** Tooltip der Icon-Rail: sichtbar bei Hover und Tastaturfokus, der Name steht zusätzlich als sr-only-Text im Link. */
function RailTip({ children }: { children: React.ReactNode }) {
  return (
    <span
      aria-hidden="true"
      className="pointer-events-none absolute left-full top-1/2 z-(--z-overlay) ml-2 hidden -translate-y-1/2 whitespace-nowrap rounded-sm border border-line bg-surface px-2 py-1 text-xs font-normal text-fg opacity-0 shadow-(--shadow-float) transition-opacity duration-(--dur-1) ease-(--ease-out) group-focus-within/item:opacity-100 group-hover/item:opacity-100 md:max-lg:block"
    >
      {children}
    </span>
  );
}

const rowBase =
  "relative flex min-h-8 items-center gap-2.5 border-l-2 px-3 no-underline max-md:min-h-11 md:max-lg:justify-center md:max-lg:px-0";
const rowState = (active: boolean) => (active ? "border-accent bg-sunk font-semibold text-fg" : "border-transparent text-fg2 hover:bg-sunk hover:text-fg");

function NavLinks({ pathname }: { pathname: string }) {
  const subId = useId();
  // Auf-/Zu-Zustand der Gruppe bleibt über Seitenwechsel und Neuladen erhalten; auf Unterseiten ist sie immer offen.
  const [stored, setStored] = useStoredFlag("pw-nav:notifications");
  const onSub = pathname.startsWith("/notifications/");
  const expanded = onSub || stored === true;

  return (
    <nav aria-label="Hauptnavigation" className="flex flex-col gap-px">
      {NAV.map((n) => {
        const active = n.match(pathname);
        const exactNotifications = n.href === "/notifications" && pathname === "/notifications";
        const isGroup = n.href === "/notifications";
        return (
          <div key={n.href} className="group/item relative">
            <Link
              href={n.href}
              aria-current={exactNotifications || (active && !isGroup) ? "page" : undefined}
              className={`${rowBase} font-semibold ${rowState(active && !(isGroup && onSub))} ${isGroup ? "pr-10 md:max-lg:pr-0" : ""} ${isGroup && onSub ? "text-fg" : ""}`}
            >
              <NavIcon name={n.icon} />
              <span className={RAIL_SR}>{n.label}</span>
            </Link>
            <RailTip>{n.label}</RailTip>
            {isGroup ? (
              <>
                <button
                  type="button"
                  aria-expanded={expanded}
                  aria-controls={subId}
                  aria-label={`${n.label}: Kanäle ${expanded ? "ausblenden" : "einblenden"}`}
                  disabled={onSub}
                  onClick={() => setStored(!(stored === true))}
                  className="absolute right-0 top-0 inline-flex h-full min-w-9 items-center justify-center text-fg3 hover:text-fg disabled:cursor-default disabled:opacity-60 max-md:min-w-11 md:max-lg:hidden"
                >
                  <span className={`transition-transform duration-(--dur-2) ease-(--ease-out) ${expanded ? "rotate-180" : ""}`}>
                    <NavIcon name="chevron" />
                  </span>
                </button>
                {/* grid-template-rows 0fr -> 1fr: Höhe animiert ohne feste Maße; die Seitenleiste ist fixiert, der Inhalt springt nicht. */}
                <div
                  id={subId}
                  className={`grid transition-[grid-template-rows,opacity] duration-(--dur-2) ease-(--ease-out) md:max-lg:hidden ${
                    expanded ? "grid-rows-[1fr] opacity-100" : "grid-rows-[0fr] opacity-0"
                  }`}
                >
                  <ul inert={!expanded} className="flex min-h-0 flex-col gap-px overflow-hidden">
                    {CHANNELS.map((c) => {
                      const href = `/notifications/${c.kind}`;
                      const here = pathname === href;
                      return (
                        <li key={c.kind}>
                          <Link
                            href={href}
                            aria-current={here ? "page" : undefined}
                            className={`flex min-h-8 items-center border-l-2 py-1 pl-10 pr-3 no-underline max-md:min-h-11 ${rowState(here)}`}
                          >
                            {c.label}
                          </Link>
                        </li>
                      );
                    })}
                  </ul>
                </div>
              </>
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
    <div className="flex h-full flex-col gap-3 py-3">
      <Link href="/" className="flex min-h-8 items-center px-3 font-mono text-base font-medium text-fg no-underline max-md:min-h-11 max-md:pr-14 md:max-lg:justify-center md:max-lg:px-0">
        <span className={RAIL_SR}>patchwatch</span>
        <span aria-hidden="true" className="hidden md:max-lg:inline">
          pw
        </span>
      </Link>
      <div className="flex-1 overflow-y-auto md:max-lg:overflow-visible">
        <NavLinks pathname={pathname} />
      </div>
      <div className="flex flex-col gap-2 border-t border-line px-3 pt-3 md:max-lg:items-center md:max-lg:px-0">
        <FeedStrip />
        <LiveIndicator />
        <p className={`text-xs text-fg2 ${RAIL_SR}`}>
          <span className="sr-only">Angemeldet als </span>
          {me.username}
        </p>
        <Button onClick={() => void logout()} className="self-start md:max-lg:self-center md:max-lg:px-2" title="Abmelden">
          <span className="hidden md:max-lg:inline">
            <NavIcon name="logout" />
          </span>
          <span className={RAIL_SR}>Abmelden</span>
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
      {/* Ab 768 px: feste Seitenleiste (ab 1024 px 220 px, dazwischen Icon-Rail) */}
      <aside className="fixed inset-y-0 left-0 z-(--z-sidebar) hidden border-r border-line bg-surface md:block md:w-(--rail-w) lg:w-(--sidebar-w)">
        <SidebarBody pathname={pathname} />
      </aside>

      {/* Mobil: Kopfzeile mit Menü-Button und Off-Canvas */}
      <header className="sticky top-0 z-(--z-sidebar) flex h-(--topbar-h) items-center gap-3 border-b border-line bg-surface px-3 md:hidden">
        <button
          ref={menuBtn}
          type="button"
          aria-expanded={open}
          aria-controls="mobile-menu"
          onClick={() => setOpen(true)}
          className="inline-flex min-h-11 items-center gap-2 rounded-sm border border-control bg-surface px-3 font-semibold text-fg hover:bg-sunk"
        >
          <NavIcon name="menu" />
          Menü
        </button>
        <span className="font-semibold">{pageName(pathname)}</span>
      </header>
      {/* Off-Canvas bleibt gerendert und blendet per CSS ein/aus; geschlossen ist es inert und unsichtbar. */}
      <div
        inert={!open}
        className={`fixed inset-0 z-(--z-overlay) transition-[visibility] duration-(--dur-2) md:hidden ${open ? "visible" : "invisible"}`}
      >
        <button
          type="button"
          tabIndex={-1}
          aria-hidden="true"
          onClick={() => setOpen(false)}
          className={`absolute inset-0 bg-(--scrim) transition-opacity duration-(--dur-2) ease-(--ease-out) ${open ? "opacity-100" : "opacity-0"}`}
        />
        <div
          id="mobile-menu"
          ref={drawer}
          role="dialog"
          aria-modal="true"
          aria-label="Navigation"
          className={`absolute inset-y-0 left-0 w-[272px] max-w-[85vw] border-r border-line bg-surface shadow-(--shadow-float) transition-transform duration-(--dur-2) ease-(--ease-out) ${
            open ? "translate-x-0" : "-translate-x-full"
          }`}
        >
          <button
            type="button"
            onClick={() => setOpen(false)}
            className="absolute right-2 top-2 inline-flex min-h-11 min-w-11 items-center justify-center rounded-sm text-fg2 hover:bg-sunk hover:text-fg"
          >
            <NavIcon name="close" />
            <span className="sr-only">Menü schließen</span>
          </button>
          <SidebarBody pathname={pathname} />
        </div>
      </div>

      <main id="main" tabIndex={-1} className="md:pl-(--rail-w) lg:pl-(--sidebar-w)">
        {/* Volle Breite: Tabellen und Listen haben keine Maximalbreite, nur Formulare begrenzen sich selbst. */}
        <ViewTransition default="page">
          <div className="min-w-0 px-4 py-4 md:px-6 md:py-5">{children}</div>
        </ViewTransition>
      </main>
    </>
  );
}
