"use client";

import { useEffect, useId, useLayoutEffect, useRef, useState, type RefObject } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useApi } from "@/lib/useApi";
import { CHANNELS } from "@/lib/channels";
import { useLiveState } from "@/lib/live";
import { useStoredFlag } from "@/lib/useStoredFlag";
import type { Feed, ChannelView, Host, NotificationsResponse } from "@/lib/types";
import { HOST_STATUS } from "@/lib/status";
import { useLiveEvents } from "@/lib/live";
import { Avatar } from "./Avatar";
import { useAuth } from "./AuthProvider";
import { feedSummary } from "./FeedStatus";
import { Icon, Logo, NavIcon, type NavIconName } from "./Icons";

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

/** Zustand eines Kanals für die Seitenleiste: Symbol plus Text, nie nur Farbe. */
function channelState(ch: ChannelView | undefined): { icon: "ok" | "warn" | "pending"; tone: string; text: string } | null {
  if (!ch) return null;
  if (ch.last_error) return { icon: "warn", tone: "text-warn", text: `Fehler, ${ch.last_error}` };
  if (ch.enabled) return { icon: "ok", tone: "text-ok", text: "aktiv" };
  return { icon: "pending", tone: "text-fg3", text: "aus" };
}

/** Beschriftung: blendet beim Einklappen in 120 ms aus (bleibt für Screenreader und Tooltips erhalten). */
const LABEL = "min-w-0 flex-1 truncate transition-opacity duration-(--dur-1) ease-(--ease-out) motion-reduce:transition-none rail:opacity-0";
/** Symbolfläche: feste Breite, damit das Symbol in beiden Zuständen an derselben Stelle (Mitte der Rail) steht. */
const ICON = "grid size-5 shrink-0 place-items-center";
/**
 * Gemeinsames Zeilenraster der Seitenleiste (Navigation und Fußbereich): 36 px hoch (mobil 44 px), Symbolspalte 20 px,
 * Text beginnt in jeder Zeile am selben x. Die Fußzeilen teilen sich außerdem eine Schrift (13 px, Gewicht 500, gedämpft).
 */
const FOOT_TEXT = "text-[13px] font-medium leading-5 text-fg2";

function FeedStrip() {
  const { data } = useApi<Feed[]>("/feeds", 60_000);
  const s = feedSummary(data);
  if (!s) return null;
  return (
    <Link
      href="/cves#feeds"
      className={`${rowBase} ${FOOT_TEXT} hover:bg-sunk hover:text-fg`}
      title="Zustand der CVE-Feeds anzeigen"
    >
      <span className={`${ICON} ${s.ok ? "text-ok" : s.info.tone === "warn" ? "text-warn" : "text-unknown"}`}>
        <Icon name={s.info.icon} size={16} />
      </span>
      <span className={LABEL}>{s.label}</span>
    </Link>
  );
}

function LiveIndicator() {
  const state = useLiveState();
  const text = state === "live" ? "Live" : state === "connecting" ? "Verbinde …" : "Getrennt, verbinde neu …";
  return (
    <p className={`${rowBase} ${FOOT_TEXT}`} role="status" title={text}>
      <span className={ICON}>
        {/* Punkt in derselben 16-px-Fläche wie die Symbole, damit Zustandswechsel nichts verschieben. */}
        <span aria-hidden="true" className="grid size-4 place-items-center">
          <span className={`block size-2 rounded-full ${state === "live" ? "bg-ok" : "border border-fg3"}`} />
        </span>
      </span>
      <span className={LABEL}>{text}</span>
    </p>
  );
}

/** Tooltip der Icon-Rail: sichtbar bei Hover und Tastaturfokus, der Name steht zusätzlich als Text im Link. */
function RailTip({ children }: { children: React.ReactNode }) {
  return (
    <span
      aria-hidden="true"
      className="pointer-events-none absolute left-full top-1/2 z-(--z-overlay) ml-2 hidden -translate-y-1/2 whitespace-nowrap rounded-sm border border-line bg-surface px-2 py-1 text-xs font-normal text-fg opacity-0 shadow-(--shadow-float) transition-opacity duration-(--dur-1) ease-(--ease-out) group-focus-within/item:opacity-100 group-hover/item:opacity-100 rail:block"
    >
      {children}
    </span>
  );
}

/** Zählerplakette: bei breiter Leiste rechts in der Zeile, in der Rail als Punkt am Symbol. Der Text steht auch für Screenreader da. */
function Badge({ count, tone, what, corner }: { count: number; tone: "crit" | "warn"; what: string; corner?: boolean }) {
  if (count <= 0) return null;
  return (
    <span
      className={`pointer-events-none absolute rail:left-[24px] rail:right-auto rail:top-1 rail:translate-y-0 ${corner ? "left-[24px] top-1" : "right-3 top-1/2 -translate-y-1/2"}`}
    >
      <span
        aria-hidden="true"
        className={`inline-flex h-4 min-w-4 items-center justify-center rounded-full px-1 text-[11px] font-semibold leading-none text-surface ${tone === "crit" ? "bg-crit" : "bg-warn"}`}
      >
        {count > 99 ? "99+" : count}
      </span>
      <span className="sr-only">{`, ${count} ${what}`}</span>
    </span>
  );
}

const rowBase =
  "relative flex min-h-9 items-center gap-2.5 overflow-hidden whitespace-nowrap rounded-sm border-l-2 border-transparent px-2 no-underline max-md:min-h-11";
/** Der Hintergrund der aktiven Zeile ist die gleitende Fläche (GlideSurface), nicht die Zeile selbst. */
const rowState = (active: boolean) => (active ? "font-semibold text-fg" : "text-fg2 hover:bg-sunk hover:text-fg");

/**
 * Gleitende Fläche hinter der aktiven Zeile. Nur `transform` wird animiert (200 ms); Breite und Höhe folgen dem Layout ohne
 * Übergang. Neu gemessen wird beim Seitenwechsel (mit Übergang) und bei jeder Größenänderung der Leiste (ohne Übergang),
 * damit sie beim Einklappen und beim Aufklappen der Gruppe nicht hinterherhinkt.
 */
function placeSurface(n: HTMLElement, el: HTMLElement, animate: boolean) {
  const a = n.querySelector<HTMLElement>('a[aria-current="page"]');
  const nr = n.getBoundingClientRect();
  const ar = a?.getBoundingClientRect();
  if (!animate) el.style.transition = "none";
  if (!a || !ar || ar.width === 0 || nr.width === 0) {
    el.style.opacity = "0";
  } else {
    el.style.opacity = "1";
    el.style.width = `${ar.width}px`;
    el.style.height = `${ar.height}px`;
    el.style.transform = `translate(${ar.left - nr.left}px, ${ar.top - nr.top}px)`;
  }
  if (!animate) {
    // Stil jetzt ohne Übergang festschreiben (erzwungenes Layout), danach die Klassen-Übergänge wieder freigeben.
    void el.offsetWidth;
    el.style.transition = "";
  }
}

function useGlide(nav: RefObject<HTMLElement | null>, surface: RefObject<HTMLElement | null>, key: string) {
  const first = useRef(true);
  useLayoutEffect(() => {
    const n = nav.current;
    const el = surface.current;
    if (!n || !el) return;
    placeSurface(n, el, !first.current);
    first.current = false;
    // Der erste Aufruf des Beobachters kommt sofort nach observe() und würde das Gleiten abbrechen: überspringen.
    let initial = true;
    const ro = new ResizeObserver(() => {
      if (initial) {
        initial = false;
        return;
      }
      placeSurface(n, el, false);
    });
    ro.observe(n);
    return () => ro.disconnect();
  }, [nav, surface, key]);
}

function NavLinks({ pathname }: { pathname: string }) {
  const subId = useId();
  const nav = useRef<HTMLElement>(null);
  const surface = useRef<HTMLSpanElement>(null);
  // Auf-/Zu-Zustand der Gruppe bleibt über Seitenwechsel und Neuladen erhalten; ohne gespeicherte Wahl ist sie auf Unterseiten offen.
  const [stored, setStored] = useStoredFlag("pw-nav:notifications");
  const onSub = pathname.startsWith("/notifications/");
  const expanded = typeof stored === "boolean" ? stored : onSub;
  const channels = useApi<NotificationsResponse>("/notifications", 60_000).data?.channels;
  const hosts = useApi<Host[]>("/hosts", 60_000);
  useLiveEvents(["host_status", "report_received"], () => void hosts.reload());
  // Zähler: Hosts mit kritischem Stand (verwundbar / Sicherheitsupdates offen) und Kanäle mit Fehler.
  const critical = hosts.data?.filter((h) => HOST_STATUS[h.status]?.tone === "crit").length ?? 0;
  const failing = channels?.filter((c) => c.last_error).length ?? 0;
  useGlide(nav, surface, `${pathname}|${expanded}`);

  return (
    <nav ref={nav} aria-label="Hauptnavigation" className="relative isolate flex flex-col gap-0.5 px-2">
      <span
        ref={surface}
        aria-hidden="true"
        data-glide
        className="pointer-events-none absolute left-0 top-0 -z-10 rounded-sm border-l-2 border-accent bg-sunk opacity-0 transition-[transform,opacity] duration-(--glide-dur) ease-(--ease-out) motion-reduce:transition-none"
      />
      {NAV.map((n) => {
        const active = n.match(pathname);
        const exactNotifications = n.href === "/notifications" && pathname === "/notifications";
        const isGroup = n.href === "/notifications";
        return (
          <div key={n.href}>
            <div className="group/item relative">
              <Link
                href={n.href}
                aria-current={exactNotifications || (active && !isGroup) ? "page" : undefined}
                className={`${rowBase} font-semibold ${rowState(active && !(isGroup && onSub))} ${isGroup ? "pr-6 rail:pr-3" : ""} ${isGroup && onSub ? "text-fg" : ""}`}
              >
                <span className={ICON}>
                  <NavIcon name={n.icon} />
                </span>
                <span className={LABEL}>{n.label}</span>
              </Link>
              {n.href === "/" ? <Badge count={critical} tone="crit" what="Hosts mit kritischem Stand" /> : null}
              {isGroup ? <Badge count={failing} tone="warn" what="Kanäle mit Fehler" corner /> : null}
              <RailTip>{n.label}</RailTip>
              {isGroup ? (
                <button
                  type="button"
                  aria-expanded={expanded}
                  aria-controls={subId}
                  aria-label={`${n.label}: Kanäle ${expanded ? "ausblenden" : "einblenden"}`}
                  onClick={() => setStored(!expanded)}
                  className="absolute inset-y-0 right-0 inline-flex min-w-9 items-center justify-center rounded-r-sm text-fg3 hover:text-fg max-md:min-w-11 rail:hidden"
                >
                  <span className={`transition-transform duration-(--dur-2) ease-(--ease-out) ${expanded ? "rotate-180" : ""}`}>
                    <NavIcon name="chevron" />
                  </span>
                </button>
              ) : null}
            </div>
            {isGroup ? (
              <>
                {/* grid-template-rows 0fr -> 1fr: Höhe animiert ohne feste Maße; die Seitenleiste ist fixiert, der Inhalt springt nicht. */}
                <div
                  id={subId}
                  className={`grid transition-[grid-template-rows,opacity] duration-(--dur-2) ease-(--ease-out) rail:hidden ${
                    expanded ? "grid-rows-[1fr] opacity-100" : "grid-rows-[0fr] opacity-0"
                  }`}
                >
                  {/* Führungslinie unter dem Symbol der Gruppe verbindet die Kanäle optisch mit ihr. */}
                  <ul
                    inert={!expanded}
                    className="relative flex min-h-0 flex-col gap-px overflow-hidden before:absolute before:inset-y-1 before:left-[19px] before:w-px before:bg-line"
                  >
                    {CHANNELS.map((c) => {
                      const href = `/notifications/${c.kind}`;
                      const here = pathname === href;
                      const st = channelState(channels?.find((x) => x.kind === c.kind));
                      return (
                        <li key={c.kind}>
                          <Link
                            href={href}
                            aria-current={here ? "page" : undefined}
                            aria-label={st ? `${c.label}: ${st.text}` : undefined}
                            title={st ? `${c.label}: ${st.text}` : undefined}
                            className={`flex min-h-9 items-center gap-2 rounded-sm border-l-2 border-transparent py-1 pl-10 pr-3 no-underline max-md:min-h-11 ${rowState(here)}`}
                          >
                            <span className="min-w-0 flex-1 truncate">{c.label}</span>
                            {st ? (
                              <span aria-hidden="true" className={st.tone}>
                                <Icon name={st.icon} size={16} />
                              </span>
                            ) : null}
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

function SidebarBody({ pathname, collapse }: { pathname: string; collapse?: { collapsed: boolean; toggle: () => void } }) {
  const { me, logout } = useAuth();
  const expandBtn = useRef<HTMLButtonElement>(null);
  const hideBtn = useRef<HTMLButtonElement>(null);
  const moved = useRef(false);

  // Nach dem Umschalten bleibt der Fokus auf dem Bedienelement, das jetzt sichtbar ist (das andere ist ausgeblendet).
  useEffect(() => {
    if (!collapse || !moved.current) return;
    (collapse.collapsed ? expandBtn : hideBtn).current?.focus();
  }, [collapse, collapse?.collapsed]);
  const toggle = () => {
    moved.current = true;
    collapse?.toggle();
  };

  return (
    <div className="flex h-full flex-col">
      <div className="flex h-(--topbar-h) shrink-0 items-center border-b border-line">
        <Link
          href="/"
          className="flex h-full min-w-0 flex-1 items-center gap-2.5 overflow-hidden whitespace-nowrap pl-[18px] font-mono text-base font-medium text-fg no-underline max-md:pr-14 sbc:hidden"
        >
          <Logo />
          <span className={LABEL}>patchwatch</span>
        </Link>
        {/* Eingeklappt (ab 1024 px) ist das Logo die Schaltfläche zum Einblenden. */}
        {collapse ? (
          <div className="group/item relative hidden h-full flex-1 sbc:block">
            <button
              ref={expandBtn}
              type="button"
              onClick={toggle}
              aria-expanded={false}
              aria-controls="sidebar"
              className="flex h-full w-full items-center pl-[18px] text-fg hover:bg-sunk"
            >
              <Logo />
              <span className="sr-only">Seitenleiste einblenden</span>
            </button>
            <RailTip>Seitenleiste einblenden</RailTip>
          </div>
        ) : null}
        {collapse ? (
          <button
            ref={hideBtn}
            type="button"
            onClick={toggle}
            aria-expanded={true}
            aria-controls="sidebar"
            className="mr-2 hidden size-9 shrink-0 items-center justify-center rounded-sm text-fg3 hover:bg-sunk hover:text-fg lg:inline-flex rail:hidden"
          >
            <NavIcon name="collapse" />
            <span className="sr-only">Seitenleiste ausblenden</span>
          </button>
        ) : null}
      </div>
      <div className="flex-1 overflow-y-auto py-3 rail:overflow-visible">
        <NavLinks pathname={pathname} />
      </div>
      <div className="border-t border-line px-2 py-3">
        {/* Gruppe 1: Zustand (Feeds, Live); Gruppe 2: Benutzer und Abmelden, getrennt durch eine feine Linie. */}
        <div className="flex flex-col gap-0.5">
          <FeedStrip />
          <LiveIndicator />
        </div>
        <div role="separator" className="mx-2 my-2 h-px bg-line" />
        <div className="flex flex-col gap-0.5">
          <div className="group/item relative">
            <div className={`${rowBase} ${FOOT_TEXT}`} title={me.username}>
              <span className={ICON}>
                <Avatar name={me.username} version={me.avatar} size={20} />
              </span>
              <p className={LABEL}>
                <span className="sr-only">Angemeldet als </span>
                {me.username}
              </p>
            </div>
            <RailTip>{me.username}</RailTip>
          </div>
          <div className="group/item relative">
            <button type="button" onClick={() => void logout()} className={`${rowBase} ${FOOT_TEXT} w-full cursor-pointer text-left hover:bg-sunk hover:text-fg`}>
              <span className={ICON}>
                <NavIcon name="logout" />
              </span>
              <span className={LABEL}>Abmelden</span>
            </button>
            <RailTip>Abmelden</RailTip>
          </div>
        </div>
      </div>
    </div>
  );
}

const FOCUSABLE = 'a[href], button:not([disabled]), input, select, textarea, [tabindex]:not([tabindex="-1"])';

export function Shell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const [open, setOpen] = useState(false);
  const [prevPath, setPrevPath] = useState(pathname);
  // Eingeklappt (ab 1024 px): in localStorage gemerkt; das Skript im <head> setzt html[data-sb] schon vor dem ersten Bild.
  const [stored, setStored] = useStoredFlag("pw-nav:collapsed");
  const collapsed = stored === true;
  const setCollapsed = (v: boolean) => {
    if (v) document.documentElement.setAttribute("data-sb", "collapsed");
    else document.documentElement.removeAttribute("data-sb");
    setStored(v);
  };
  useEffect(() => {
    // Zustand aus einem anderen Tab übernehmen.
    if (collapsed) document.documentElement.setAttribute("data-sb", "collapsed");
    else document.documentElement.removeAttribute("data-sb");
  }, [collapsed]);
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
    // Der Fokus gelingt erst, wenn das Menü sichtbar ist: Im Moment des Öffnens steht `visibility` noch am Anfang seines
    // Übergangs (hidden), und focus() scheitert dann stillschweigend. Darum bis zu 10 Frames lang erneut versuchen.
    let raf = 0;
    let tries = 0;
    const focusFirst = () => {
      root?.querySelector<HTMLElement>(FOCUSABLE)?.focus();
      if (root && !root.contains(document.activeElement) && ++tries < 10) raf = requestAnimationFrame(focusFirst);
    };
    raf = requestAnimationFrame(focusFirst);
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
      cancelAnimationFrame(raf);
      document.removeEventListener("keydown", onKey);
      btn?.focus();
    };
  }, [open]);

  return (
    <>
      {/* Ab 768 px: feste Seitenleiste (ab 1024 px 220 px oder eingeklappt, dazwischen Icon-Rail). Die Breite animiert in 240 ms. */}
      <aside
        id="sidebar"
        className="fixed inset-y-0 left-0 z-(--z-sidebar) hidden border-r border-line bg-surface transition-[width] duration-(--sb-dur) ease-(--ease-out) motion-reduce:transition-none md:block md:w-(--rail-w) lg:w-(--sb-w)"
      >
        <SidebarBody pathname={pathname} collapse={{ collapsed, toggle: () => setCollapsed(!collapsed) }} />
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

      <main id="main" tabIndex={-1} inert={open} className="transition-[padding-left] duration-(--sb-dur) ease-(--ease-out) motion-reduce:transition-none md:pl-(--rail-w) lg:pl-(--sb-w)">
        {/* Volle Breite: Tabellen und Listen haben keine Maximalbreite, nur Formulare begrenzen sich selbst. */}
        {/* Seitenwechsel: neuer Inhalt ist sofort da und blendet in 150 ms ein (nur Opacity). Eine View Transition
            hielt die Aktualisierung bis zum Schnappschuss zurück und kostete 50-100 ms je Klick (docs/perf.md). */}
        <div key={pathname} className="page-in min-w-0 px-4 py-4 md:px-6 md:py-5">
          {children}
        </div>
      </main>
    </>
  );
}
