"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import Link from "next/link";
import { api } from "@/lib/api";
import { prefetchApi, useApi } from "@/lib/useApi";
import { absTime } from "@/lib/format";
import { CVE_STATUS, type IconName } from "@/lib/status";
import { LEVEL_FILTERS, announcedText, barSegments, fixInfo, groupTitle, kernelLine, levelWord, openStatusWord, parseCveFilter, shortText, stateCounts, summarySentence, type FeedNotice, type Tile } from "@/lib/hostCves";
import type { CveStatus, Host, HostCve, HostCveGroupsResponse, HostCvesResponse, UpdateItem } from "@/lib/types";
import { Marker } from "@/components/DistroChip";
import { StatusBadge } from "@/components/StatusBadge";
import { Dialog } from "@/components/Dialog";
import { Mono } from "@/components/Version";
import { ErrorNote } from "@/components/States";
import { Linkified } from "@/components/Linkified";
import { Icon, NavIcon } from "@/components/Icons";
import { CodeField } from "@/components/CopyButton";

const LIVE = ["report_received", "host_status", "host_cve_status"] as const;
const ROW_H = 32; // dichte Zeilen (DESIGN.md): 32 px bei 16 px Schrift
const ROW_H_TOUCH = 64; // schmal (unter 768 px oder Liste unter 40 rem): zweizeilig
const NARROW_REM = 40; // dieselbe Grenze wie die gestapelten Tabellen (globals.css, Variante stacked)
const PAGE = 200;
const GROUP_PAGE = 1000; // Obergrenze der API je Anfrage
const VIRTUAL_FROM = 60; // ab dieser Zeilenzahl wird nur der sichtbare Ausschnitt gerendert
/** Weg zum Fix (nur Anzeige, es wird nichts ausgeführt). */
const UPDATE_CMD = "sudo apt update && sudo apt upgrade";
const UPDATE_HINT = `Fix im Archiv. Update einspielen: ${UPDATE_CMD}, danach Neustart, falls ein Kernel betroffen ist.`;
const PROXMOX_ADVISORIES = "https://forum.proxmox.com/forums/security-advisories.26/";

/** Kacheln der Kopfzeile; jede gehört zu genau einer Liste. */
export type CveFilter = Tile;
const TILE_STATUS: Record<Tile, string> = {
  open: "vulnerable,fix_pending",
  reboot: "fixed_installed_reboot_required",
  fixed: "fixed",
  unknown: "unknown",
};
export { parseCveFilter };

/**
 * Zeilenmaße einer Liste. Schmal (gestapelte Zeile) unter 768 px Fensterbreite oder wenn die Liste schmaler als 40 rem ist:
 * Media-Queries rechnen in px, bei vergrößerter Schrift (200 % bei 1280 px) passt das feste rem-Raster der breiten Zeile
 * sonst nicht. Die Zeilenhöhe wächst mit der Schrift (bei 16 px 32 bzw. 64 px). `el` ist der Behälter der Liste; beobachtet
 * werden Breite und Höhe (die Höhe ändert sich auch, wenn nur die Schrift wächst).
 */
function useRows(el: HTMLElement | null): { narrow: boolean; rowH: number } {
  const [rows, setRows] = useState({ narrow: false, rowH: ROW_H });
  useEffect(() => {
    const m = window.matchMedia("(max-width: 767px)");
    const on = () => {
      const rem = parseFloat(getComputedStyle(document.documentElement).fontSize) || 16;
      const narrow = m.matches || (el !== null && el.clientWidth < NARROW_REM * rem);
      const rowH = Math.round(((narrow ? ROW_H_TOUCH : ROW_H) * rem) / 16);
      setRows((r) => (r.narrow === narrow && r.rowH === rowH ? r : { narrow, rowH }));
    };
    on();
    m.addEventListener("change", on);
    const ro = el && typeof ResizeObserver !== "undefined" ? new ResizeObserver(on) : null;
    if (el) ro?.observe(el);
    return () => {
      m.removeEventListener("change", on);
      ro?.disconnect();
    };
  }, [el]);
  return rows;
}

function useDebounced<T>(v: T, ms: number): T {
  const [d, setD] = useState(v);
  useEffect(() => {
    const t = setTimeout(() => setD(v), ms);
    return () => clearTimeout(t);
  }, [v, ms]);
  return d;
}

/** Eine Zeile: was gilt, in Worten (Fix-Version und Zustand des Hosts). */
export function hostState(c: HostCve, running: string | null, proxmox: boolean): string {
  const run = running ?? "unbekannt";
  switch (c.status) {
    case "fixed":
      return c.fix_version ? `Fix ab ${c.fix_version}, läuft ${run}` : `Behoben, läuft ${run}`;
    case "fixed_installed_reboot_required":
      return `Fix installiert, Kernel läuft noch ${run}, Neustart nötig`;
    case "vulnerable": {
      const f = fixInfo(c);
      if (f.kind === "announced") return `Fix angekündigt${f.version ? ` (voraussichtlich in ${f.version})` : ""}, läuft ${run}`;
      return f.version ? `Fix ab ${f.version}, läuft ${run}` : `Kein Fix bekannt, läuft ${run}`;
    }
    case "fix_pending":
      return c.fix_version ? `Fix angekündigt ab ${c.fix_version}, läuft ${run}` : `Fix angekündigt, läuft ${run}`;
    default:
      return proxmox ? "Keine belastbare Quelle, manuell prüfen" : "Quelle liefert keine Aussage";
  }
}

const dateFmt = new Intl.DateTimeFormat("de-DE", { day: "2-digit", month: "2-digit", year: "numeric", timeZone: "Europe/Berlin" });
const since = (iso: string | null) => (iso ? dateFmt.format(new Date(iso)) : "–");

const TILE_META: Record<Tile, { word: string; icon: IconName; tone: "crit" | "warn" | "ok" | "grey" | "unknown"; line: (kernel: string | null) => React.ReactNode }> = {
  open: { word: "Offen", icon: "crit", tone: "crit", line: () => "Kein Fix installiert" },
  reboot: { word: "Neustart nötig", icon: "reboot", tone: "warn", line: (k) => (k ? <>Fix installiert, läuft erst nach Neustart auf <span className="whitespace-nowrap">{k}</span></> : "Fix installiert, läuft erst nach Neustart") },
  fixed: { word: "Gefixt", icon: "ok", tone: "ok", line: () => "Läuft bereits mit Fix" },
  unknown: { word: "Unbekannt", icon: "unknown", tone: "unknown", line: () => "Quelle liefert keine Aussage" },
};
const TONE_BORDER = { crit: "border-crit", warn: "border-warn", ok: "border-ok", grey: "border-fg3", unknown: "border-unknown" } as const;
const TONE_TEXT = { crit: "text-crit", warn: "text-warn", ok: "text-ok", grey: "text-fg2", unknown: "text-unknown" } as const;
const TONE_BG = { crit: "bg-crit", warn: "bg-warn", ok: "bg-ok", grey: "bg-fg3", unknown: "bg-unknown" } as const;

export function HostCves({ host, initialFilter, notice, details }: { host: Host; initialFilter: CveFilter | null; notice: FeedNotice; details?: React.ReactNode }) {
  // Proxmox: es gibt nur "unbekannt, manuell prüfen"; diese Einträge stehen sofort im Blick (nie grün, kein Alarm).
  const [tile, setTile] = useState<Tile>(initialFilter ?? (host.is_proxmox ? "unknown" : "open"));
  const [text, setText] = useState("");
  const q = useDebounced(text.trim(), 250);
  const [levelMin, setLevelMin] = useState(0);
  const [limit, setLimit] = useState(PAGE);
  const [showAllFixed, setShowAllFixed] = useState(false);
  const [detail, setDetail] = useState<HostCve | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [compact, setCompact] = useState(false);
  const sentinel = useRef<HTMLDivElement>(null);

  // Kompakte Leiste erst, wenn die große Kopfzeile aus dem Bild gescrollt ist.
  useEffect(() => {
    const el = sentinel.current;
    if (!el || typeof IntersectionObserver === "undefined") return;
    const io = new IntersectionObserver(([e]) => setCompact(!e!.isIntersecting && e!.boundingClientRect.top < 0));
    io.observe(el);
    return () => io.disconnect();
  }, []);

  const grouped = tile === "reboot" || tile === "fixed";
  const lvl = levelMin > 0 ? `&level_min=${levelMin}` : "";
  const qs = q ? `&q=${encodeURIComponent(q)}` : "";
  const base = `/hosts/${host.id}/cves`;
  // Zähler, Host und Hinweis kommen aus einer eigenen kleinen Anfrage und bleiben beim Kachelwechsel stehen.
  const head = useApi<HostCvesResponse>(`${base}?limit=1`, 60_000, LIVE, undefined, { keepPrevious: true });
  const listPath = grouped ? null : `${base}?status=${TILE_STATUS[tile]}${tile === "open" ? "&sort=level&dir=desc" : ""}&limit=${limit}${qs}${lvl}`;
  const groupsPath = grouped ? `${base}/groups?kind=${tile}${qs}${lvl}` : null;
  const list = useApi<HostCvesResponse>(listPath, 60_000, LIVE, undefined, { keepPrevious: true });
  const groups = useApi<HostCveGroupsResponse>(groupsPath, 60_000, LIVE, undefined, { keepPrevious: true });

  const counts = head.data?.counts;
  const issue = head.data?.issue ?? host.cve_source_issue ?? null;
  const running = head.data?.host.running_kernel_version ?? head.data?.host.running_kernel ?? host.kernel_package_version ?? host.running_kernel;
  const newest = head.data?.host.newest_kernel_version ?? host.newest_kernel_version;
  const rebootNeeded = head.data?.host.reboot_needed ?? host.reboot_needed;
  const sc = counts ? stateCounts(counts) : null;
  const numbers: Record<Tile, number> = sc ? { open: sc.open, reboot: sc.reboot, fixed: sc.fixed, unknown: sc.unknown } : { open: 0, reboot: 0, fixed: 0, unknown: 0 };

  async function reloadAll() {
    await Promise.all([head.reload(), list.reload(), groups.reload()]);
  }

  async function toggleReview(c: HostCve, checked: boolean) {
    setBusy(c.cve_id);
    try {
      const path = `/hosts/${host.id}/cves/${c.cve_id}/review`;
      const what = "Prüfmarkierung konnte nicht gespeichert werden";
      if (checked) await api.put(path, undefined, { what });
      else await api.del(path, { what });
      await reloadAll();
      setDetail((d) => (d && d.cve_id === c.cve_id ? { ...d, reviewed_at: checked ? new Date().toISOString() : null, reviewed_by: checked ? d.reviewed_by : null } : d));
    } catch {
      /* Der API-Client hat den Fehler als Toast gemeldet. */
    } finally {
      setBusy(null);
    }
  }

  function pick(t: Tile) {
    setTile(t);
    setLimit(PAGE);
    setShowAllFixed(false);
  }

  const sentence = sc ? summarySentence(sc, { newest, proxmox: host.is_proxmox, restricted: notice.restricted }) : "CVE-Lage wird geladen …";
  const segments = sc ? barSegments(sc) : [];
  // Vier gleichwertige Kacheln; „Unbekannt“ bleibt auch bei 0 sichtbar (dann gedämpft), damit das Raster stabil ist.
  const bigTiles: Tile[] = ["open", "reboot", "fixed", "unknown"];

  return (
    <section aria-labelledby="cve" className="mb-6">
      <h2 id="cve" className="sr-only">
        CVE-Lage für den laufenden Kernel
      </h2>
      {host.is_proxmox ? (
        <p role="note" className="mb-2 border-l-4 border-unknown bg-unknown-soft px-3 py-1.5 text-unknown">
          <strong className="font-semibold">Proxmox-Kernel:</strong> Für -pve-Kernel gibt es keine belastbare CVE-Quelle. Jede Bewertung ist unbekannt und muss
          manuell geprüft werden:{" "}
          <a href={PROXMOX_ADVISORIES} target="_blank" rel="noopener noreferrer">
            Proxmox Security Advisories
          </a>
          . Eine Prüfung („geprüft am“) gilt nur für den Kernel, bei dem sie gesetzt wurde.
        </p>
      ) : null}
      {notice.text ? (
        <p role="note" className="mb-2 flex items-start gap-2 border-l-4 border-warn bg-warn-soft px-3 py-1.5 text-warn">
          <span className="mt-0.5 shrink-0">
            <Icon name="warn" />
          </span>
          <span>
            {notice.text} <Link href="/cves#feeds">Zur Quellen-Tabelle</Link>
          </span>
        </p>
      ) : issue && !notice.restricted ? (
        <p role="note" className="mb-2 border-l-4 border-unknown bg-unknown-soft px-3 py-1.5 text-unknown">
          <strong className="font-semibold">Bewertung eingeschränkt:</strong> {issue}. <Link href="/cves#feeds">Zur Quellen-Tabelle</Link>
        </p>
      ) : null}
      {head.error && !head.data ? <ErrorNote message={head.error} /> : null}

      {/* Entscheidungshilfe: ein Satz, gestapelter Balken, vier große Kacheln (je eine Liste), Unbekannt klein. */}
      <p className="mb-1.5 text-base font-semibold" aria-live="polite">
        {sentence}
      </p>
      <div
        role="img"
        aria-label={sc ? `Verteilung: ${numbers.open} offen, ${numbers.reboot} Neustart nötig, ${numbers.fixed} gefixt, ${numbers.unknown} unbekannt` : "Verteilung wird geladen"}
        className="mb-3 flex h-2.5 w-full overflow-hidden rounded-xs bg-sunk"
      >
        {segments.map((sg) => (
          <span key={sg.tile} style={{ width: `${sg.pct}%` }} className={`${TONE_BG[TILE_META[sg.tile].tone]} ${sg.tile === "unknown" ? "opacity-60" : ""}`} title={`${TILE_META[sg.tile].word}: ${sg.count}`} />
        ))}
      </div>
      {/* Feste Spaltenzahl je Breite (auto-fit ergäbe bei 768–1279 px drei Spalten statt 2x2); Mindestbreite 200 px, wo sie passt. Mit der 20-rem-Spalte rechts (ab 1280 px, Variante side) sind die Kacheln nur 161–200 px breit: dort minmax(0,1fr), sonst liefe das Raster über. */}
      <div className="mb-2 grid grid-cols-[minmax(200px,1fr)] gap-2 min-[640px]:grid-cols-[repeat(2,minmax(200px,1fr))] side:grid-cols-[repeat(auto-fit,minmax(min(100%,9rem),1fr))]" role="group" aria-label="CVE-Zustände">
        {bigTiles.map((t) => (
          <TileButton
            key={t}
            t={t}
            n={numbers[t]}
            active={tile === t}
            loaded={Boolean(sc)}
            onPick={pick}
            line={TILE_META[t].line(newest)}
            sub={t === "open" ? openSub(head.data?.open_with_fix ?? 0, notice.restricted) : null}
            warn={t === "open" && notice.restricted}
          />
        ))}
      </div>
      <div className="mb-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-fg2">
        <span className="inline-flex flex-wrap items-center gap-x-2 gap-y-1">
          <span>{kernelLine(running ?? null, newest ?? null, Boolean(rebootNeeded))}</span>
        </span>
      </div>
      {details}
      <div ref={sentinel} aria-hidden="true" className="h-px" />

      {/* Verkürzte Leiste: erscheint erst beim Scrollen und nimmt keinen Platz ein (keine Layoutsprünge). */}
      <div className="sticky top-(--topbar-h) z-10 h-0 md:top-0">
        <div
          inert={!compact}
          aria-hidden={!compact}
          className={`absolute inset-x-0 top-0 flex flex-wrap items-center gap-1.5 border-b border-line bg-bg px-1 py-1 shadow-sm ${compact ? "" : "invisible"}`}
          role="group"
          aria-label="Zusammenfassung"
        >
          {(["open", "reboot", "fixed", "unknown"] as Tile[]).map((t) => (
            <button
              key={t}
              type="button"
              aria-pressed={tile === t}
              onClick={() => pick(t)}
              className={`inline-flex h-6 items-center gap-1 rounded-xs border px-1.5 text-xs font-medium max-md:h-11 max-md:px-3 max-md:text-sm ${tile === t ? `border-2 ${TONE_BORDER[TILE_META[t].tone]} bg-sunk` : "border-line bg-surface hover:bg-sunk"}`}
            >
              <span className={TONE_TEXT[TILE_META[t].tone]}>
                <Icon name={t === "open" && notice.restricted ? "warn" : TILE_META[t].icon} size={14} />
              </span>
              {TILE_META[t].word} <span className="tabular-nums font-semibold">{sc ? numbers[t] : "…"}</span>
              {tile === t ? <Icon name="ok" size={14} /> : null}
            </button>
          ))}
        </div>
      </div>

      <div className="mb-2 flex flex-wrap items-center gap-2">
        {/* max-w-full: Das Feld ist 16 rem breit; ohne Grenze am Label wäre max-w-full am Feld wirkungslos (Label wächst mit). */}
        <label className="flex max-w-full items-center gap-2 text-xs text-fg2">
          <span className="sr-only">CVEs dieses Hosts durchsuchen</span>
          <input
            type="search"
            value={text}
            onChange={(e) => setText(e.target.value)}
            placeholder="CVE-ID oder Text suchen"
            aria-label="CVEs dieses Hosts durchsuchen"
            className="min-h-8 w-64 max-w-full rounded-[3px] border border-control bg-sunk px-2 py-1 text-sm text-fg placeholder:text-fg3 max-md:min-h-11"
          />
        </label>
        <div role="group" aria-label="Level-Filter" className="flex flex-wrap gap-1">
          {LEVEL_FILTERS.map((f) => (
            <button
              key={f.min}
              type="button"
              aria-pressed={levelMin === f.min}
              onClick={() => setLevelMin(f.min)}
              className={`min-h-8 rounded-xs border px-2 text-xs font-medium max-md:min-h-11 max-md:px-3 ${levelMin === f.min ? "border-accent bg-accent text-bg" : "border-line bg-sunk text-fg hover:bg-surface"}`}
            >
              {f.label}
            </button>
          ))}
        </div>
        {tile === "fixed" && (groups.data?.groups.length ?? 0) > 1 ? (
          <button type="button" className="ml-auto text-xs underline max-md:min-h-11 max-md:min-w-11" onClick={() => setShowAllFixed((v) => !v)}>
            {showAllFixed ? "Alle zuklappen" : "Alle anzeigen"}
          </button>
        ) : null}
      </div>

      <div key={tile} className="tab-fade">
        {grouped ? (
          <>
            {tile === "reboot" ? (
              <p role="note" className="mb-2 flex items-center gap-2 text-sm text-fg2">
                <span className="text-warn">
                  <Icon name="reboot" size={14} />
                </span>
                Ein Neustart behebt alle diese CVEs.
              </p>
            ) : null}
            <GroupedList
              kind={tile}
              hostId={host.id}
              state={groups}
              q={q}
              lvl={lvl}
              expandAll={showAllFixed}
              proxmox={host.is_proxmox}
              onOpen={setDetail}
              empty={tile === "reboot" ? "Kein Neustart nötig: kein Fix wartet auf einen Neustart." : "Noch keine gefixten CVEs gespeichert."}
            />
          </>
        ) : (
          <CveList
            title={TILE_META[tile].word}
            state={list}
            proxmox={host.is_proxmox}
            variant={tile === "open" ? "open" : "plain"}
            onOpen={setDetail}
            onMore={() => setLimit((l) => l + PAGE)}
            expected={sc ? numbers[tile] : null}
            empty={tile === "open" ? (notice.restricted ? "Keine offenen CVEs bekannt, aber die Quelle ist unvollständig." : "Keine offenen CVEs. Für den laufenden Kernel ist keine CVE ohne installierten Fix bekannt.") : host.is_proxmox ? "Setze CVEs auf die Watchlist, dann erscheinen sie hier als „manuell prüfen“." : "Keine Einträge für diese Auswahl."}
          />
        )}
      </div>

      <Dialog open={detail !== null} title={detail?.cve_id ?? "CVE"} onClose={() => setDetail(null)}>
        {detail ? <Detail c={detail} host={host} running={running ?? null} busy={busy === detail.cve_id} onReview={(v) => void toggleReview(detail, v)} /> : null}
      </Dialog>
    </section>
  );
}

function openSub(withFix: number, restricted: boolean): string {
  const base = withFix > 0 ? `${withFix} davon mit Fix im Archiv` : "Fix noch nicht verfügbar";
  return restricted ? `${base} · kann unvollständig sein` : base;
}

function TileButton({ t, n, active, loaded, onPick, line, sub, warn }: { t: Tile; n: number; active: boolean; loaded: boolean; onPick: (t: Tile) => void; line: React.ReactNode; sub: string | null; warn: boolean }) {
  const m = TILE_META[t];
  return (
    <button
      type="button"
      aria-pressed={active}
      onClick={() => onPick(t)}
      className={`flex min-w-0 flex-col gap-0.5 rounded-xs border bg-surface px-3 py-2 text-left hover:bg-sunk max-md:min-h-11 ${active ? `border-2 ${TONE_BORDER[m.tone]} bg-sunk` : "border-line"}`}
    >
      <span className={`flex flex-wrap items-center gap-x-1.5 text-sm font-semibold ${TONE_TEXT[m.tone]}`}>
        <Icon name={warn ? "warn" : m.icon} size={16} />
        {m.word}
        {active ? (
          <span className="ml-auto inline-flex items-center gap-0.5 text-xs font-medium text-fg2">
            <Icon name="ok" size={14} /> Angezeigt
          </span>
        ) : null}
      </span>
      <span className={`text-2xl font-semibold leading-none tabular-nums ${loaded && n === 0 && !active ? "text-fg3" : "text-fg"}`}>{loaded ? n.toLocaleString("de-DE") : "…"}</span>
      <span className="text-xs text-fg2">{line}</span>
      {sub ? (
        <span className="text-xs text-fg3" title={t === "open" && /Fix im Archiv/.test(sub) ? UPDATE_HINT : undefined}>
          {sub}
        </span>
      ) : null}
    </button>
  );
}

/** Virtualisierte, dichte Zeilenliste mit fester Höhe und eigener Bildlaufleiste. */
function VirtualRows({ items, rowH, height, label, render }: { items: HostCve[]; rowH: number; height?: string; label: string; render: (c: HostCve, style: React.CSSProperties | undefined) => React.ReactNode }) {
  const scroller = useRef<HTMLDivElement>(null);
  const [scroll, setScroll] = useState(0);
  const [viewH, setViewH] = useState(480);
  useEffect(() => {
    const el = scroller.current;
    if (!el) return;
    const ro = new ResizeObserver(() => setViewH(el.clientHeight));
    ro.observe(el);
    setViewH(el.clientHeight);
    return () => ro.disconnect();
  }, []);
  const virtual = items.length > VIRTUAL_FROM;
  const first = virtual ? Math.max(0, Math.floor(scroll / rowH) - 8) : 0;
  const last = virtual ? Math.min(items.length, Math.ceil((scroll + viewH) / rowH) + 8) : items.length;
  return (
    <div ref={scroller} onScroll={(e) => setScroll(e.currentTarget.scrollTop)} tabIndex={0} role="region" aria-label={label} className="overflow-y-auto overflow-x-hidden rounded-xs border border-line bg-surface" style={{ height: height ?? `min(${items.length * rowH + 2}px, ${LIST_MAX})` }}>
      <ul className="m-0 list-none p-0" style={virtual ? { position: "relative", height: items.length * rowH } : undefined}>
        {items.slice(first, last).map((c, i) => render(c, virtual ? { position: "absolute", top: (first + i) * rowH, left: 0, right: 0 } : undefined))}
      </ul>
    </div>
  );
}

/**
 * Spaltenraster der Zeilen: ID | Level | Text | [Status] | [Fix-Version] | Seit | Details.
 * Ab 1600 px (`wide`) kommen Fix-Version (falls noch nicht da), Paket und Quelle dazu; die Beschreibung behält `1fr`.
 */
function gridCols(variant: "open" | "plain" | "group", wide = false): string {
  const fix = "minmax(8rem,11rem)";
  const status = "9.5rem";
  const cols = ["9.5rem", "6.5rem", "minmax(0,1fr)"];
  if (variant === "open") cols.push(status);
  if (variant === "group") cols.push(fix);
  if (variant === "plain") cols.push(status, fix);
  if (wide) {
    if (variant === "open") cols.push(fix);
    cols.push("minmax(7rem,10rem)", "minmax(5rem,8rem)");
  }
  cols.push("5.5rem", "1.5rem");
  return cols.join(" ");
}

/** Raster per CSS-Variablen: unter 1600 px das schmale, ab 1600 px das breite Raster. */
function gridStyle(variant: "open" | "plain" | "group"): React.CSSProperties {
  return { "--cols": gridCols(variant), "--cols-wide": gridCols(variant, true) } as React.CSSProperties;
}
function ListHead({ variant }: { variant: "open" | "plain" | "group" }) {
  return (
    <div className="mb-px hidden items-center gap-2 px-2 text-xs font-semibold text-fg3 md:grid md:[grid-template-columns:var(--cols)] wide:[grid-template-columns:var(--cols-wide)]" style={gridStyle(variant)}>
      <span>CVE</span>
      <span>Level</span>
      <span>Beschreibung</span>
      {variant !== "group" ? <span>Status</span> : null}
      {variant !== "open" ? <span>Fix-Version</span> : null}
      {variant === "open" ? <span className="hidden wide:inline">Fix-Version</span> : null}
      <span className="hidden wide:inline">Paket</span>
      <span className="hidden wide:inline">Quelle</span>
      <span>Seit</span>
      <span className="sr-only">Details</span>
    </div>
  );
}

const LIST_MAX = "clamp(12rem, calc(100dvh - 22rem), 56rem)";

function CveList({ title, state, proxmox, variant, onOpen, onMore, empty, expected }: { expected: number | null; title: string; state: ReturnType<typeof useApi<HostCvesResponse>>; proxmox: boolean; variant: "open" | "plain"; onOpen: (c: HostCve) => void; onMore: () => void; empty: string }) {
  const items = useMemo(() => state.data?.items ?? [], [state.data]);
  const total = state.data?.total ?? 0;
  const [box, setBox] = useState<HTMLDivElement | null>(null);
  const { narrow, rowH } = useRows(box);
  const rest = total - items.length;
  const loading = !state.data;
  return (
    <div ref={setBox} className="min-w-0">
      <h3 className="mb-1 flex items-baseline gap-2 text-sm font-semibold">
        {title} <span className="tabular-nums text-xs font-normal text-fg3">{loading ? "…" : total.toLocaleString("de-DE")}</span>
      </h3>
      {narrow ? null : <ListHead variant={variant} />}
      {loading ? (
        <div className="rounded-xs border border-line bg-surface p-3 text-xs text-fg3" style={{ height: expected === null ? "8rem" : `min(${Math.max(expected, 1) * rowH + 2}px, ${LIST_MAX})` }}>
          Lädt …
        </div>
      ) : items.length === 0 ? (
        <p className="rounded-xs border border-line bg-surface p-3 text-sm text-fg2">{empty}</p>
      ) : (
        <VirtualRows
          items={items}
          rowH={rowH}
          label={`${title}, Liste`}
          render={(c, style) => <Row key={c.cve_id} c={c} h={rowH} narrow={narrow} variant={variant} proxmox={proxmox} onOpen={onOpen} style={style} />}
        />
      )}
      {rest > 0 ? (
        <button type="button" className="mt-1 text-xs underline max-md:min-h-11 max-md:min-w-11" onClick={onMore}>
          {rest} weitere anzeigen
        </button>
      ) : null}
    </div>
  );
}

function GroupedList({ kind, hostId, state, q, lvl, expandAll, proxmox, onOpen, empty }: { kind: "reboot" | "fixed"; hostId: number; state: ReturnType<typeof useApi<HostCveGroupsResponse>>; q: string; lvl: string; expandAll: boolean; proxmox: boolean; onOpen: (c: HostCve) => void; empty: string }) {
  const [open, setOpen] = useState<Record<string, boolean>>({});
  const groups = state.data?.groups ?? [];
  if (!state.data) return <div className="rounded-xs border border-line bg-surface p-3 text-xs text-fg3">Lädt …</div>;
  if (groups.length === 0) return <p className="rounded-xs border border-line bg-surface p-3 text-sm text-fg2">{empty}</p>;
  const key = (g: { fix_version: string | null }) => g.fix_version ?? "";
  // Neustart: bei nur einer Gruppe steht sie sofort offen; Gefixt bleibt eingeklappt.
  const isOpen = (g: { fix_version: string | null }) => open[key(g)] ?? (expandAll || (kind === "reboot" && groups.length === 1));
  return (
    <div className="space-y-1">
      {groups.map((g) => {
        const o = isOpen(g);
        const id = `grp-${kind}-${key(g).replace(/[^a-zA-Z0-9]/g, "_") || "none"}`;
        return (
          <div key={key(g)} className="rounded-xs border border-line bg-surface">
            <h3 className="m-0">
              <button
                type="button"
                aria-expanded={o}
                aria-controls={id}
                onClick={() => setOpen((cur) => ({ ...cur, [key(g)]: !o }))}
                className="flex min-h-8 w-full items-center gap-2 px-2 text-left text-sm font-semibold hover:bg-sunk max-md:min-h-11"
              >
                <span aria-hidden="true" className={`inline-flex transition-transform duration-100 ${o ? "" : "-rotate-90"}`}>
                  <NavIcon name="chevron" size={14} />
                </span>
                <span>
                  {g.fix_version ? (
                    <>
                      Behoben in <Mono>{g.fix_version}</Mono>: {g.count.toLocaleString("de-DE")} {g.count === 1 ? "CVE" : "CVEs"}
                    </>
                  ) : (
                    groupTitle(null, g.count)
                  )}
                </span>
              </button>
            </h3>
            <div id={id} hidden={!o}>
              {o ? <GroupItems hostId={hostId} kind={kind} fix={g.fix_version} count={g.count} q={q} lvl={lvl} proxmox={proxmox} onOpen={onOpen} /> : null}
            </div>
          </div>
        );
      })}
    </div>
  );
}

function GroupItems({ hostId, kind, fix, count, q, lvl, proxmox, onOpen }: { hostId: number; kind: "reboot" | "fixed"; fix: string | null; count: number; q: string; lvl: string; proxmox: boolean; onOpen: (c: HostCve) => void }) {
  const [limit, setLimit] = useState(GROUP_PAGE);
  // Einträge ohne Fix-Version haben keinen Gruppenfilter; sie stehen in der Statusliste.
  const fv = fix ? `&fix_version=${encodeURIComponent(fix)}` : "";
  const path = `/hosts/${hostId}/cves?status=${TILE_STATUS[kind]}${fv}&sort=level&dir=desc&limit=${limit}${q ? `&q=${encodeURIComponent(q)}` : ""}${lvl}`;
  const s = useApi<HostCvesResponse>(path, 60_000, LIVE, undefined, { keepPrevious: true });
  const [box, setBox] = useState<HTMLDivElement | null>(null);
  const { narrow, rowH } = useRows(box);
  const items = s.data?.items ?? [];
  const rest = (s.data?.total ?? count) - items.length;
  if (!s.data) return <div className="border-t border-line p-2 text-xs text-fg3">Lädt …</div>;
  const h = `${Math.min(Math.max(items.length, 1), 12) * rowH + 2}px`;
  return (
    <div ref={setBox} className="border-t border-line p-1">
      {narrow ? null : <ListHead variant="group" />}
      <VirtualRows
        items={items}
        rowH={rowH}
        height={h}
        label={`${fix ?? "Ohne Fix-Version"}, Liste`}
        render={(c, style) => <Row key={c.cve_id} c={c} h={rowH} narrow={narrow} variant="group" proxmox={proxmox} onOpen={onOpen} style={style} />}
      />
      {rest > 0 ? (
        <button type="button" className="mt-1 text-xs underline max-md:min-h-11 max-md:min-w-11" onClick={() => setLimit((l) => l + GROUP_PAGE)}>
          {rest} weitere anzeigen
        </button>
      ) : null}
    </div>
  );
}

function Row({ c, h, narrow, variant, proxmox, onOpen, style }: { c: HostCve; h: number; narrow: boolean; variant: "open" | "plain" | "group"; proxmox: boolean; onOpen: (c: HostCve) => void; style?: React.CSSProperties }) {
  const full = c.description ?? c.reason;
  const text = shortText(full) || c.reason;
  const st = CVE_STATUS[c.status];
  const statusLabel = proxmox && c.status === "unknown" ? (c.reviewed_at ? "Unbekannt: geprüft" : "Unbekannt: manuell prüfen") : c.status === "vulnerable" || c.status === "fix_pending" ? openStatusWord(c) : shortLabel(c.status);
  const lvlTone = c.level >= 8 ? "text-crit" : c.level >= 5 ? "text-warn" : "text-fg2";
  const link = (
    <Link href={`/cves/${c.cve_id}`} className="mono inline-flex items-center gap-1 font-medium max-md:min-h-11" onPointerEnter={() => prefetchApi(`/cves/${c.cve_id}`)} onFocus={() => prefetchApi(`/cves/${c.cve_id}`)}>
      {c.cve_id}
      {c.watched ? <Marker>Watchlist</Marker> : null}
    </Link>
  );
  const more = (
    <button type="button" onClick={() => onOpen(c)} aria-label={`Details zu ${c.cve_id}`} className="inline-flex size-6 shrink-0 items-center justify-center rounded-xs border border-control text-fg2 hover:bg-sunk max-md:size-11">
      <span aria-hidden="true">⋯</span>
    </button>
  );
  // Quell-Paket(e) laut Quelle (z. B. „linux“); mehrere ohne Wiederholung.
  const packages = [...new Set(c.sources.map((x) => x.package))].join(", ");
  const fk = fixInfo(c);
  const fixCell = !c.fix_version ? (
    <span className="text-fg3">–</span>
  ) : fk.kind === "announced" ? (
    <span className="text-fg3" title="Angekündigt, noch nicht als veröffentlicht bestätigt">
      <Mono>{c.fix_version}</Mono> (angekündigt)
    </span>
  ) : (
    <Mono>{c.fix_version}</Mono>
  );
  if (narrow) {
    // Mobil gestapelt: Zeile 1 ID, Level, Details; Zeile 2 Status und Fix-Stand.
    return (
      <li style={{ height: h, ...style }} className="flex flex-wrap content-center items-center gap-x-2 border-b border-line px-2 text-xs">
        {link}
        <span className={`font-medium ${lvlTone}`}>{levelWord(c.level)}</span>
        <span className="ml-auto">{more}</span>
        <span className="basis-full truncate text-fg3" title={full}>
          {[variant !== "group" ? statusLabel : null, c.fix_version ? (fk.kind === "announced" ? `${c.fix_version} (angekündigt)` : c.fix_version) : null, `seit ${since(c.published_at)}`].filter(Boolean).join(" · ")}
        </span>
      </li>
    );
  }
  return (
    <li style={{ height: h, ...gridStyle(variant), ...style }} className="grid items-center gap-2 border-b border-line px-2 text-xs [grid-template-columns:var(--cols)] last:border-b-0 wide:[grid-template-columns:var(--cols-wide)]">
      {link}
      <span className={`font-medium ${lvlTone}`} title={c.level ? `Level ${c.level}/10` : undefined}>
        {levelWord(c.level)}
        {c.level ? <span className="ml-1 tabular-nums text-fg3">{c.level}</span> : null}
      </span>
      <span className="min-w-0 truncate text-fg2" title={full}>
        {text}
      </span>
      {variant !== "group" ? (
        <span className="min-w-0" title={c.status === "vulnerable" && fk.kind === "released" ? UPDATE_HINT : undefined}>
          <StatusBadge info={st} label={statusLabel} />
        </span>
      ) : null}
      {variant === "plain" || variant === "group" ? <span className="min-w-0 whitespace-nowrap">{fixCell}</span> : null}
      {variant === "open" ? <span className="hidden min-w-0 whitespace-nowrap wide:block">{fixCell}</span> : null}
      <span className="hidden min-w-0 truncate wide:block" title={packages}>
        {packages ? <Mono>{packages}</Mono> : <span className="text-fg3">–</span>}
      </span>
      <span className="hidden min-w-0 truncate text-fg2 wide:block">{c.source ?? "–"}</span>
      <span className="tabular-nums text-fg3">{since(c.published_at)}</span>
      {more}
    </li>
  );
}

/** Kurze Chip-Beschriftungen für die dichte Zeile; Icon + Text, nie nur Farbe. */
function shortLabel(s: CveStatus): string {
  return s === "fixed_installed_reboot_required" ? "Neustart nötig" : CVE_STATUS[s].label;
}

function Detail({ c, host, running, busy, onReview }: { c: HostCve; host: Host; running: string | null; busy: boolean; onReview: (v: boolean) => void }) {
  const fix = fixInfo(c);
  // Zweite Quelle neben dem Tracker: die Paketliste des letzten Reports (apt-Kandidaten des Hosts); nur bei angekündigtem Fix nötig.
  const updates = useApi<{ items: UpdateItem[] | null }>(fix.kind === "announced" ? `/hosts/${host.id}/updates` : null, 0);
  const announced = announcedText(fix, updates.data?.items);
  return (
    <div className="space-y-3 text-sm">
      <p className="flex flex-wrap items-center gap-2">
        <StatusBadge info={CVE_STATUS[c.status]} label={host.is_proxmox && c.status === "unknown" ? "Unbekannt: manuell prüfen" : undefined} />
        <Link href={`/cves/${c.cve_id}`} className="mono">
          Zur CVE-Seite
        </Link>
        {c.level ? <span className="text-xs text-fg3">Level {c.level}/10</span> : null}
      </p>
      <p className="text-fg2">{hostState(c, running, host.is_proxmox)}</p>
      {c.status === "vulnerable" && fix.kind === "released" ? (
        <p role="note" className="border-l-4 border-accent bg-sunk px-3 py-1.5">
          <strong className="font-semibold">Fix im Archiv{c.sources.length ? ` (Paket ${[...new Set(c.sources.map((x) => x.package))].join(", ")}, ab ${fix.version})` : ` ab ${fix.version}`}.</strong> Update einspielen:
          <CodeField className="my-1" text={UPDATE_CMD} label="Befehl kopieren" />
          Danach Neustart, falls ein Kernel betroffen ist. Patchwatch führt nichts aus.
        </p>
      ) : null}
      {c.status === "vulnerable" && fix.kind === "announced" ? (
        <div role="note" className="space-y-1 border-l-4 border-warn bg-sunk px-3 py-1.5">
          <p>
            <strong className="font-semibold">Fix angekündigt, noch nicht bestätigt.</strong>
          </p>
          {announced.lines.map((l) => (
            <p key={l}>{l}</p>
          ))}
          {announced.aptAvailable ? (
            <>
              <p>Update einspielen:</p>
              <CodeField text={UPDATE_CMD} label="Befehl kopieren" />
              <p>Danach Neustart, falls ein Kernel betroffen ist. Patchwatch führt nichts aus.</p>
            </>
          ) : null}
        </div>
      ) : null}
      <p className="break-words">
        <Linkified text={c.reason} />
      </p>
      {c.description ? <p className="text-fg3">{c.description}</p> : null}
      {c.sources.length > 0 ? (
        <div className="max-w-full overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="text-left text-fg3">
                <th className="pr-3 font-semibold">Quelle</th>
                <th className="pr-3 font-semibold">Release</th>
                <th className="pr-3 font-semibold">Paket</th>
                <th className="pr-3 font-semibold">Status</th>
                <th className="font-semibold">Fix-Version</th>
              </tr>
            </thead>
            <tbody>
              {c.sources.map((s) => (
                <tr key={`${s.source}${s.release}${s.package}`}>
                  <td className="pr-3">{s.source}</td>
                  <td className="pr-3">{s.release}</td>
                  <td className="pr-3">
                    <Mono>{s.package}</Mono>
                  </td>
                  <td className="pr-3">{s.status}</td>
                  <td>
                    <Mono>{s.fix_version ?? "–"}</Mono>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
      <p className="text-xs text-fg3">
        Letzte Änderung {absTime(c.computed_at)}
        {c.source ? <> · Quelle {c.source}</> : null}
      </p>
      <label className="flex min-h-8 items-start gap-2 py-1 max-md:min-h-11 max-md:items-center">
        <input
          type="checkbox"
          className="mt-0.5 size-4 accent-[var(--accent)] max-md:mt-0 max-md:size-5"
          checked={Boolean(c.reviewed_at)}
          disabled={busy}
          onChange={(e) => onReview(e.target.checked)}
          aria-label={`${c.cve_id} manuell geprüft`}
        />
        <span>
          {c.reviewed_at ? (
            <>
              geprüft am {absTime(c.reviewed_at)}
              {c.reviewed_by ? <span className="text-fg3"> von {c.reviewed_by}</span> : null}
            </>
          ) : (
            "Manuell geprüft"
          )}
          <span className="block text-xs text-fg3">Gilt nur für den aktuellen Kernel; der Status ändert sich dadurch nicht.</span>
        </span>
      </label>
    </div>
  );
}
