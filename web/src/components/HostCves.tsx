"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import Link from "next/link";
import { api } from "@/lib/api";
import { prefetchApi, useApi } from "@/lib/useApi";
import { absTime } from "@/lib/format";
import { CVE_STATUS, type IconName } from "@/lib/status";
import { LEVEL_FILTERS, barSegments, groupTitle, kernelLine, levelWord, openStatusWord, parseCveFilter, shortText, stateCounts, summarySentence, type FeedNotice, type Tile } from "@/lib/hostCves";
import type { CveStatus, Host, HostCve, HostCveGroupsResponse, HostCvesResponse } from "@/lib/types";
import { Marker } from "@/components/DistroChip";
import { StatusBadge } from "@/components/StatusBadge";
import { Dialog } from "@/components/Dialog";
import { Mono } from "@/components/Version";
import { ErrorNote } from "@/components/States";
import { Linkified } from "@/components/Linkified";
import { Icon, NavIcon } from "@/components/Icons";
import { CopyButton } from "@/components/CopyButton";

const LIVE = ["report_received", "host_status", "host_cve_status"] as const;
const ROW_H = 32; // dichte Zeilen (DESIGN.md): 32 px
const ROW_H_TOUCH = 64; // unter 768 px: zweizeilig
const PAGE = 200;
const GROUP_PAGE = 1000; // Obergrenze der API je Anfrage
const VIRTUAL_FROM = 60; // ab dieser Zeilenzahl wird nur der sichtbare Ausschnitt gerendert
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

/** Wahr unter 768 px (Touch-Maße). */
function useNarrow(): boolean {
  const [narrow, setNarrow] = useState(false);
  useEffect(() => {
    const m = window.matchMedia("(max-width: 767px)");
    const on = () => setNarrow(m.matches);
    on();
    m.addEventListener("change", on);
    return () => m.removeEventListener("change", on);
  }, []);
  return narrow;
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
    case "vulnerable":
      return c.fix_version ? `Fix ab ${c.fix_version}, läuft ${run}` : `Kein Fix bekannt, läuft ${run}`;
    case "fix_pending":
      return c.fix_version ? `Fix angekündigt ab ${c.fix_version}, läuft ${run}` : `Fix angekündigt, läuft ${run}`;
    default:
      return proxmox ? "Keine belastbare Quelle, manuell prüfen" : "Quelle liefert keine Aussage";
  }
}

const dateFmt = new Intl.DateTimeFormat("de-DE", { day: "2-digit", month: "2-digit", year: "numeric" });
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

export function HostCves({ host, initialFilter, notice }: { host: Host; initialFilter: CveFilter | null; notice: FeedNotice }) {
  // Proxmox: es gibt nur "unbekannt, manuell prüfen"; diese Einträge stehen sofort im Blick (nie grün, kein Alarm).
  const [tile, setTile] = useState<Tile>(initialFilter ?? (host.is_proxmox ? "unknown" : "open"));
  const [text, setText] = useState("");
  const q = useDebounced(text.trim(), 250);
  const [levelMin, setLevelMin] = useState(0);
  const [limit, setLimit] = useState(PAGE);
  const [showAllFixed, setShowAllFixed] = useState(false);
  const [detail, setDetail] = useState<HostCve | null>(null);
  const [problem, setProblem] = useState<string | null>(null);
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
    setProblem(null);
    try {
      const path = `/hosts/${host.id}/cves/${c.cve_id}/review`;
      if (checked) await api.put(path);
      else await api.del(path);
      await reloadAll();
      setDetail((d) => (d && d.cve_id === c.cve_id ? { ...d, reviewed_at: checked ? new Date().toISOString() : null, reviewed_by: checked ? d.reviewed_by : null } : d));
    } catch (e) {
      setProblem(e instanceof Error ? e.message : "Speichern fehlgeschlagen");
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
  const bigTiles: Tile[] = ["open", "reboot", "fixed"];

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
      {problem ? <ErrorNote message={problem} /> : null}
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
      <div className="mb-2 grid grid-cols-3 gap-2 max-md:flex max-md:overflow-x-auto max-md:pb-1 max-md:[scroll-snap-type:x_proximity]" role="group" aria-label="CVE-Zustände">
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
        <button
          type="button"
          aria-pressed={tile === "unknown"}
          onClick={() => pick("unknown")}
          className={`flex shrink-0 flex-col justify-center rounded-xs border px-3 py-1.5 text-left text-xs max-md:min-h-11 ${tile === "unknown" ? "border-2 border-unknown bg-unknown-soft" : "border-line bg-surface hover:bg-sunk"} md:hidden`}
        >
          <span className="flex items-center gap-1 font-semibold text-unknown">
            <Icon name="unknown" size={14} /> Unbekannt <span className="tabular-nums">{sc ? numbers.unknown : "…"}</span>
            {tile === "unknown" ? <Icon name="ok" size={14} /> : null}
          </span>
        </button>
      </div>
      <div className="mb-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-fg2">
        <button
          type="button"
          aria-pressed={tile === "unknown"}
          onClick={() => pick("unknown")}
          className={`inline-flex h-6 items-center gap-1 rounded-xs border px-1.5 font-medium max-md:hidden ${tile === "unknown" ? "border-2 border-unknown bg-unknown-soft text-unknown" : "border-line bg-surface text-fg2 hover:bg-sunk"}`}
        >
          <Icon name="unknown" size={14} /> Unbekannt <span className="tabular-nums font-semibold">{sc ? numbers.unknown : "…"}</span>
          {tile === "unknown" ? <Icon name="ok" size={14} /> : null}
        </button>
        <span className="inline-flex flex-wrap items-center gap-x-2 gap-y-1">
          <span>{kernelLine(running ?? null, newest ?? null, Boolean(rebootNeeded))}</span>
          {rebootNeeded ? <CopyButton text="sudo reboot" label="Befehl kopieren" /> : null}
        </span>
      </div>
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
        <label className="flex items-center gap-2 text-xs text-fg2">
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
            empty={tile === "open" ? (notice.restricted ? "Keine offenen CVEs bekannt, aber die Quelle ist unvollständig." : "Nichts offen.") : host.is_proxmox ? "Setze CVEs auf die Watchlist, dann erscheinen sie hier als „manuell prüfen“." : "Keine Einträge für diese Auswahl."}
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
      className={`flex min-w-0 flex-col gap-0.5 rounded-xs border bg-surface px-3 py-2 text-left hover:bg-sunk max-md:min-h-11 max-md:w-56 max-md:shrink-0 ${active ? `border-2 ${TONE_BORDER[m.tone]} bg-sunk` : "border-line"}`}
    >
      <span className={`flex items-center gap-1.5 text-sm font-semibold ${TONE_TEXT[m.tone]}`}>
        <Icon name={warn ? "warn" : m.icon} size={16} />
        {m.word}
        {active ? (
          <span className="ml-auto inline-flex items-center gap-0.5 text-xs font-medium text-fg2">
            <Icon name="ok" size={14} /> Angezeigt
          </span>
        ) : null}
      </span>
      <span className="text-2xl font-semibold leading-none tabular-nums text-fg">{loaded ? n.toLocaleString("de-DE") : "…"}</span>
      <span className="text-xs text-fg2">{line}</span>
      {sub ? <span className="text-xs text-fg3">{sub}</span> : null}
    </button>
  );
}

/** Virtualisierte, dichte Zeilenliste mit fester Höhe und eigener Bildlaufleiste. */
function VirtualRows({ items, rowH, height, label, render }: { items: HostCve[]; rowH: number; height: string; label: string; render: (c: HostCve, style: React.CSSProperties | undefined) => React.ReactNode }) {
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
    <div ref={scroller} onScroll={(e) => setScroll(e.currentTarget.scrollTop)} tabIndex={0} role="region" aria-label={label} className="overflow-y-auto overflow-x-hidden rounded-xs border border-line bg-surface" style={{ height }}>
      <ul className="m-0 list-none p-0" style={virtual ? { position: "relative", height: items.length * rowH } : undefined}>
        {items.slice(first, last).map((c, i) => render(c, virtual ? { position: "absolute", top: (first + i) * rowH, left: 0, right: 0 } : undefined))}
      </ul>
    </div>
  );
}

/** Spaltenraster der Zeilen: ID | Level | Text | [Status] | [Fix-Version] | Seit | Details. */
function gridCols(variant: "open" | "plain" | "group"): string {
  const fix = "minmax(8rem,11rem)";
  const status = "9.5rem";
  const cols = ["9.5rem", "6.5rem", "minmax(0,1fr)"];
  if (variant === "open") cols.push(status);
  if (variant === "group") cols.push(fix);
  if (variant === "plain") cols.push(status, fix);
  cols.push("5.5rem", "1.5rem");
  return cols.join(" ");
}

function ListHead({ variant }: { variant: "open" | "plain" | "group" }) {
  return (
    <div className="mb-px hidden items-center gap-2 px-2 text-xs font-semibold text-fg3 md:grid" style={{ gridTemplateColumns: gridCols(variant) }}>
      <span>CVE</span>
      <span>Level</span>
      <span>Beschreibung</span>
      {variant !== "group" ? <span>Status</span> : null}
      {variant !== "open" ? <span>Fix-Version</span> : null}
      <span>Seit</span>
      <span className="sr-only">Details</span>
    </div>
  );
}

const LIST_H = "clamp(17rem, calc(100dvh - 26rem), 48rem)";

function CveList({ title, state, proxmox, variant, onOpen, onMore, empty }: { title: string; state: ReturnType<typeof useApi<HostCvesResponse>>; proxmox: boolean; variant: "open" | "plain"; onOpen: (c: HostCve) => void; onMore: () => void; empty: string }) {
  const items = useMemo(() => state.data?.items ?? [], [state.data]);
  const total = state.data?.total ?? 0;
  const rowH = useNarrow() ? ROW_H_TOUCH : ROW_H;
  const rest = total - items.length;
  const loading = !state.data;
  return (
    <div className="min-w-0">
      <h3 className="mb-1 flex items-baseline gap-2 text-sm font-semibold">
        {title} <span className="tabular-nums text-xs font-normal text-fg3">{loading ? "…" : total.toLocaleString("de-DE")}</span>
      </h3>
      <ListHead variant={variant} />
      {loading ? (
        <div className="rounded-xs border border-line bg-surface p-3 text-xs text-fg3" style={{ height: LIST_H }}>
          Lädt …
        </div>
      ) : items.length === 0 ? (
        <p className="rounded-xs border border-line bg-surface p-3 text-sm text-fg2">{empty}</p>
      ) : (
        <VirtualRows
          items={items}
          rowH={rowH}
          height={LIST_H}
          label={`${title}, Liste`}
          render={(c, style) => <Row key={c.cve_id} c={c} h={rowH} variant={variant} proxmox={proxmox} onOpen={onOpen} style={style} />}
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
  const rowH = useNarrow() ? ROW_H_TOUCH : ROW_H;
  const items = s.data?.items ?? [];
  const rest = (s.data?.total ?? count) - items.length;
  if (!s.data) return <div className="border-t border-line p-2 text-xs text-fg3">Lädt …</div>;
  const h = `${Math.min(Math.max(items.length, 1), 12) * rowH + 2}px`;
  return (
    <div className="border-t border-line p-1">
      <ListHead variant="group" />
      <VirtualRows
        items={items}
        rowH={rowH}
        height={h}
        label={`${fix ?? "Ohne Fix-Version"}, Liste`}
        render={(c, style) => <Row key={c.cve_id} c={c} h={rowH} variant="group" proxmox={proxmox} onOpen={onOpen} style={style} />}
      />
      {rest > 0 ? (
        <button type="button" className="mt-1 text-xs underline max-md:min-h-11 max-md:min-w-11" onClick={() => setLimit((l) => l + GROUP_PAGE)}>
          {rest} weitere anzeigen
        </button>
      ) : null}
    </div>
  );
}

function Row({ c, h, variant, proxmox, onOpen, style }: { c: HostCve; h: number; variant: "open" | "plain" | "group"; proxmox: boolean; onOpen: (c: HostCve) => void; style?: React.CSSProperties }) {
  const full = c.description ?? c.reason;
  const text = shortText(full) || c.reason;
  const narrow = h > ROW_H;
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
  const fixCell = c.fix_version ? <Mono>{c.fix_version}</Mono> : <span className="text-fg3">–</span>;
  if (narrow) {
    // Mobil gestapelt: Zeile 1 ID, Level, Details; Zeile 2 Status und Fix-Stand.
    return (
      <li style={{ height: h, ...style }} className="flex flex-wrap content-center items-center gap-x-2 border-b border-line px-2 text-xs">
        {link}
        <span className={`font-medium ${lvlTone}`}>{levelWord(c.level)}</span>
        <span className="ml-auto">{more}</span>
        <span className="basis-full truncate text-fg3" title={full}>
          {[variant !== "group" ? statusLabel : null, c.fix_version, `seit ${since(c.published_at)}`].filter(Boolean).join(" · ")}
        </span>
      </li>
    );
  }
  return (
    <li style={{ height: h, gridTemplateColumns: gridCols(variant), ...style }} className="grid items-center gap-2 border-b border-line px-2 text-xs last:border-b-0">
      {link}
      <span className={`font-medium ${lvlTone}`} title={c.level ? `Level ${c.level}/10` : undefined}>
        {levelWord(c.level)}
        {c.level ? <span className="ml-1 tabular-nums text-fg3">{c.level}</span> : null}
      </span>
      <span className="min-w-0 truncate text-fg2" title={full}>
        {text}
      </span>
      {variant !== "group" ? (
        <span className="min-w-0">
          <StatusBadge info={st} label={statusLabel} />
        </span>
      ) : null}
      {variant === "plain" || variant === "group" ? <span className="min-w-0 whitespace-nowrap">{fixCell}</span> : null}
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
