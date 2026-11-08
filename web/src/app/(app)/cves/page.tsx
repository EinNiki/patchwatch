"use client";

import { memo, Suspense, useCallback, useEffect, useMemo, useRef, useState } from "react";
import Link from "next/link";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { api } from "@/lib/api";
import { prefetchApi, useApi } from "@/lib/useApi";
import { cacheGet, cacheSet } from "@/lib/apiCache";
import type { CveDetail, CveListItem, Host } from "@/lib/types";
import { Empty, ErrorNote } from "@/components/States";
import { TableSkeleton } from "@/components/Skeleton";
import { Icon, NavIcon } from "@/components/Icons";
import { affectedHosts, affectingLabel, hostChips, hostState, listStats, parseAffectsAll, parseSort, updatedTitle } from "@/lib/cveList";
import { absTime, relTime } from "@/lib/format";
import { useFlash } from "@/lib/useFlash";
import { toast } from "@/lib/toastStore";
import { Button, Field, TextInput } from "@/components/Controls";
import { ChipLegend, DistroChip } from "@/components/DistroChip";
import { PageHeader } from "@/components/PageHeader";
import { Popover } from "@/components/Popover";
import { FeedSources } from "@/components/FeedSources";

const PAGE = 100;
const CVE_RE = /^CVE-\d{4}-\d{4,7}$/;
/** Ansicht "nur Watchlist": eine entfernte CVE bleibt so lange sichtbar (mit Rückgängig), dann blendet sie aus. */
const HIDE_WAIT_MS = 4000;
const FADE_MS = 150;

function dropFromCache(path: string, id: string) {
  const cur = cacheGet<CveListItem[]>(path);
  if (cur) cacheSet(path, cur.filter((x) => x.id !== id));
}

const FIX_LABEL: Record<string, string> = { fixed: "gefixt", open: "offen" };
const LEGACY_SPLIT: Record<string, { debian: string; ubuntu: string }> = {
  debian_fixed_ubuntu_open: { debian: "fixed", ubuntu: "open" },
  ubuntu_fixed_debian_open: { debian: "open", ubuntu: "fixed" },
};
const fixParam = (v: string | null) => (v === "fixed" || v === "open" ? v : "");

function useDebounced<T>(value: T, ms: number): T {
  const [v, setV] = useState(value);
  useEffect(() => {
    const t = setTimeout(() => setV(value), ms);
    return () => clearTimeout(t);
  }, [value, ms]);
  return v;
}

function CveView() {
  const router = useRouter();
  const pathname = usePathname();
  const params = useSearchParams();
  const urlQ = params.get("q") ?? "";
  const onlyWatch = params.get("watchlist") === "1";
  const distro = ["debian", "ubuntu"].includes(params.get("distro") ?? "") ? (params.get("distro") as string) : "";
  // Alt-URLs mit `split=` werden auf die beiden Distro-Filter abgebildet.
  const splitRaw = params.get("split") ?? "";
  const legacy = LEGACY_SPLIT[splitRaw];
  const debianFix = fixParam(params.get("debian")) || legacy?.debian || "";
  const ubuntuFix = fixParam(params.get("ubuntu")) || legacy?.ubuntu || "";
  const affectsAll = parseAffectsAll(params.get("affects"));
  const sort = parseSort(params.get("sort"));
  const dir = params.get("dir") === "asc" ? "asc" : "desc";
  /** Klick auf eine Spaltenüberschrift: gleiche Spalte kehrt die Richtung um, eine andere startet absteigend. */
  function sortBy(key: string) {
    const p = new URLSearchParams(params.toString());
    if (key === sort) {
      if (dir === "desc") p.set("dir", "asc");
      else p.delete("dir");
    } else {
      p.delete("dir");
    }
    if (key === "hosts") p.delete("sort");
    else p.set("sort", key);
    router.replace(p.toString() ? `${pathname}?${p}` : pathname, { scroll: false });
  }
  const [qInput, setQInput] = useState(urlQ);
  const q = useDebounced(qInput, 150);
  const [limit, setLimit] = useState(PAGE);
  const [newId, setNewId] = useState("");
  const [pendingIds, setPendingIds] = useState<ReadonlySet<string>>(new Set());
  const [newNote, setNewNote] = useState("");
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [filtersOpen, setFiltersOpen] = useState(false);

  const qs = new URLSearchParams({ limit: String(limit) });
  if (onlyWatch) qs.set("watchlist", "true");
  if (q.trim()) qs.set("q", q.trim());
  if (sort !== "hosts") qs.set("sort", sort);
  if (affectsAll) qs.set("affects", "all");
  if (dir === "asc") qs.set("dir", "asc");
  if (distro) qs.set("distro", distro);
  if (debianFix) qs.set("debian", debianFix);
  if (ubuntuFix) qs.set("ubuntu", ubuntuFix);
  const listPath = `/cves?${qs}`;
  // Hostnamen der Chips → Adresse der Host-Seite (die CVE-Liste liefert nur Namen; Hostnamen sind eindeutig).
  const hostList = useApi<Host[]>("/hosts", 60_000);
  const hostIds = useMemo(() => new Map((hostList.data ?? []).map((h) => [h.name, h.id] as const)), [hostList.data]);
  const cves = useApi<CveListItem[]>(listPath, 60_000, ["host_cve_status", "report_received"], undefined, { keepPrevious: true });
  // Zählung „betrifft meine Hosts“ für die Kennzahlzeile (gleiche Filterlogik wie die Liste).
  const countQs = new URLSearchParams(qs);
  for (const k of ["limit", "sort", "dir"]) countQs.delete(k);
  const scopeCount = useApi<{ affecting: number }>(`/cves/scope-count?${countQs}`, 60_000, ["host_cve_status", "report_received"], undefined, { keepPrevious: true });
  // Sofortige Rückmeldung beim Filtern: die bisherige Liste bleibt stehen und wird abgedunkelt, bis die neue da ist.
  const updating = cves.stale || qInput !== q;
  // Beim ersten Aufbau erscheinen zuerst 30 Zeilen, der Rest folgt in kleinen Schritten: kein langer Task, die Seite
  // reagiert sofort (100 Zeilen auf einmal waren ~100 ms Hauptthread).
  // Sofortige Reaktion auf einen Klick in der Kopfzeile: Solange die neu sortierte Liste vom Server noch unterwegs ist,
  // wird die vorhandene Liste lokal umsortiert (beobachtete CVEs bleiben oben). Die Serverantwort ersetzt sie danach.
  const sortedRows = useMemo(() => {
    const rows = cves.data ?? [];
    if (!cves.stale) return rows;
    const val = (c: CveListItem) =>
      sort === "level" ? c.level : sort === "hosts" ? affectedHosts(c) : Date.parse((sort === "updated" ? c.updated_at : c.published_at) ?? "") || 0;
    const sign = dir === "asc" ? 1 : -1;
    return [...rows].sort((a, b) => Number(b.watched) - Number(a.watched) || sign * (val(a) - val(b)) || (sort === "hosts" ? b.level - a.level : 0) || b.id.localeCompare(a.id));
  }, [cves.data, cves.stale, sort, dir]);
  const total = cves.data?.length ?? 0;
  const [rendered, setRendered] = useState(30);
  useEffect(() => {
    if (rendered >= total) return;
    const t = setTimeout(() => setRendered((n) => n + 35), 0);
    return () => clearTimeout(t);
  }, [rendered, total]);

  // Zeilen, die in der Watchlist-Ansicht gerade entfernt wurden: "wait" = Hinweis sichtbar, "fade" = blendet aus.
  // Je Zeile ein eigener Timer; der Server speichert sofort, nur das Ausblenden ist verzögert.
  const [hiding, setHiding] = useState<ReadonlyMap<string, "wait" | "fade">>(new Map());
  const [announce, setAnnounce] = useState("");
  const pending = useRef(new Map<string, { path: string; timers: ReturnType<typeof setTimeout>[]; item?: CveListItem; index: number }>());

  function setHideState(id: string, state: "wait" | "fade" | null) {
    setHiding((m) => {
      const n = new Map(m);
      if (state) n.set(id, state);
      else n.delete(id);
      return n;
    });
  }
  function finishHide(id: string) {
    const p = pending.current.get(id);
    if (!p) return;
    p.timers.forEach(clearTimeout);
    pending.current.delete(id);
    dropFromCache(p.path, id);
    setHideState(id, null);
  }
  function cancelHide(id: string) {
    const p = pending.current.get(id);
    if (!p) return;
    p.timers.forEach(clearTimeout);
    pending.current.delete(id);
    setHideState(id, null);
  }
  function startHide(id: string, item: CveListItem) {
    const entry = { path: listPath, timers: [] as ReturnType<typeof setTimeout>[], item, index: cves.data?.findIndex((x) => x.id === id) ?? 0 };
    pending.current.set(id, entry);
    setHideState(id, "wait");
    entry.timers.push(
      setTimeout(() => {
        setHideState(id, "fade");
        entry.timers.push(setTimeout(() => finishHide(id), FADE_MS));
      }, HIDE_WAIT_MS),
    );
  }

  // Lädt ein Live-Ereignis die Liste neu, während eine Zeile noch mit "Rückgängig" sichtbar sein soll, setzen wir sie
  // an ihre Stelle zurück (der Server liefert sie nach dem Entfernen nicht mehr).
  useEffect(() => {
    const list = cves.data;
    if (!list || cves.stale) return;
    const missing = [...pending.current.entries()].filter(([id, p]) => p.path === listPath && p.item && !list.some((x) => x.id === id));
    if (missing.length === 0) return;
    const next = [...list];
    for (const [, p] of missing) next.splice(Math.min(Math.max(p.index, 0), next.length), 0, p.item!);
    cacheSet(listPath, next);
  }, [cves.data, cves.stale, listPath]);

  // Ansicht wechselt (Filter geändert) oder Seite wird verlassen: ausstehendes Ausblenden sofort abschließen.
  useEffect(() => {
    const map = pending.current;
    return () => {
      for (const [id, p] of map) {
        p.timers.forEach(clearTimeout);
        dropFromCache(p.path, id);
      }
      map.clear();
      setHiding(new Map());
    };
  }, [listPath]);
  const filtered = onlyWatch || affectsAll || q.trim() !== "" || distro !== "" || debianFix !== "" || ubuntuFix !== "";
  const activeFilters = [q.trim(), onlyWatch, affectsAll, distro, debianFix, ubuntuFix].filter(Boolean).length;
  const flashed = useFlash(
    cves.data,
    (c) => c.id,
    (c) => `${c.hosts_vulnerable}|${c.hosts_fix_pending}|${c.hosts_unknown}|${c.updated_at}|${c.distros.map((d) => `${d.source}${d.release}${d.status}`).join(",")}`,
  );

  /** Filter stehen in der URL (teilbar, Zurück-Taste funktioniert). */
  function setParam(key: string, value: string | null) {
    const p = new URLSearchParams(params.toString());
    if (legacy) {
      p.delete("split");
      if (debianFix) p.set("debian", debianFix);
      if (ubuntuFix) p.set("ubuntu", ubuntuFix);
    }
    if (value) p.set(key, value);
    else p.delete(key);
    router.replace(p.toString() ? `${pathname}?${p}` : pathname, { scroll: false });
  }
  const setWatchFilter = (on: boolean) => setParam("watchlist", on ? "1" : null);

  /** Ersetzt nur die betroffene Zeile durch ihren frischen Stand (kein Neuladen der Liste). */
  async function refreshRow(id: string) {
    const rowQs = new URLSearchParams({ q: id, limit: "20" });
    const rows = await api.get<CveListItem[]>(`/cves?${rowQs}`);
    const fresh = rows.find((r) => r.id === id);
    if (fresh) cves.mutate((list) => list.map((x) => (x.id === id ? fresh : x)));
  }

  /** Optimistisch: der Stern springt sofort, die Anfrage läuft im Hintergrund, bei Fehler Rollback mit Hinweis. */
  async function toggle(c: CveListItem) {
    const want = !c.watched;
    if (pendingIds.has(c.id)) return;
    setNotice(null);
    setPendingIds((s) => new Set(s).add(c.id));
    const hadHide = pending.current.has(c.id);
    cancelHide(c.id);
    cves.mutate((list) => list.map((x) => (x.id === c.id ? { ...x, watched: want } : x)));
    if (onlyWatch && !want) {
      startHide(c.id, { ...c, watched: false });
      setAnnounce(`${c.id} von der Watchlist entfernt, Rückgängig möglich`);
    } else if (want && hadHide) {
      setAnnounce(`${c.id} bleibt auf der Watchlist`);
    }
    try {
      const what = `${c.id}: Die Watchlist konnte nicht geändert werden. Der Stand wurde zurückgesetzt`;
      if (want) await api.put(`/watchlist/${c.id}`, undefined, { what });
      else await api.del(`/watchlist/${c.id}`, { what });
      if (!(onlyWatch && !want)) await refreshRow(c.id).catch(() => undefined);
    } catch {
      if (onlyWatch && !want) cancelHide(c.id);
      cves.mutate((list) => list.map((x) => (x.id === c.id ? { ...x, watched: c.watched } : x)));
    } finally {
      setPendingIds((s) => {
        const n = new Set(s);
        n.delete(c.id);
        return n;
      });
    }
  }

  // Stabile Referenz für die memoisierten Zeilen; ruft immer die aktuelle toggle-Version auf.
  const toggleRef = useRef(toggle);
  useEffect(() => {
    toggleRef.current = toggle;
  });
  const onToggle = useCallback((c: CveListItem) => void toggleRef.current(c), []);

  async function add(e: React.FormEvent) {
    e.preventDefault();
    const id = newId.trim().toUpperCase();
    if (!CVE_RE.test(id)) {
      setNotice("Ungültige CVE-ID. Erwartet wird das Format CVE-2024-1086.");
      return;
    }
    setBusy(true);
    setNotice(null);
    try {
      await api.put(`/watchlist/${id}`, newNote.trim() ? { note: newNote.trim() } : {}, { what: "CVE konnte nicht zur Watchlist hinzugefügt werden" });
      toast.success(`${id} zur Watchlist hinzugefügt.`);
      setNewId("");
      setNewNote("");
      await cves.reload();
    } catch {
      /* Der API-Client hat den Fehler als Toast gemeldet. */
    } finally {
      setBusy(false);
    }
  }

  const stats = cves.data ? listStats(cves.data) : null;
  const truncated = (cves.data?.length ?? 0) >= limit && (scopeCount.data?.affecting ?? 0) > (stats?.affecting ?? 0);
  const chips: { key: string; label: string; remove: () => void }[] = [];
  // Leerer Standard („Meine Hosts“ ohne weitere Filter): freundlicher Hinweis statt „Keine passenden CVEs“.
  const noOtherFilter = !onlyWatch && q.trim() === "" && !distro && !debianFix && !ubuntuFix;
  const onlyMineEmpty = cves.data?.length === 0 && !affectsAll && noOtherFilter;
  // „Alle“ ohne weitere Filter und trotzdem leer: es gibt noch gar keine CVE-Daten.
  const noDataAtAll = cves.data?.length === 0 && affectsAll && noOtherFilter;
  if (q.trim()) chips.push({ key: "q", label: `Suche: ${q.trim()}`, remove: () => { setQInput(""); setParam("q", null); } });
  if (distro) chips.push({ key: "distro", label: `Distribution: ${distro === "debian" ? "Debian" : "Ubuntu"}`, remove: () => setParam("distro", null) });
  if (debianFix) chips.push({ key: "debian", label: `Debian: ${FIX_LABEL[debianFix]}`, remove: () => setParam("debian", null) });
  if (ubuntuFix) chips.push({ key: "ubuntu", label: `Ubuntu: ${FIX_LABEL[ubuntuFix]}`, remove: () => setParam("ubuntu", null) });
  if (onlyWatch) chips.push({ key: "watchlist", label: "Nur Watchlist", remove: () => setWatchFilter(false) });
  if (affectsAll) chips.push({ key: "affects", label: "Betrifft: alle CVEs", remove: () => setParam("affects", null) });
  const resetAll = () => {
    setQInput("");
    router.replace(pathname, { scroll: false });
  };

  return (
    <>
      <PageHeader title="CVEs" count={cves.data ? `${cves.data.length}${cves.data.length >= limit ? "+" : ""} angezeigt` : undefined} />
      <FeedSources />

      <section aria-labelledby="wl-h">
        <h2 id="wl-h" className="mb-2 text-lg font-semibold">
          CVE-Liste
        </h2>
        <div className="mb-3 border-y border-line">
          <h3 className="flex min-h-9 items-center font-semibold text-fg2">Watchlist: CVE hinzufügen</h3>
          <form onSubmit={(e) => void add(e)} className="flex flex-wrap items-end gap-3 pb-3 pt-1">
            <Field label="CVE-ID beobachten">
              <TextInput value={newId} onChange={(e) => setNewId(e.target.value)} placeholder="CVE-2024-1086" className="w-48 font-mono" maxLength={20} />
            </Field>
            <Field label="Notiz (optional)">
              <TextInput value={newNote} onChange={(e) => setNewNote(e.target.value)} className="w-64 max-w-full" maxLength={500} />
            </Field>
            <Button type="submit" variant="primary" disabled={busy || !newId.trim()}>
              Zur Watchlist
            </Button>
          </form>
        </div>
        <div className="sr-only" role="status" aria-live="polite">{announce}</div>
        <div role="status">{notice ? <ErrorNote message={notice} /> : null}</div>

        <div className="mb-3 md:hidden">
          <Button aria-expanded={filtersOpen} aria-controls="cve-filters" onClick={() => setFiltersOpen((o) => !o)}>
            <NavIcon name="filter" />
            Filter{activeFilters ? ` (${activeFilters})` : ""}
          </Button>
        </div>
        <div id="cve-filters" className={`mb-3 mt-2 flex-wrap items-center gap-x-3 gap-y-2 max-md:flex-col max-md:items-stretch ${filtersOpen ? "flex" : "max-md:hidden md:flex"}`}>
          <label className="flex items-center gap-2 text-xs font-semibold text-fg2 max-md:flex-col max-md:items-stretch max-md:gap-1">
            Suche
            <TextInput type="search" value={qInput} onChange={(e) => setQInput(e.target.value)} placeholder="CVE-ID oder Text" className="w-52 max-w-full font-normal max-md:w-full" />
          </label>
          <label className="flex items-center gap-2 text-xs font-semibold text-fg2 max-md:flex-col max-md:items-stretch max-md:gap-1">
            Betrifft
            <select value={affectsAll ? "all" : "mine"} onChange={(e) => setParam("affects", e.target.value === "all" ? "all" : null)} className="min-h-8 rounded-sm border border-control bg-sunk px-1.5 text-sm font-normal text-fg max-md:min-h-11">
              <option value="mine">Meine Hosts</option>
              <option value="all">Alle</option>
            </select>
          </label>
          <label className="flex items-center gap-2 text-xs font-semibold text-fg2 max-md:flex-col max-md:items-stretch max-md:gap-1">
            Distribution
            <select value={distro} onChange={(e) => setParam("distro", e.target.value || null)} className="min-h-8 rounded-sm border border-control bg-sunk px-1.5 text-sm font-normal text-fg max-md:min-h-11">
              <option value="">Alle</option>
              <option value="debian">Debian</option>
              <option value="ubuntu">Ubuntu</option>
            </select>
          </label>
          {(["debian", "ubuntu"] as const).map((d) => (
            <label key={d} className="flex items-center gap-2 text-xs font-semibold text-fg2 max-md:flex-col max-md:items-stretch max-md:gap-1">
              {d === "debian" ? "Debian" : "Ubuntu"}
              <select
                value={d === "debian" ? debianFix : ubuntuFix}
                onChange={(e) => setParam(d, e.target.value || null)}
                className="min-h-8 rounded-sm border border-control bg-sunk px-1.5 text-sm font-normal text-fg max-md:min-h-11"
              >
                <option value="">Egal</option>
                <option value="fixed">gefixt</option>
                <option value="open">offen</option>
              </select>
            </label>
          ))}
          <label className="flex min-h-8 items-center gap-2 text-sm max-md:min-h-11">
            <input type="checkbox" checked={onlyWatch} onChange={(e) => setWatchFilter(e.target.checked)} className="size-4 accent-(--accent) max-md:size-5" />
            nur Watchlist
          </label>
        </div>

        {chips.length > 0 ? (
          <ul aria-label="Aktive Filter" className="mb-3 flex flex-wrap items-center gap-2">
            {chips.map((c) => (
              <li key={c.key}>
                <button type="button" onClick={c.remove} aria-label={`Filter ${c.label} entfernen`} className="inline-flex min-h-7 items-center gap-1.5 rounded-sm border border-line bg-sunk px-2 text-xs text-fg hover:border-control max-md:min-h-11">
                  {c.label}
                  <NavIcon name="close" size={12} />
                </button>
              </li>
            ))}
            {chips.length > 1 ? (
              <li>
                <button type="button" onClick={resetAll} className="inline-flex min-h-7 items-center px-1 text-xs text-accent underline max-md:min-h-11">
                  Alle zurücksetzen
                </button>
              </li>
            ) : null}
          </ul>
        ) : null}

        <p className="mb-1 text-xs text-fg3">Filter berücksichtigen nur Releases deiner Hosts.</p>
        {/* Kennzahlen: nur Anzeige (kein Knopf), aus den geladenen Zeilen berechnet und deshalb deckungsgleich mit der Tabelle. */}
        <p className="mb-2 flex flex-wrap items-baseline gap-x-2 gap-y-0.5 text-sm" aria-live="polite" data-testid="cve-stats">
          <span className="font-semibold" data-testid="affects-count">
            {scopeCount.data ? affectingLabel(scopeCount.data.affecting) : <span className="text-fg3">CVEs werden gezählt …</span>}
          </span>
          {stats && stats.affecting > 0 ? (
            <>
              <span aria-hidden="true" className="text-fg3">·</span>
              <span>davon hoch/kritisch <strong className="tabular-nums">{stats.high}</strong></span>
              <span aria-hidden="true" className="text-fg3">·</span>
              <span><strong className="tabular-nums">{stats.withFix}</strong> mit Fix im Archiv</span>
              <span aria-hidden="true" className="text-fg3">·</span>
              <span><strong className="tabular-nums">{stats.withoutFix}</strong> ohne Fix</span>
              {truncated ? <span className="text-xs text-fg3">(in den ersten {cves.data?.length} der Liste)</span> : null}
            </>
          ) : null}
        </p>

        {cves.error && !cves.data ? <ErrorNote message={cves.error} /> : null}
        {!cves.data ? (
          <TableSkeleton what="CVEs" />
        ) : cves.data.length === 0 ? (
          <Empty title={onlyMineEmpty ? "Keine CVE betrifft deine Hosts" : noDataAtAll ? "Noch keine CVE-Daten" : filtered ? "Keine passenden CVEs" : "Noch keine CVE-Daten"}>
            {onlyMineEmpty ? (
              <>
                <span className="block">Gut so: Zu deinen Hosts gibt es zurzeit keine CVE mit verwundbarem Zustand, angekündigtem Fix oder nötigem Neustart.</span>
                <span className="mt-2 flex flex-wrap gap-3">
                  <button type="button" onClick={() => setParam("affects", "all")} className="text-accent underline max-md:min-h-11">
                    Alle CVEs anzeigen
                  </button>
                </span>
              </>
            ) : filtered && !noDataAtAll ? (
              <>
                <span className="block">
                  Aktive Filter: {chips.length > 0 ? chips.map((c) => c.label).join(", ") : "keine"}.
                </span>
                <span className="mt-2 flex flex-wrap gap-3">
                  <button type="button" onClick={resetAll} className="text-accent underline max-md:min-h-11">
                    Filter zurücksetzen
                  </button>
                </span>
              </>
            ) : (
              <>
                Sobald ein Feed erfolgreich abgerufen wurde, erscheinen die CVEs hier. Prüfe den Feed-Zustand oben oder rufe die Feeds mit „Jetzt
                abrufen“ ab.
              </>
            )}
          </Empty>
        ) : (
          <>
            <div className="updatable max-xl:overflow-x-auto" data-updating={updating ? "" : undefined} aria-busy={updating || undefined}>
              <table className="tbl stack fit">
                <caption>CVEs mit Distributionen, betroffenen Hosts und Watchlist-Status</caption>
                <thead>
                  <tr>
                    <th scope="col" className="w-10"><span className="th-pad"><span className="sr-only">Beobachten</span></span></th>
                    <SortTh label="CVE" hint={sort === "latest" ? (dir === "desc" ? "neueste zuerst" : "älteste zuerst") : "nach Datum sortieren"} active={sort === "latest"} dir={dir} onClick={() => sortBy("latest")} />
                    <th scope="col" className="grow"><span className="th-pad">Beschreibung</span></th>
                    <th scope="col"><span className="th-pad">Distributionen</span></th>
                    <SortTh label="Hosts" hint="nach Anzahl betroffener Hosts sortieren" active={sort === "hosts"} dir={dir} onClick={() => sortBy("hosts")} />
                    <th scope="col" className="max-wide:hidden"><span className="th-pad">Pakete</span></th>
                    <SortTh label="Level" className="max-wide:hidden" active={sort === "level"} dir={dir} onClick={() => sortBy("level")} />
                    <SortTh label="Aktualisiert" className="md:max-xl:hidden" active={sort === "updated"} dir={dir} onClick={() => sortBy("updated")} />
                  </tr>
                </thead>
                <tbody>
                  {sortedRows.slice(0, rendered).map((c) => (
                    <CveRow
                      key={c.id}
                      c={c}
                      flash={flashed.has(c.id)}
                      hide={hiding.get(c.id)}
                      hostIds={hostIds}
                      onToggle={onToggle}
                    />
                  ))}
                </tbody>
              </table>
            </div>
            {cves.data.length >= limit ? (
              <p className="mt-2">
                <Button onClick={() => setLimit(limit + PAGE)}>Weitere laden</Button>
              </p>
            ) : null}
          </>
        )}
        <p className="mt-4 text-xs text-fg3">
          Details zur Bewertung je Host stehen in der Host-Ansicht (<Link href="/">Hosts</Link>). 
        </p>
        <ChipLegend />
      </section>
    </>
  );
}

/** Eine Tabellenzeile. `memo`: Ein Stern-Klick oder ein Live-Update rendert nur die betroffene Zeile neu, nicht alle 100. */
const CveRow = memo(function CveRow({
  c,
  flash,
  hide,
  hostIds,
  onToggle,
}: {
  c: CveListItem;
  flash: boolean;
  hide: "wait" | "fade" | undefined;
  hostIds: ReadonlyMap<string, number>;
  onToggle: (c: CveListItem) => void;
}) {
  const [pop, setPop] = useState(false);
  return (
      <tr data-flash={flash ? "" : undefined} data-watched={c.watched ? "" : undefined} data-leaving={hide === "fade" ? "" : undefined}>
        <td className="cell-star">
          <button
            type="button"
            className="star-btn"
            data-on={c.watched ? "" : undefined}
            data-pop={pop ? "" : undefined}
            onClick={() => {
              setPop(true);
              onToggle(c);
            }}
            onAnimationEnd={() => setPop(false)}
            aria-label={c.watched ? "Nicht mehr beobachten" : "Beobachten"}
            title={c.watched ? "Nicht mehr beobachten" : "Beobachten"}
          >
            <NavIcon name={c.watched ? "star-fill" : "star"} />
          </button>
        </td>
        <td className="cell-primary">
          <Link href={`/cves/${c.id}`} className="mono whitespace-nowrap font-medium" onPointerEnter={() => prefetchApi(`/cves/${c.id}`)} onFocus={() => prefetchApi(`/cves/${c.id}`)}>
            {c.id}
          </Link>
          {hide !== undefined ? (
            <div className="text-xs text-fg2">
              Entfernt.{" "}
              <button type="button" className="underline" onClick={() => onToggle(c)}>
                Rückgängig
              </button>
            </div>
          ) : null}
          {c.exploited ? <div className="text-xs font-semibold text-crit">Aktiv ausgenutzt (CISA KEV)</div> : null}
          {c.level ? <div className="text-xs text-fg3 wide:hidden">Level {c.level}/10</div> : null}
        </td>
        <td className="grow wrap min-w-24 max-md:order-0 max-md:flex-[1_0_100%]">
          {c.description ? <span className="line-clamp-2 max-w-[64rem] [contain:inline-size] max-md:[contain:none]">{c.description}</span> : <span className="text-fg3">Noch nicht in den Feeds</span>}
          {c.note ? <div className="text-xs text-accent">Notiz: {c.note}</div> : null}
        </td>
        <td className="cell-status min-w-[12rem] max-md:min-w-0 max-md:flex-[1_0_100%]">
          <Distros c={c} />
        </td>
        <td data-label="Hosts">
          <HostChips c={c} ids={hostIds} />
        </td>
        <td className="max-wide:hidden">
          <PackagesCell c={c} />
        </td>
        <td className="mono max-wide:hidden" title={c.priority ?? undefined}>{c.level ? `${c.level}/10` : "–"}</td>
        <td data-label="Aktualisiert" className="whitespace-nowrap md:max-xl:hidden">
          {c.updated_at ? (
            <time dateTime={c.updated_at} title={updatedTitle(c.updated_at, c.last_synced_at, absTime)}>
              {relTime(c.updated_at)}
            </time>
          ) : (
            <span className="text-fg3" title={updatedTitle(null, c.last_synced_at, absTime)}>
              unbekannt
            </span>
          )}
        </td>
      </tr>
  );
});

/** Chips der Releases, die auf Hosts laufen; weitere Releases lädt „+ n weitere“ bei Bedarf nach. */
function Distros({ c }: { c: CveListItem }) {
  const [more, setMore] = useState(false);
  if (c.distros.length === 0 && c.hidden_releases === 0) return <span className="text-fg3">keine Quellendaten</span>;
  return (
    <div className="flex flex-col items-start gap-1 max-md:flex-row max-md:flex-wrap">
      {c.distros.length === 0 ? <span className="text-fg3">Kein Release auf deinen Hosts</span> : null}
      {c.distros.map((d) => (
        <DistroChip key={`${d.source}/${d.release}`} d={d} />
      ))}
      {more ? <OtherReleases id={c.id} /> : null}
      {c.hidden_releases > 0 ? (
        <Button aria-expanded={more} onClick={() => setMore(!more)} className="!h-(--chip-h) !min-h-(--chip-h) !rounded-xs !border-line !px-1.5 !py-0 !text-xs !font-normal !text-fg2 max-md:!min-h-11">
          {more ? "Weniger anzeigen" : `+ ${c.hidden_releases} weitere Releases`}
          <span className="sr-only"> für {c.id}</span>
        </Button>
      ) : null}
    </div>
  );
}

/** Lädt erst beim Aufklappen die Detaildaten, damit nicht jede der 100 Zeilen einen eigenen Abruf-Hook trägt. */
function OtherReleases({ id }: { id: string }) {
  const detail = useApi<CveDetail>(`/cves/${id}`);
  const others = detail.data?.distros.filter((d) => !d.mine) ?? [];
  return (
    <>
      {others.map((d) => (
        <DistroChip key={`${d.source}/${d.release}`} d={d} />
      ))}
      {detail.error ? <span className="text-crit">{detail.error}</span> : null}
    </>
  );
}

/** Quell-Pakete der Chips ohne Wiederholung (z. B. „linux“). */
function PackagesCell({ c }: { c: CveListItem }) {
  const pk = [...new Set(c.distros.map((d) => d.package))];
  if (pk.length === 0) return <span className="text-fg3">–</span>;
  return <span className="mono text-xs" title={pk.join(", ")}>{pk.slice(0, 2).join(", ")}{pk.length > 2 ? ` +${pk.length - 2}` : ""}</span>;
}

/**
 * Spalte „Hosts“: nur Hostnamen als Chips, jeder ein Link zur Host-Seite. Das Symbol vor dem Namen zeigt den Zustand
 * (Form und Farbe, dazu Tooltip und aria-label). Höchstens 3 Chips in einer Zeile, der Rest steht hinter „+N“ im Popover.
 * Die Namen kommen aus der CVE-Liste, die Adresse aus der Hostliste.
 */
function HostChips({ c, ids }: { c: CveListItem; ids: ReadonlyMap<string, number> }) {
  const { names, more } = hostChips(c, 3);
  const all = c.affected_hosts ?? [];
  const state = hostState(c);
  if (names.length === 0 && more === 0) {
    // Keine Namen (nur „unbekannt“ oder gar nichts): Symbol mit Zahl statt Text, zugänglich benannt.
    if (c.hosts_unknown === 0) return <span className="text-fg3" aria-label="keine betroffenen Hosts">–</span>;
    const t = `${c.hosts_unknown} ${c.hosts_unknown === 1 ? "Host" : "Hosts"}: Lage unbekannt`;
    return (
      <span className="inline-flex items-center gap-1 text-unknown" title={t} aria-label={t}>
        <Icon name="unknown" size={12} />
        <span className="text-xs tabular-nums">{c.hosts_unknown}</span>
      </span>
    );
  }
  const chip = "inline-flex h-(--chip-h) max-w-32 items-center gap-1 rounded-xs border border-line bg-sunk px-1.5 text-xs no-underline hover:border-accent hover:text-accent max-md:min-h-11 max-md:max-w-28 max-md:px-2";
  const hostLink = (n: string, cls: string) => {
    const id = ids.get(n);
    const label = `${n}: ${state ? state.text : "betroffen"}`;
    const inner = (
      <>
        {state ? (
          <span className={state.tone}>
            <Icon name={state.icon} size={12} />
          </span>
        ) : null}
        <span className="truncate">{n}</span>
      </>
    );
    return id === undefined ? (
      <span className={cls} title={label} aria-label={label}>
        {inner}
      </span>
    ) : (
      <Link href={`/hosts/${id}`} className={cls} title={label} aria-label={label}>
        {inner}
      </Link>
    );
  };
  const rest = affectedHosts(c) - all.length;
  return (
    <ul className="m-0 flex list-none flex-nowrap items-center gap-1 p-0" aria-label="Betroffene Hosts">
      {names.map((n) => (
        <li key={n} className="min-w-0">{hostLink(n, chip)}</li>
      ))}
      {all.length > names.length || more > 0 ? (
        <li>
          <Popover
            label={`Alle betroffenen Hosts von ${c.id}`}
            width={240}
            trigger={(t) => (
              <button
                type="button"
                ref={t.ref}
                aria-haspopup={t["aria-haspopup"]}
                aria-expanded={t["aria-expanded"]}
                aria-controls={t["aria-controls"]}
                title={`${more} weitere Hosts anzeigen`}
                onClick={t.toggle}
                className="inline-flex h-(--chip-h) items-center justify-center rounded-xs px-1.5 text-xs text-fg2 hover:text-fg max-md:min-h-11 max-md:min-w-11 max-md:px-3"
              >
                +{more}
                <span className="sr-only"> weitere Hosts</span>
              </button>
            )}
          >
            <ul className="m-0 flex list-none flex-col gap-1 p-0 text-xs">
              {all.map((n) => (
                <li key={n}>{hostLink(n, "inline-flex min-h-7 items-center gap-1.5 text-sm no-underline hover:underline max-md:min-h-11")}</li>
              ))}
              {rest > 0 ? <li className="text-fg3">und {rest} weitere (siehe Host-Liste)</li> : null}
            </ul>
          </Popover>
        </li>
      ) : null}
    </ul>
  );
}

export default function CvesPage() {
  return (
    <Suspense fallback={<TableSkeleton what="CVEs" />}>
      <CveView />
    </Suspense>
  );
}

/** Spaltenüberschrift mit Sortierung: Pfeil zeigt die Richtung der aktiven Spalte. */
function SortTh({ label, hint, active, dir, onClick, className }: { label: string; hint?: string; active: boolean; dir: "asc" | "desc"; onClick: () => void; className?: string }) {
  return (
    <th scope="col" className={className} aria-sort={active ? (dir === "asc" ? "ascending" : "descending") : undefined}>
      <span className="th-pad">
        <button type="button" onClick={onClick} className="inline-flex min-h-7 items-center gap-1 font-semibold max-md:min-h-11">
          {label}
          {/* ↑ = höchster Wert / neuestes zuerst, ↓ = niedrigster / ältestes zuerst; inaktive Spalten zeigen den Pfeil blass */}
          <span aria-hidden="true" className={`inline-block w-3 text-center ${active ? "" : "text-fg3"}`}>{active && dir === "asc" ? "↓" : "↑"}</span>
          {hint ? <span className="sr-only">{hint}</span> : null}
        </button>
      </span>
    </th>
  );
}
