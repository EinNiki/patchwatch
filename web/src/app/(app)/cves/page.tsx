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
import { affectedHosts, affectingShort, filterDeviations, hostChips, hostState, statParts, listStats, parseAffectsAll, parseSort, updatedTitle } from "@/lib/cveList";
import { absTime, relTime } from "@/lib/format";
import { useRowLink } from "@/lib/rowLink";
import { useFlash } from "@/lib/useFlash";
import { toast } from "@/lib/toastStore";
import { Button, Field, TextInput } from "@/components/Controls";
import { Dialog } from "@/components/Dialog";
import { ChipLegend, DistroChip } from "@/components/DistroChip";
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
  const [pendingIds, setPendingIds] = useState<ReadonlySet<string>>(new Set());
  const [watching, setWatching] = useState(false);
  const [watchKey, setWatchKey] = useState(0);
  const searchRef = useRef<HTMLInputElement>(null);

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
  const scopeCount = useApi<{ affecting: number; mine: number; all: number }>(`/cves/scope-count?${countQs}`, 60_000, ["host_cve_status", "report_received"], undefined, { keepPrevious: true });
  // Sofortige Rückmeldung beim Filtern: die bisherige Liste bleibt stehen und wird abgedunkelt, bis die neue da ist.
  const updating = cves.stale || qInput !== q;
  // Beim ersten Aufbau erscheinen zuerst 30 Zeilen, der Rest folgt in kleinen Schritten: kein langer Task, die Seite
  // reagiert sofort (100 Zeilen auf einmal waren ~100 ms Hauptthread).
  // Sofortige Reaktion auf einen Klick in der Kopfzeile: Solange die neu sortierte Liste vom Server noch unterwegs ist,
  // wird die vorhandene Liste lokal umsortiert (beobachtete CVEs bleiben oben). Die Serverantwort ersetzt sie danach.
  const sortedRows = (() => {
    const rows = cves.data ?? [];
    if (!cves.stale) return rows;
    const val = (c: CveListItem) =>
      sort === "level" ? c.level : sort === "hosts" ? affectedHosts(c) : Date.parse((sort === "updated" ? c.updated_at : c.published_at) ?? "") || 0;
    const sign = dir === "asc" ? 1 : -1;
    return [...rows].sort((a, b) => Number(b.watched) - Number(a.watched) || sign * (val(a) - val(b)) || (sort === "hosts" ? b.level - a.level : 0) || b.id.localeCompare(a.id));
  })();
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
  const deviations = filterDeviations({ affectsAll, distro, debianFix, ubuntuFix });
  const flashed = useFlash(
    cves.data,
    (c) => c.id,
    (c) => `${c.watched}|${c.hosts_vulnerable}|${c.hosts_fix_pending}|${c.hosts_unknown}|${c.updated_at}|${c.distros.map((d) => `${d.source}${d.release}${d.status}`).join(",")}`,
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

  /** Setzt eine CVE auf die Watchlist. Fehler meldet der API-Client als Toast; Rückgabe: ob es geklappt hat. */
  async function watchId(id: string, note?: string): Promise<boolean> {
    try {
      await api.put(`/watchlist/${id}`, note ? { note } : {}, { what: "CVE konnte nicht zur Watchlist hinzugefügt werden" });
      toast.success(`${id} zur Watchlist hinzugefügt.`);
      await cves.reload();
      return true;
    } catch {
      return false;
    }
  }

  // „/“ springt ins Suchfeld (nicht, solange man schon in einem Eingabefeld tippt).
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== "/" || e.ctrlKey || e.metaKey || e.altKey) return;
      const t = e.target as HTMLElement | null;
      if (t && (t.closest("input, textarea, select, [contenteditable=true]") || t.closest("dialog"))) return;
      e.preventDefault();
      searchRef.current?.focus();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const stats = cves.data ? listStats(cves.data) : null;
  const truncated = (cves.data?.length ?? 0) >= limit && (scopeCount.data?.affecting ?? 0) > (stats?.affecting ?? 0);
  const chips: { key: string; label: string; remove: () => void }[] = [];
  // Leerer Standard („Meine Hosts“ ohne weitere Filter): freundlicher Hinweis statt „Keine passenden CVEs“.
  const noOtherFilter = !onlyWatch && q.trim() === "" && !distro && !debianFix && !ubuntuFix;
  const onlyMineEmpty = cves.data?.length === 0 && !affectsAll && noOtherFilter;
  // „Alle“ ohne weitere Filter und trotzdem leer: es gibt noch gar keine CVE-Daten.
  const noDataAtAll = cves.data?.length === 0 && affectsAll && noOtherFilter;
  if (distro) chips.push({ key: "distro", label: `Distribution: ${distro === "debian" ? "Debian" : "Ubuntu"}`, remove: () => setParam("distro", null) });
  if (debianFix) chips.push({ key: "debian", label: `Debian: ${FIX_LABEL[debianFix]}`, remove: () => setParam("debian", null) });
  if (ubuntuFix) chips.push({ key: "ubuntu", label: `Ubuntu: ${FIX_LABEL[ubuntuFix]}`, remove: () => setParam("ubuntu", null) });
  if (affectsAll) chips.push({ key: "affects", label: "Betrifft: Alle", remove: () => setParam("affects", null) });
  const resetAll = () => {
    setQInput("");
    router.replace(pathname, { scroll: false });
  };

  const qId = qInput.trim().toUpperCase();
  const suggest = CVE_RE.test(qId) && cves.data && !cves.stale && qInput.trim() === q.trim() && !cves.data.some((c) => c.id === qId) ? qId : null;
  const totalLabel = scopeCount.data ? scopeCount.data.all : null;
  const parts = stats ? statParts(stats) : [];
  // Suchfeld wie die Knöpfe der Leiste: 32 px, mobil 44 px (die Knöpfe kommen aus Controls.tsx).
  const SEARCH_H = "h-8 min-h-8 max-md:h-11 max-md:min-h-11";

  return (
    <>
      <header className="mb-3 border-b border-line pb-3">
        <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
          <h1 className="text-xl font-semibold">CVEs</h1>
          <p className="m-0 text-sm text-fg3" data-testid="affects-count">
            {scopeCount.data ? (
              <>
                {affectingShort(scopeCount.data.affecting)}
                {totalLabel !== null ? ` · ${totalLabel.toLocaleString("de-DE")} insgesamt` : ""}
              </>
            ) : (
              "CVEs werden gezählt …"
            )}
          </p>
        </div>
        {/* Kennzahlen: nur Anzeige, aus den geladenen Zeilen berechnet (deckungsgleich mit der Tabelle), Nullwerte entfallen. */}
        {parts.length > 0 ? (
          <p className="m-0 mt-1 text-xs text-fg2" aria-live="polite" data-testid="cve-stats">
            {parts.join(" · ")}
            {truncated ? <span className="text-fg3"> (in den ersten {cves.data?.length} der Liste)</span> : null}
          </p>
        ) : (
          <span data-testid="cve-stats" className="hidden" />
        )}
      </header>
      <FeedSources />

      <section aria-labelledby="wl-h">
        <h2 id="wl-h" className="sr-only">
          CVE-Liste
        </h2>
        <div className="sr-only" role="status" aria-live="polite">{announce}</div>

        {/* Werkzeugleiste: Suche, Filter, Watchlist-Stern, „+ CVE beobachten“; alle gleich hoch (32 px, mobil 44 px). */}
        <div id="cve-filters" role="search" aria-label="CVEs suchen und filtern" className="mb-2 flex flex-wrap items-center gap-2">
          <TextInput
            ref={searchRef}
            type="search"
            aria-label="Suche nach CVE-ID oder Text"
            title="Tastenkürzel: /"
            value={qInput}
            onChange={(e) => setQInput(e.target.value)}
            placeholder="CVE-ID oder Text (Taste /)"
            className={`${SEARCH_H} min-w-0 basis-full md:basis-64 md:flex-1 md:max-w-xl`}
          />
          <Popover
            label="Filter"
            width={300}
            trigger={(t) => (
              <Button
                ref={t.ref}
                className="min-w-0"
                aria-haspopup={t["aria-haspopup"]}
                aria-expanded={t["aria-expanded"]}
                aria-controls={t["aria-controls"]}
                onClick={t.toggle}
              >
                <NavIcon name="filter" />
                Filter{deviations > 0 ? <span className="tabular-nums" aria-label={`, ${deviations} aktiv`}> {deviations}</span> : null}
              </Button>
            )}
          >
            {(close) => (
              <FilterPanel
                affectsAll={affectsAll}
                debianFix={debianFix}
                ubuntuFix={ubuntuFix}
                deviations={deviations}
                onChange={(k: string, v: string | null) => setParam(k, v)}
                onReset={() => {
                  const p = new URLSearchParams(params.toString());
                  for (const k of ["affects", "distro", "debian", "ubuntu", "split"]) p.delete(k);
                  router.replace(p.toString() ? `${pathname}?${p}` : pathname, { scroll: false });
                }}
                onClose={close}
              />
            )}
          </Popover>
          <Button
            size="icon"
            variant={onlyWatch ? "active" : "default"}
            aria-pressed={onlyWatch}
            aria-label="Nur Watchlist"
            title={onlyWatch ? "Nur Watchlist: an (alle CVEs anzeigen)" : "Nur Watchlist anzeigen"}
            onClick={() => setWatchFilter(!onlyWatch)}
          >
            <NavIcon name={onlyWatch ? "star-fill" : "star"} />
          </Button>
          <Button className="ml-auto min-w-0" onClick={() => { setWatchKey((k) => k + 1); setWatching(true); }}>
            <NavIcon name="plus" />
            CVE beobachten
          </Button>
        </div>

        {chips.length > 0 ? (
          <ul aria-label="Aktive Filter" className="mb-2 flex flex-wrap items-center gap-2">
            {chips.map((c) => (
              <li key={c.key}>
                <button type="button" onClick={c.remove} aria-label={`${c.label} entfernen`} className="inline-flex min-h-7 items-center gap-1.5 rounded-sm border border-line bg-sunk px-2 text-xs text-fg hover:border-control max-md:min-h-11">
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
        {suggest ? (
          <p className="mb-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-sm text-fg2" data-testid="watch-suggest">
            {suggest} steht nicht in der Liste.
            <Button className="min-h-8 min-w-0" onClick={() => void watchId(suggest)}>
              <NavIcon name="star" />
              {suggest} beobachten
            </Button>
          </p>
        ) : null}

        <WatchDialog key={watchKey} open={watching} onClose={() => setWatching(false)} onWatch={watchId} />

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
              <table className="tbl stack dist md:[--tbl-min:45.5rem] xl:[--tbl-min:52.5rem] wide:[--tbl-min:63.5rem]">
                <caption>CVEs mit Distributionen, betroffenen Hosts und Watchlist-Status</caption>
                <thead>
                  <tr>
                    <th scope="col" className="w-[3%] min-w-10"><span className="th-pad"><span className="sr-only">Beobachten</span></span></th>
                    <SortTh className="w-[10%] min-w-36" label="CVE" hint={sort === "latest" ? (dir === "desc" ? "neueste zuerst" : "älteste zuerst") : "nach Datum sortieren"} active={sort === "latest"} dir={dir} onClick={() => sortBy("latest")} />
                    <th scope="col" className="w-[24%] min-w-40"><span className="th-pad">Beschreibung</span></th>
                    <th scope="col" className="w-[15%] min-w-40"><span className="th-pad">Distributionen</span></th>
                    <SortTh className="w-[22%] min-w-56" label="Hosts" hint="nach Anzahl betroffener Hosts sortieren" active={sort === "hosts"} dir={dir} onClick={() => sortBy("hosts")} />
                    <th scope="col" className="w-[8%] min-w-24 max-wide:hidden"><span className="th-pad">Pakete</span></th>
                    <SortTh label="Level" className="w-[6%] min-w-20 max-wide:hidden" active={sort === "level"} dir={dir} onClick={() => sortBy("level")} />
                    <SortTh label="Aktualisiert" className="w-[12%] min-w-28 md:max-xl:hidden" active={sort === "updated"} dir={dir} onClick={() => sortBy("updated")} />
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
  const rowLink = useRowLink(`/cves/${c.id}`);
  return (
      <tr {...rowLink} data-flash={flash ? "" : undefined} data-watched={c.watched ? "" : undefined} data-leaving={hide === "fade" ? "" : undefined}>
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
        <td className="max-md:order-0 max-md:flex-[1_0_100%]">
          {c.description ? <span className="line-clamp-2 max-w-[64rem] [contain:inline-size] max-md:[contain:none]">{c.description}</span> : <span className="text-fg3">Noch nicht in den Feeds</span>}
          {c.note ? <div className="text-xs text-accent">Notiz: {c.note}</div> : null}
        </td>
        <td className="cell-status md:max-w-0 max-md:flex-[1_0_100%]">
          <Distros c={c} />
        </td>
        <td data-label="Hosts" className="md:max-w-0">
          <HostChips c={c} ids={hostIds} />
        </td>
        <td className="max-wide:hidden">
          <PackagesCell c={c} />
        </td>
        <td className="mono max-wide:hidden" title={c.priority ?? undefined}>{c.level ? `${c.level}/10` : "–"}</td>
        <td data-label="Aktualisiert" className="md:max-xl:hidden">
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
        <button type="button" aria-expanded={more} onClick={() => setMore(!more)} className="inline-flex h-(--chip-h) items-center justify-center gap-1.5 whitespace-nowrap rounded-xs border border-line bg-surface px-1.5 text-xs text-fg2 transition-[background-color] duration-(--dur-1) hover:bg-sunk active:bg-sunk max-md:h-auto max-md:min-h-11">
          {more ? "Weniger anzeigen" : `+ ${c.hidden_releases} weitere Releases`}
          <span className="sr-only"> für {c.id}</span>
        </button>
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
    <ul className="m-0 flex min-w-0 list-none flex-nowrap items-center gap-1 p-0" aria-label="Betroffene Hosts">
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
                className="inline-flex h-(--chip-h) min-h-6 min-w-6 shrink-0 whitespace-nowrap items-center justify-center rounded-xs px-1.5 text-xs text-fg2 hover:text-fg max-md:min-h-11 max-md:min-w-11 max-md:px-3"
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

type Choice = { value: string; label: string };

/** Eine Gruppe aus Schaltflächen, von denen genau eine gilt (Radiogruppe). Änderungen wirken sofort. */
function Segmented({ label, value, options, onPick }: { label: string; value: string; options: Choice[]; onPick: (v: string) => void }) {
  return (
    <div role="radiogroup" aria-label={label} className="flex flex-col gap-1">
      <span className="text-xs font-semibold text-fg2">{label}</span>
      <div className="inline-flex overflow-hidden rounded-[3px] border border-control">
        {options.map((o) => {
          const on = o.value === value;
          return (
            <button
              key={o.value}
              type="button"
              role="radio"
              aria-checked={on}
              onClick={() => onPick(o.value)}
              className={`min-h-9 flex-1 px-3 text-sm max-md:min-h-11 ${on ? "bg-accent-soft font-semibold text-accent" : "bg-surface text-fg hover:bg-sunk"}`}
            >
              {o.label}
            </button>
          );
        })}
      </div>
    </div>
  );
}

/** Inhalt des Filter-Popovers: Betrifft, Debian, Ubuntu. Die Auswahl gilt sofort (URL), „Fertig“ schließt nur. */
function FilterPanel({
  affectsAll,
  debianFix,
  ubuntuFix,
  deviations,
  onChange,
  onReset,
  onClose,
}: {
  affectsAll: boolean;
  debianFix: string;
  ubuntuFix: string;
  deviations: number;
  onChange: (key: string, value: string | null) => void;
  onReset: () => void;
  onClose: () => void;
}) {
  const fix: Choice[] = [
    { value: "", label: "Egal" },
    { value: "fixed", label: "gefixt" },
    { value: "open", label: "offen" },
  ];
  return (
    <div className="flex flex-col gap-3 p-3">
      <Segmented
        label="Betrifft"
        value={affectsAll ? "all" : ""}
        options={[{ value: "", label: "Meine Hosts" }, { value: "all", label: "Alle" }]}
        onPick={(v) => onChange("affects", v || null)}
      />
      <Segmented label="Debian" value={debianFix} options={fix} onPick={(v) => onChange("debian", v || null)} />
      <Segmented label="Ubuntu" value={ubuntuFix} options={fix} onPick={(v) => onChange("ubuntu", v || null)} />
      <p className="m-0 text-xs text-fg3">Filter berücksichtigen nur Releases deiner Hosts.</p>
      <div className="flex justify-end gap-2">
        <Button className="min-w-0" onClick={onReset} disabled={deviations === 0}>
          Zurücksetzen
        </Button>
        <Button variant="primary" className="min-w-0" onClick={onClose}>
          Fertig
        </Button>
      </div>
    </div>
  );
}

/** Kleiner Dialog „CVE beobachten“: Formatprüfung, Duplikat-Hinweis, Fehler am Feld, Erfolg als Toast. */
function WatchDialog({ open, onClose, onWatch }: { open: boolean; onClose: () => void; onWatch: (id: string, note?: string) => Promise<boolean> }) {
  const [id, setId] = useState("");
  const [note, setNote] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    const v = id.trim().toUpperCase();
    if (!CVE_RE.test(v)) {
      setErr("Bitte eine CVE-ID im Format CVE-2024-1086 eingeben.");
      return;
    }
    setBusy(true);
    setErr(null);
    try {
      const rows = await api.get<CveListItem[]>(`/cves?${new URLSearchParams({ q: v, affects: "all", limit: "20" })}`);
      if (rows.find((r) => r.id === v)?.watched) {
        setErr(`${v} wird bereits beobachtet.`);
        return;
      }
      if (await onWatch(v, note.trim() || undefined)) onClose();
      else setErr(`${v} konnte nicht hinzugefügt werden (ID unbekannt oder Server nicht erreichbar).`);
    } catch {
      setErr("Die Prüfung ist fehlgeschlagen. Bitte später erneut versuchen.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog open={open} title="CVE beobachten" onClose={onClose}>
      <form onSubmit={submit} noValidate className="flex flex-col gap-3">
        <Field label="CVE-ID">
          <TextInput
            value={id}
            onChange={(e) => {
              setId(e.target.value);
              setErr(null);
            }}
            placeholder="CVE-2024-1086"
            autoComplete="off"
            spellCheck={false}
            aria-invalid={err ? true : undefined}
            aria-describedby={err ? "watch-err" : undefined}
            autoFocus
          />
        </Field>
        {err ? (
          <p id="watch-err" role="alert" className="m-0 text-xs text-crit">
            {err}
          </p>
        ) : null}
        <Field label="Notiz (optional)">
          <TextInput value={note} onChange={(e) => setNote(e.target.value)} maxLength={500} />
        </Field>
        <div className="flex justify-end gap-2">
          <Button type="button" onClick={onClose}>
            Abbrechen
          </Button>
          <Button type="submit" variant="primary" busy={busy}>
            Beobachten
          </Button>
        </div>
      </form>
    </Dialog>
  );
}
