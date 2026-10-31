"use client";

import { Suspense, useEffect, useState } from "react";
import Link from "next/link";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { api } from "@/lib/api";
import { prefetchApi, useApi } from "@/lib/useApi";
import type { CveDetail, CveListItem } from "@/lib/types";
import { RelTime } from "@/components/RelTime";
import { Empty, ErrorNote } from "@/components/States";
import { TableSkeleton } from "@/components/Skeleton";
import { NavIcon } from "@/components/Icons";
import { useFlash } from "@/lib/useFlash";
import { Button, Field, TextInput } from "@/components/Controls";
import { DistroChip } from "@/components/DistroChip";
import { PageHeader } from "@/components/PageHeader";
import { FeedSources } from "@/components/FeedSources";

const PAGE = 100;
const CVE_RE = /^CVE-\d{4}-\d{4,7}$/;

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
  const allReleases = params.get("releases") === "all";
  const distro = ["debian", "ubuntu"].includes(params.get("distro") ?? "") ? (params.get("distro") as string) : "";
  // Alt-URLs mit `split=` werden auf die beiden Distro-Filter abgebildet.
  const splitRaw = params.get("split") ?? "";
  const legacy = LEGACY_SPLIT[splitRaw];
  const debianFix = fixParam(params.get("debian")) || legacy?.debian || "";
  const ubuntuFix = fixParam(params.get("ubuntu")) || legacy?.ubuntu || "";
  const [qInput, setQInput] = useState(urlQ);
  const q = useDebounced(qInput, 300);
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
  if (allReleases) qs.set("releases", "all");
  if (distro) qs.set("distro", distro);
  if (debianFix) qs.set("debian", debianFix);
  if (ubuntuFix) qs.set("ubuntu", ubuntuFix);
  const cves = useApi<CveListItem[]>(`/cves?${qs}`, 60_000, ["host_cve_status", "report_received"]);
  const filtered = onlyWatch || q.trim() !== "" || allReleases || distro !== "" || debianFix !== "" || ubuntuFix !== "";
  const activeFilters = [q.trim(), onlyWatch, allReleases, distro, debianFix, ubuntuFix].filter(Boolean).length;
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
    if (allReleases) rowQs.set("releases", "all");
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
    cves.mutate((list) => list.map((x) => (x.id === c.id ? { ...x, watched: want } : x)));
    try {
      if (want) await api.put(`/watchlist/${c.id}`);
      else await api.del(`/watchlist/${c.id}`);
      if (onlyWatch && !want) cves.mutate((list) => list.filter((x) => x.id !== c.id));
      else await refreshRow(c.id).catch(() => undefined);
    } catch {
      cves.mutate((list) => list.map((x) => (x.id === c.id ? { ...x, watched: c.watched } : x)));
      setNotice(`${c.id}: Die Watchlist konnte nicht geändert werden. Der Stand wurde zurückgesetzt.`);
    } finally {
      setPendingIds((s) => {
        const n = new Set(s);
        n.delete(c.id);
        return n;
      });
    }
  }

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
      await api.put(`/watchlist/${id}`, newNote.trim() ? { note: newNote.trim() } : {});
      setNewId("");
      setNewNote("");
      await cves.reload();
    } catch {
      setNotice("CVE konnte nicht zur Watchlist hinzugefügt werden.");
    } finally {
      setBusy(false);
    }
  }

  const chips: { key: string; label: string; remove: () => void }[] = [];
  if (q.trim()) chips.push({ key: "q", label: `Suche: ${q.trim()}`, remove: () => { setQInput(""); setParam("q", null); } });
  if (distro) chips.push({ key: "distro", label: `Distribution: ${distro === "debian" ? "Debian" : "Ubuntu"}`, remove: () => setParam("distro", null) });
  if (debianFix) chips.push({ key: "debian", label: `Debian: ${FIX_LABEL[debianFix]}`, remove: () => setParam("debian", null) });
  if (ubuntuFix) chips.push({ key: "ubuntu", label: `Ubuntu: ${FIX_LABEL[ubuntuFix]}`, remove: () => setParam("ubuntu", null) });
  if (onlyWatch) chips.push({ key: "watchlist", label: "Nur Watchlist", remove: () => setWatchFilter(false) });
  if (allReleases) chips.push({ key: "releases", label: "Alle Releases", remove: () => setParam("releases", null) });
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
        <details className="mb-3 border-y border-line">
          <summary className="flex min-h-9 cursor-pointer items-center gap-2 font-semibold text-fg2 max-md:min-h-11">Watchlist: CVE hinzufügen</summary>
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
        </details>
        <div role="status">{notice ? <ErrorNote message={notice} /> : null}</div>

        <div className="mb-3 md:hidden">
          <Button aria-expanded={filtersOpen} aria-controls="cve-filters" onClick={() => setFiltersOpen((o) => !o)}>
            <NavIcon name="filter" />
            Filter{activeFilters ? ` (${activeFilters})` : ""}
          </Button>
        </div>
        <div id="cve-filters" className={`mb-3 mt-2 flex-wrap items-center gap-x-4 gap-y-2 max-md:flex-col max-md:items-stretch ${filtersOpen ? "flex" : "max-md:hidden md:flex"}`}>
          <label className="flex items-center gap-2 text-xs font-semibold text-fg2 max-md:flex-col max-md:items-stretch max-md:gap-1">
            Suche
            <TextInput type="search" value={qInput} onChange={(e) => setQInput(e.target.value)} placeholder="CVE-ID oder Text" className="w-64 max-w-full font-normal max-md:w-full" />
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
            <input type="checkbox" checked={onlyWatch} onChange={(e) => setWatchFilter(e.target.checked)} className="size-4 accent-(--accent)" />
            nur Watchlist
          </label>
          <label className="flex min-h-8 items-center gap-2 text-sm max-md:min-h-11">
            <input type="checkbox" checked={allReleases} onChange={(e) => setParam("releases", e.target.checked ? "all" : null)} className="size-4 accent-(--accent)" />
            Alle Releases
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

        {cves.error && !cves.data ? <ErrorNote message={cves.error} /> : null}
        {!cves.data ? (
          <TableSkeleton what="CVEs" />
        ) : cves.data.length === 0 ? (
          <Empty title={filtered ? "Keine passenden CVEs" : "Noch keine CVE-Daten"}>
            {filtered ? (
              "Ändere die Suche oder die Filter. Ohne „Alle Releases“ zählen nur Releases, die auf deinen Hosts laufen."
            ) : (
              <>
                Sobald ein Feed erfolgreich abgerufen wurde, erscheinen die CVEs hier. Prüfe den Feed-Zustand oben oder rufe die Feeds mit „Jetzt
                abrufen“ ab.
              </>
            )}
          </Empty>
        ) : (
          <>
            <div className="max-lg:overflow-x-auto">
              <table className="tbl stack">
                <caption>CVEs mit Distributionen, betroffenen Hosts und Watchlist-Status</caption>
                <thead>
                  <tr>
                    <th scope="col" className="w-10"><span className="th-pad"><span className="sr-only">Beobachten</span></span></th>
                    <th scope="col"><span className="th-pad">CVE</span></th>
                    <th scope="col"><span className="th-pad">Beschreibung</span></th>
                    <th scope="col"><span className="th-pad">Distributionen</span></th>
                    <th scope="col"><span className="th-pad">Hosts</span></th>
                    <th scope="col" className="max-wide:hidden"><span className="th-pad">Prio</span></th>
                    <th scope="col" className="md:max-xl:hidden"><span className="th-pad">Aktualisiert</span></th>
                  </tr>
                </thead>
                <tbody>
                  {cves.data.map((c) => (
                    <tr key={c.id} data-flash={flashed.has(c.id) ? "" : undefined} data-watched={c.watched ? "" : undefined}>
                      <td className="cell-star">
                        <button
                          type="button"
                          className="star-btn"
                          data-on={c.watched ? "" : undefined}
                          onClick={() => void toggle(c)}
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
                        {c.exploited ? <div className="text-xs font-semibold text-crit">Aktiv ausgenutzt (CISA KEV)</div> : null}
                        {c.priority ? <div className="text-xs text-fg3 wide:hidden">Priorität {c.priority}</div> : null}
                      </td>
                      <td className="w-full min-w-24 max-md:order-0 max-md:flex-[1_0_100%]">
                        {c.description ? <span className="line-clamp-2 max-w-[44rem] [contain:inline-size] max-md:[contain:none]">{c.description}</span> : <span className="text-fg3">Noch nicht in den Feeds</span>}
                        {c.note ? <div className="text-xs text-accent">Notiz: {c.note}</div> : null}
                      </td>
                      <td className="cell-status min-w-[12rem] max-md:min-w-0 max-md:flex-[1_0_100%]">
                        <Distros c={c} allReleases={allReleases} />
                      </td>
                      <td data-label="Hosts">
                        <HostCounts c={c} />
                      </td>
                      <td className="mono max-wide:hidden">{c.priority ?? "–"}</td>
                      <td data-label="Aktualisiert" className="whitespace-nowrap md:max-xl:hidden">
                        <RelTime iso={c.updated_at} />
                      </td>
                    </tr>
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
          Details zur Bewertung je Host stehen in der Host-Ansicht (<Link href="/">Hosts</Link>). Gestrichelte Chips zeigen Releases, die auf keinem deiner Hosts laufen.
        </p>
      </section>
    </>
  );
}

/** Chips der Releases, die auf Hosts laufen; weitere Releases lädt „+ n weitere“ bei Bedarf nach. */
function Distros({ c, allReleases }: { c: CveListItem; allReleases: boolean }) {
  const [more, setMore] = useState(false);
  const detail = useApi<CveDetail>(more ? `/cves/${c.id}` : null);
  const others = detail.data?.distros.filter((d) => !d.mine) ?? [];
  if (c.distros.length === 0 && c.hidden_releases === 0) return <span className="text-fg3">keine Quellendaten</span>;
  return (
    <div className="flex flex-col items-start gap-1 max-md:flex-row max-md:flex-wrap wide:flex-row wide:flex-wrap">
      {c.distros.length === 0 ? <span className="text-fg3">Kein Release auf deinen Hosts</span> : null}
      {c.distros.map((d) => (
        <DistroChip key={`${d.source}/${d.release}`} d={d} />
      ))}
      {more ? others.map((d) => <DistroChip key={`${d.source}/${d.release}`} d={d} />) : null}
      {!allReleases && c.hidden_releases > 0 ? (
        <Button aria-expanded={more} onClick={() => setMore(!more)} className="!h-(--chip-h) !min-h-(--chip-h) !rounded-xs !border-line !px-1.5 !py-0 !text-xs !font-normal !text-fg2 max-md:!min-h-11">
          {more ? "Weniger anzeigen" : `+ ${c.hidden_releases} weitere Releases`}
          <span className="sr-only"> für {c.id}</span>
        </Button>
      ) : null}
      {more && detail.error ? <span className="text-crit">{detail.error}</span> : null}
    </div>
  );
}

function HostCounts({ c }: { c: CveListItem }) {
  const parts = [
    c.hosts_vulnerable > 0 && <span key="v" className="whitespace-nowrap font-semibold text-crit">{c.hosts_vulnerable} verwundbar</span>,
    c.hosts_fix_pending > 0 && <span key="p" className="whitespace-nowrap text-warn">{c.hosts_fix_pending} Fix angekündigt</span>,
    c.hosts_unknown > 0 && <span key="u" className="whitespace-nowrap text-unknown">{c.hosts_unknown} unbekannt</span>,
  ].filter(Boolean);
  if (parts.length === 0) return <span className="text-fg3">keine betroffenen Hosts</span>;
  return <div className="flex flex-col gap-0.5 max-md:flex-row max-md:flex-wrap max-md:gap-x-2">{parts}</div>;
}

export default function CvesPage() {
  return (
    <Suspense fallback={<TableSkeleton what="CVEs" />}>
      <CveView />
    </Suspense>
  );
}
