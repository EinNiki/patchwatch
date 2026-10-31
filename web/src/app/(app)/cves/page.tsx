"use client";

import { Suspense, useEffect, useState } from "react";
import Link from "next/link";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { api, ApiError } from "@/lib/api";
import { useApi } from "@/lib/useApi";
import { absTime } from "@/lib/format";
import type { CveDetail, CveListItem, Feed } from "@/lib/types";
import type { StatusInfo } from "@/lib/status";
import { StatusBadge } from "@/components/StatusBadge";
import { Mono } from "@/components/Version";
import { RelTime } from "@/components/RelTime";
import { Empty, ErrorNote } from "@/components/States";
import { TableSkeleton } from "@/components/Skeleton";
import { NavIcon } from "@/components/Icons";
import { useFlash } from "@/lib/useFlash";
import { Button, Field, TextInput } from "@/components/Controls";
import { DistroChip, Marker } from "@/components/DistroChip";
import { PageHeader } from "@/components/PageHeader";

const PAGE = 100;
const CVE_RE = /^CVE-\d{4}-\d{4,7}$/;

const FEED_STATE: Record<Feed["state"], StatusInfo> = {
  ok: { label: "Aktuell", tone: "ok", icon: "ok", rank: 0 },
  stale: { label: "Veraltet", tone: "warn", icon: "clock", rank: 1 },
  never: { label: "Noch nie abgerufen", tone: "unknown", icon: "unknown", rank: 2 },
};

function useDebounced<T>(value: T, ms: number): T {
  const [v, setV] = useState(value);
  useEffect(() => {
    const t = setTimeout(() => setV(value), ms);
    return () => clearTimeout(t);
  }, [value, ms]);
  return v;
}

function FeedPanel() {
  const feeds = useApi<Feed[]>("/feeds", 30_000);
  const [note, setNote] = useState<string | null>(null);
  const [problem, setProblem] = useState<string | null>(null);

  async function refresh() {
    setProblem(null);
    try {
      await api.post("/feeds/refresh");
      setNote("Abruf gestartet. Die Anzeige aktualisiert sich in einigen Sekunden.");
      setTimeout(() => void feeds.reload(), 5000);
      setTimeout(() => void feeds.reload(), 20_000);
    } catch (e) {
      setProblem(e instanceof ApiError && e.status === 409 ? "Ein Abruf läuft bereits." : "Abruf konnte nicht gestartet werden.");
    }
  }

  return (
    <section id="feeds" aria-labelledby="feeds-h" className="mb-6 scroll-mt-4">
      <div className="mb-2 flex flex-wrap items-center gap-x-4 gap-y-2">
        <h2 id="feeds-h" className="text-lg font-semibold">
          CVE-Feeds
        </h2>
        <Button onClick={() => void refresh()}>Jetzt abrufen</Button>
        <span role="status" className="text-fg2">
          {note}
        </span>
      </div>
      {problem ? <ErrorNote message={problem} /> : null}
      {feeds.error && !feeds.data ? <ErrorNote message={feeds.error} /> : null}
      {!feeds.data ? null : feeds.data.length === 0 ? (
        <Empty title="Keine CVE-Quelle konfiguriert">
          Setze <Mono>PATCHWATCH_CVE_SOURCES</Mono> (ubuntu, debian, osv) in der Server-Konfiguration.
        </Empty>
      ) : (
        <div className="max-xl:overflow-x-auto">
          <table className="tbl stack">
            <caption>Zustand der CVE-Feeds</caption>
            <thead>
              <tr>
                <th scope="col"><span className="th-pad">Quelle</span></th>
                <th scope="col"><span className="th-pad">Zustand</span></th>
                <th scope="col"><span className="th-pad">Letzter erfolgreicher Abruf</span></th>
                <th scope="col"><span className="th-pad">Letzter Versuch</span></th>
                <th scope="col"><span className="th-pad">Fehler</span></th>
              </tr>
            </thead>
            <tbody>
              {feeds.data.map((f) => (
                <tr key={f.source}>
                  <td className="cell-primary">
                    <Mono>{f.source}</Mono>
                    {!f.configured ? <span className="ml-2 text-xs text-fg3">nicht aktiv</span> : null}
                  </td>
                  <td className="cell-status lead">
                    <StatusBadge info={FEED_STATE[f.state]} label={f.state === "stale" && f.stale_since ? `Veraltet seit ${absTime(f.stale_since)}` : undefined} />
                  </td>
                  <td data-label="Letzter Erfolg">
                    <RelTime iso={f.last_success_at} />
                    {f.last_success_at ? <div className="text-xs text-fg3 max-md:hidden">{absTime(f.last_success_at)}</div> : null}
                  </td>
                  <td data-label="Letzter Versuch">
                    <RelTime iso={f.last_attempt_at} />
                  </td>
                  <td className="max-w-[28rem] max-md:max-w-none">
                    {f.last_error ? (
                      <span className="text-warn">
                        {f.last_error} <span className="text-fg3">({f.consecutive_failures}× in Folge)</span>
                      </span>
                    ) : (
                      <span className="text-fg3">–</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

function CveView() {
  const router = useRouter();
  const pathname = usePathname();
  const params = useSearchParams();
  const urlQ = params.get("q") ?? "";
  const onlyWatch = params.get("watchlist") === "1";
  const allReleases = params.get("releases") === "all";
  const distro = ["debian", "ubuntu"].includes(params.get("distro") ?? "") ? (params.get("distro") as string) : "";
  const splitRaw = params.get("split") ?? "";
  const split = ["debian_fixed_ubuntu_open", "ubuntu_fixed_debian_open"].includes(splitRaw) ? splitRaw : "";
  const [qInput, setQInput] = useState(urlQ);
  const q = useDebounced(qInput, 300);
  const [limit, setLimit] = useState(PAGE);
  const [newId, setNewId] = useState("");
  const [newNote, setNewNote] = useState("");
  const [formError, setFormError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [filtersOpen, setFiltersOpen] = useState(false);

  const qs = new URLSearchParams({ limit: String(limit) });
  if (onlyWatch) qs.set("watchlist", "true");
  if (q.trim()) qs.set("q", q.trim());
  if (allReleases) qs.set("releases", "all");
  if (distro) qs.set("distro", distro);
  if (split) qs.set("split", split);
  const cves = useApi<CveListItem[]>(`/cves?${qs}`, 60_000, ["host_cve_status", "report_received"]);
  const filtered = onlyWatch || q.trim() !== "" || allReleases || distro !== "" || split !== "";
  const activeFilters = [q.trim(), onlyWatch, allReleases, distro, split].filter(Boolean).length;
  const flashed = useFlash(
    cves.data,
    (c) => c.id,
    (c) => `${c.hosts_vulnerable}|${c.hosts_fix_pending}|${c.hosts_unknown}|${c.updated_at}|${c.distros.map((d) => `${d.source}${d.release}${d.status}`).join(",")}`,
  );

  /** Filter stehen in der URL (teilbar, Zurück-Taste funktioniert). */
  function setParam(key: string, value: string | null) {
    const p = new URLSearchParams(params.toString());
    if (value) p.set(key, value);
    else p.delete(key);
    router.replace(p.toString() ? `${pathname}?${p}` : pathname, { scroll: false });
  }
  const setWatchFilter = (on: boolean) => setParam("watchlist", on ? "1" : null);

  async function toggle(c: CveListItem) {
    setFormError(null);
    try {
      if (c.watched) await api.del(`/watchlist/${c.id}`);
      else await api.put(`/watchlist/${c.id}`);
      await cves.reload();
    } catch {
      setFormError("Watchlist konnte nicht geändert werden.");
    }
  }

  async function add(e: React.FormEvent) {
    e.preventDefault();
    const id = newId.trim().toUpperCase();
    if (!CVE_RE.test(id)) {
      setFormError("Ungültige CVE-ID. Erwartet wird das Format CVE-2024-1086.");
      return;
    }
    setBusy(true);
    setFormError(null);
    try {
      await api.put(`/watchlist/${id}`, newNote.trim() ? { note: newNote.trim() } : {});
      setNewId("");
      setNewNote("");
      await cves.reload();
    } catch {
      setFormError("CVE konnte nicht zur Watchlist hinzugefügt werden.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <PageHeader title="CVEs" count={cves.data ? `${cves.data.length}${cves.data.length >= limit ? "+" : ""} angezeigt` : undefined} />
      <FeedPanel />

      <section aria-labelledby="wl-h">
        <h2 id="wl-h" className="mb-2 text-lg font-semibold">
          Watchlist und CVE-Liste
        </h2>
        <form onSubmit={(e) => void add(e)} className="mb-4 flex flex-wrap items-end gap-3">
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
        {formError ? <ErrorNote message={formError} /> : null}

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
          <label className="flex items-center gap-2 text-xs font-semibold text-fg2 max-md:flex-col max-md:items-stretch max-md:gap-1">
            Stand der Fixes
            <select value={split} onChange={(e) => setParam("split", e.target.value || null)} className="min-h-8 rounded-sm border border-control bg-sunk px-1.5 text-sm font-normal text-fg max-md:min-h-11">
              <option value="">Alle</option>
              <option value="debian_fixed_ubuntu_open">Debian gefixt, Ubuntu offen</option>
              <option value="ubuntu_fixed_debian_open">Ubuntu gefixt, Debian offen</option>
            </select>
          </label>
          <label className="flex min-h-8 items-center gap-2 text-sm max-md:min-h-11">
            <input type="checkbox" checked={onlyWatch} onChange={(e) => setWatchFilter(e.target.checked)} className="size-4 accent-(--accent)" />
            nur Watchlist
          </label>
          <label className="flex min-h-8 items-center gap-2 text-sm max-md:min-h-11">
            <input type="checkbox" checked={allReleases} onChange={(e) => setParam("releases", e.target.checked ? "all" : null)} className="size-4 accent-(--accent)" />
            Alle Releases
          </label>
          {filtered ? (
            <Button
              onClick={() => {
                setQInput("");
                router.replace(pathname, { scroll: false });
              }}
            >
              Filter zurücksetzen
            </Button>
          ) : null}
        </div>

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
                    <th scope="col"><span className="th-pad">CVE</span></th>
                    <th scope="col"><span className="th-pad">Beschreibung</span></th>
                    <th scope="col"><span className="th-pad">Distributionen</span></th>
                    <th scope="col"><span className="th-pad">Hosts</span></th>
                    <th scope="col" className="max-wide:hidden"><span className="th-pad">Prio</span></th>
                    <th scope="col" className="md:max-xl:hidden"><span className="th-pad">Aktualisiert</span></th>
                    <th scope="col"><span className="th-pad">Watchlist</span></th>
                  </tr>
                </thead>
                <tbody>
                  {cves.data.map((c) => (
                    <tr key={c.id} data-flash={flashed.has(c.id) ? "" : undefined}>
                      <td className="cell-primary">
                        <Link href={`/cves/${c.id}`} className="mono whitespace-nowrap font-medium">
                          {c.id}
                        </Link>
                        {c.watched ? (
                          <span className="ml-2 inline-flex align-middle">
                            <Marker>Watchlist</Marker>
                          </span>
                        ) : null}
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
                      <td>
                        <Button aria-pressed={c.watched} onClick={() => void toggle(c)} aria-label={`${c.id} ${c.watched ? "von der Watchlist entfernen" : "beobachten"}`}>
                          {c.watched ? "Entfernen" : "Beobachten"}
                        </Button>
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
