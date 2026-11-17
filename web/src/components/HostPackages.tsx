"use client";

import { useState } from "react";
import { useApi } from "@/lib/useApi";
import { useDebounced } from "@/lib/useDebounced";
import { Button } from "@/components/Controls";
import { Icon } from "@/components/Icons";
import { FilterGroup } from "@/components/FilterGroup";
import { SortHead } from "@/components/SortHead";
import { SectionHeader } from "@/components/PageHeader";
import { Empty, ErrorNote, Loading } from "@/components/States";
import { Mono } from "@/components/Version";
import { RelTime } from "@/components/RelTime";
import { KIND_LABEL, filterQuery, listNotice, listsAge, type PackageFilter } from "@/lib/packages";
import type { PackageRow, PackagesResponse } from "@/lib/types";

const PAGE = 50;
type SortKey = "name" | "installed" | "candidate" | "origin" | "security";

const FILTER_OPTIONS = [
  { id: "updates", label: "Nur mit Update" },
  { id: "security", label: "Nur Sicherheit" },
  { id: "all", label: "Alle" },
] as const;

/** Reiter „Pakete“ der Host-Seite: Zähler, Suche, Filter und die Tabelle der installierten und ausstehenden Pakete. */
export function HostPackages({ hostId, initialFilter }: { hostId: number; initialFilter: PackageFilter }) {
  const [filter, setFilter] = useState<PackageFilter>(initialFilter);
  const [text, setText] = useState("");
  const q = useDebounced(text.trim(), 250);
  const [sort, setSort] = useState<{ key: SortKey; dir: "asc" | "desc" }>({ key: "security", dir: "desc" });
  const [limit, setLimit] = useState(PAGE);

  const path = `/hosts/${hostId}/packages?sort=${sort.key}&dir=${sort.dir}&limit=${limit}${filterQuery(filter)}${q ? `&q=${encodeURIComponent(q)}` : ""}`;
  const list = useApi<PackagesResponse>(path, 0, ["report_received"], undefined, { keepPrevious: true });
  const head = list.data?.host;
  const age = listsAge(head?.apt_lists_updated_at ?? null);
  const notice = head ? listNotice(head) : null;

  const reset = () => setLimit(PAGE);
  const sortBy = (key: SortKey) => {
    setSort((s) => (s.key === key ? { key, dir: s.dir === "asc" ? "desc" : "asc" } : { key, dir: key === "security" ? "desc" : "asc" }));
    reset();
  };

  return (
    <section aria-labelledby="pkg-h" className="min-w-0">
      <SectionHeader id="pkg-h" title="Pakete" />
      {list.error && !list.data ? <ErrorNote message={list.error} /> : null}
      {head ? (
        <dl className="mb-3 flex flex-wrap gap-x-6 gap-y-1 text-sm" aria-label="Zusammenfassung der Pakete">
          <Fact label="Updates offen" value={head.updates.toLocaleString("de-DE")} />
          <Fact
            label="davon Sicherheit"
            value={
              <span className={head.security > 0 ? "font-semibold text-crit" : ""}>
                {head.security > 0 ? <Icon name="crit" size={14} /> : null} {head.security.toLocaleString("de-DE")}
              </span>
            }
          />
          <Fact label="Installiert" value={head.installed.toLocaleString("de-DE")} />
          <Fact
            label="Paketlisten (apt)"
            value={
              <span className={age.stale ? "font-semibold text-warn" : ""}>
                {age.stale ? <Icon name="warn" size={14} /> : null} {age.text}
              </span>
            }
          />
          {head.packages_updated_at ? <Fact label="Liste gemeldet" value={<RelTime iso={head.packages_updated_at} />} /> : null}
        </dl>
      ) : null}
      {age.stale ? (
        <p role="note" className="mb-2 text-sm text-fg2">
          Die Paketlisten auf dem Host sind alt: Neue Updates erscheinen erst nach <Mono>apt update</Mono> auf dem Host. patchwatch führt das nie selbst aus.
        </p>
      ) : null}
      {notice ? (
        <p role="note" className="mb-2 flex items-start gap-2 text-sm text-fg2">
          <span className="mt-0.5 text-warn">
            <Icon name="warn" size={14} />
          </span>
          {notice}
        </p>
      ) : null}

      <div className="mb-2 flex flex-wrap items-center gap-2">
        <label className="flex max-w-full items-center gap-2 text-xs text-fg2">
          <span className="sr-only">Pakete dieses Hosts durchsuchen</span>
          <input
            type="search"
            value={text}
            onChange={(e) => {
              setText(e.target.value);
              reset();
            }}
            placeholder="Paketname suchen"
            aria-label="Pakete dieses Hosts durchsuchen"
            className="min-h-8 w-64 max-w-full rounded-[3px] border border-control bg-sunk px-2 py-1 text-sm text-fg placeholder:text-fg3 max-md:min-h-11"
          />
        </label>
        <FilterGroup
          label="Paketfilter"
          options={FILTER_OPTIONS}
          value={filter}
          onChange={(f) => {
            setFilter(f);
            reset();
          }}
        />
      </div>

      {!list.data ? (
        <Loading what="Pakete" />
      ) : list.data.items.length === 0 ? (
        <Empty title={filter === "updates" && !q ? "Keine offenen Updates" : "Keine Pakete gefunden"}>
          {filter === "updates" && !q ? "Die zuletzt gemeldeten Daten enthalten keine Paket-Updates." : "Für diese Suche und diesen Filter gibt es keine Treffer."}
        </Empty>
      ) : (
        <PackageTable rows={list.data.items} total={list.data.total} sort={sort} onSort={sortBy} onMore={() => setLimit((l) => l + PAGE)} />
      )}
    </section>
  );
}

function Fact({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex items-baseline gap-1.5">
      <dt className="text-fg3">{label}</dt>
      <dd className="tabular-nums">{value}</dd>
    </div>
  );
}

function KindChip({ row }: { row: PackageRow }) {
  if (!row.kind) return null;
  return (
    <span className="inline-flex items-center gap-1 text-xs text-fg2">
      {row.security ? (
        <span className="inline-flex items-center gap-1 font-semibold text-crit">
          <Icon name="crit" size={14} />
          Sicherheit
        </span>
      ) : null}
      {row.kind !== "upgrade" ? <span className="rounded-xs border border-line px-1">{KIND_LABEL[row.kind]}</span> : null}
    </span>
  );
}

function PackageTable({ rows, total, sort, onSort, onMore }: { rows: PackageRow[]; total: number; sort: { key: SortKey; dir: "asc" | "desc" }; onSort: (k: SortKey) => void; onMore: () => void }) {
  const head = (key: SortKey, label: string) => <SortHead label={label} active={sort.key === key} dir={sort.dir} onSort={() => onSort(key)} />;
  const rest = total - rows.length;
  return (
    <div className="@container/tbl max-lg:overflow-x-auto">
      <table className="tbl stack">
        <caption>Pakete dieses Hosts ({total.toLocaleString("de-DE")} Treffer)</caption>
        <thead>
          <tr>
            {head("name", "Paket")}
            {head("installed", "Installiert")}
            {head("candidate", "Verfügbar")}
            {head("origin", "Herkunft")}
            {head("security", "Hinweis")}
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.name}>
              <td className="cell-primary">
                <Mono>{r.name}</Mono>
                {r.arch ? <span className="ml-2 text-xs text-fg3">{r.arch}</span> : null}
              </td>
              <td data-label="Installiert">{r.installed ? <Mono className="text-fg2">{r.installed}</Mono> : <span className="text-fg3">nicht installiert</span>}</td>
              <td data-label="Verfügbar">{r.candidate ? <Mono>{r.candidate}</Mono> : <span className="text-fg3">–</span>}</td>
              <td data-label="Herkunft" className="text-fg2">
                {r.origin || <span className="text-fg3">–</span>}
              </td>
              <td data-label="Hinweis" className="cell-status">
                <KindChip row={r} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {rest > 0 ? (
        <Button variant="ghost" onClick={onMore} className="mt-1">
          {rest.toLocaleString("de-DE")} weitere anzeigen
        </Button>
      ) : null}
    </div>
  );
}
