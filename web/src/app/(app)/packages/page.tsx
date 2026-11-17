"use client";

import { useState } from "react";
import { useApi } from "@/lib/useApi";
import { useDebounced } from "@/lib/useDebounced";
import { PageHeader } from "@/components/PageHeader";
import { Button } from "@/components/Controls";
import { FilterGroup } from "@/components/FilterGroup";
import { Icon } from "@/components/Icons";
import { SortHead } from "@/components/SortHead";
import { Empty, ErrorNote, Loading } from "@/components/States";
import { Mono } from "@/components/Version";
import { filterQuery, type PackageFilter } from "@/lib/packages";
import type { PackageOverviewRow } from "@/lib/types";

const PAGE = 50;
type SortKey = "name" | "hosts" | "versions" | "updates" | "security";

const FILTER_OPTIONS = [
  { id: "all", label: "Alle" },
  { id: "updates", label: "Nur mit Update" },
  { id: "security", label: "Nur Sicherheit" },
] as const;

/** Pakete über alle Hosts: auf wie vielen Hosts installiert, wie viele mit Update, wie verstreut die Versionen sind. */
export default function PackagesPage() {
  const [filter, setFilter] = useState<PackageFilter>("updates");
  const [text, setText] = useState("");
  const q = useDebounced(text.trim(), 250);
  const [sort, setSort] = useState<{ key: SortKey; dir: "asc" | "desc" }>({ key: "security", dir: "desc" });
  const [limit, setLimit] = useState(PAGE);
  const path = `/packages?sort=${sort.key}&dir=${sort.dir}&limit=${limit}${filterQuery(filter)}${q ? `&q=${encodeURIComponent(q)}` : ""}`;
  const list = useApi<{ items: PackageOverviewRow[]; total: number }>(path, 0, ["report_received"], undefined, { keepPrevious: true });
  const reset = () => setLimit(PAGE);
  const sortBy = (key: SortKey) => {
    setSort((s) => (s.key === key ? { key, dir: s.dir === "asc" ? "desc" : "asc" } : { key, dir: key === "name" ? "asc" : "desc" }));
    reset();
  };
  const head = (key: SortKey, label: string, num = false) => <SortHead label={label} num={num} active={sort.key === key} dir={sort.dir} onSort={() => sortBy(key)} />;
  const rows = list.data?.items ?? [];
  const rest = (list.data?.total ?? 0) - rows.length;

  return (
    <>
      <PageHeader
        title="Pakete"
        count={list.data ? list.data.total.toLocaleString("de-DE") : undefined}
        description="Installierte Pakete aller Hosts. Updates stammen aus den Paketlisten auf den Hosts; patchwatch führt nie ein Update aus."
      />
      <div className="mb-2 flex flex-wrap items-center gap-2">
        <label className="flex max-w-full items-center gap-2 text-xs text-fg2">
          <span className="sr-only">Pakete aller Hosts durchsuchen</span>
          <input
            type="search"
            value={text}
            onChange={(e) => {
              setText(e.target.value);
              reset();
            }}
            placeholder="Paketname suchen"
            aria-label="Pakete aller Hosts durchsuchen"
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
      {list.error && !list.data ? <ErrorNote message={list.error} /> : null}
      {!list.data ? (
        list.error ? null : <Loading what="Pakete" />
      ) : rows.length === 0 ? (
        <Empty title={filter === "all" || q ? "Keine Pakete gefunden" : "Keine offenen Updates"}>
          {filter === "all" || q ? "Für diese Suche gibt es keine Treffer." : "Auf keinem Host ist ein Paket-Update offen."}
        </Empty>
      ) : (
        <div className="@container/tbl max-lg:overflow-x-auto">
          <table className="tbl stack">
            <caption>Pakete über alle Hosts</caption>
            <thead>
              <tr>
                {head("name", "Paket")}
                {head("hosts", "Hosts", true)}
                {head("versions", "Versionen", true)}
                {head("updates", "Mit Update", true)}
                {head("security", "Sicherheit", true)}
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.name}>
                  <td className="cell-primary">
                    <Mono>{r.name}</Mono>
                  </td>
                  <td data-label="Hosts" className="num">{r.hosts}</td>
                  <td data-label="Versionen" className="num">{r.versions > 1 ? r.versions : <span className="text-fg3">{r.versions}</span>}</td>
                  <td data-label="Mit Update" className="num">{r.updates > 0 ? r.updates : <span className="text-fg3">0</span>}</td>
                  <td data-label="Sicherheit" className="num">
                    {r.security > 0 ? (
                      <span className="inline-flex items-center gap-1 font-semibold text-crit">
                        <Icon name="crit" size={14} />
                        {r.security}
                      </span>
                    ) : (
                      <span className="text-fg3">0</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {rest > 0 ? (
            <Button variant="ghost" onClick={() => setLimit((l) => l + PAGE)} className="mt-1">
              {rest.toLocaleString("de-DE")} weitere anzeigen
            </Button>
          ) : null}
        </div>
      )}
    </>
  );
}
