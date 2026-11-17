"use client";

import Link from "next/link";
import { useState } from "react";
import { useApi } from "@/lib/useApi";
import { useDebounced } from "@/lib/useDebounced";
import { PageHeader } from "@/components/PageHeader";
import { Button } from "@/components/Controls";
import { ContainerVerdict } from "@/components/ContainerVerdict";
import { FilterGroup } from "@/components/FilterGroup";
import { Empty, ErrorNote, Loading } from "@/components/States";
import { Mono } from "@/components/Version";
import type { ContainersOverview } from "@/lib/types";

const PAGE = 50;
const FILTERS = [
  { id: "all", label: "Alle" },
  { id: "updates", label: "Nur mit Update" },
] as const;
type Filter = (typeof FILTERS)[number]["id"];

/** Container über alle Hosts, nach Image gruppiert (Images mit neuerem Stand zuerst). Nur Anzeige. */
export default function ContainersPage() {
  const [filter, setFilter] = useState<Filter>("all");
  const [text, setText] = useState("");
  const q = useDebounced(text.trim(), 250);
  const [limit, setLimit] = useState(PAGE);
  const path = `/containers?limit=${limit}${filter === "updates" ? "&update=1" : ""}${q ? `&q=${encodeURIComponent(q)}` : ""}`;
  const list = useApi<ContainersOverview>(path, 0, ["report_received"], undefined, { keepPrevious: true });
  const rows = list.data?.items ?? [];
  const rest = (list.data?.total ?? 0) - rows.length;
  const reset = () => setLimit(PAGE);

  return (
    <>
      <PageHeader
        title="Container"
        count={list.data ? list.data.total.toLocaleString("de-DE") : undefined}
        description="Docker-Container aller Hosts mit aktivierter Erfassung. Die Image-Versionen prüft der Server bei den Registries; patchwatch zieht nie ein Image und startet nie einen Container."
      />
      <div className="mb-2 flex flex-wrap items-center gap-2">
        <label className="flex max-w-full items-center gap-2 text-xs text-fg2">
          <span className="sr-only">Container und Images durchsuchen</span>
          <input
            type="search"
            value={text}
            onChange={(e) => {
              setText(e.target.value);
              reset();
            }}
            placeholder="Image, Container oder Host suchen"
            aria-label="Container und Images durchsuchen"
            className="min-h-8 w-64 max-w-full rounded-[3px] border border-control bg-sunk px-2 py-1 text-sm text-fg placeholder:text-fg3 max-md:min-h-11"
          />
        </label>
        <FilterGroup
          label="Imagefilter"
          options={FILTERS}
          value={filter}
          onChange={(f) => {
            setFilter(f);
            reset();
          }}
        />
      </div>
      {list.error && !list.data ? <ErrorNote message={list.error} /> : null}
      {!list.data ? (
        list.error ? null : <Loading what="Container" />
      ) : rows.length === 0 ? (
        <Empty title={filter === "updates" && !q ? "Keine Images mit neuerem Stand" : "Keine Container gefunden"}>
          {filter === "updates" && !q
            ? "Für alle gemeldeten Container ist kein neuerer Stand bekannt."
            : "Es meldet noch kein Host Container. Die Erfassung ist pro Host ausdrücklich einzuschalten (Abschnitt „Docker-Container“ der README)."}
        </Empty>
      ) : (
        <div className="@container/tbl max-lg:overflow-x-auto">
          <table className="tbl stack">
            <caption>Images und ihre Container</caption>
            <thead>
              <tr>
                <th scope="col"><span className="th-pad">Image</span></th>
                <th scope="col"><span className="th-pad">Container</span></th>
                <th scope="col"><span className="th-pad">Prüfung</span></th>
              </tr>
            </thead>
            <tbody>
              {rows.map((g) => (
                <tr key={g.image}>
                  <td className="cell-primary">
                    <Mono>{g.image}</Mono>
                  </td>
                  <td data-label="Container" className="stacked:flex-[1_0_100%]">
                    <span className="block text-xs text-fg2">
                      {g.containers.length} Container auf {g.hosts} {g.hosts === 1 ? "Host" : "Hosts"}
                      {g.updates > 0 ? `, ${g.updates} mit neuerem Stand` : ""}
                    </span>
                    <ul className="mt-0.5 flex flex-col gap-0.5 text-sm">
                      {g.containers.map((c) => (
                        <li key={`${c.host_id}/${c.name}`}>
                          <Link href={`/hosts/${c.host_id}?tab=container`}>{c.host_name}</Link> <span className="text-fg3">·</span> <Mono>{c.name}</Mono>
                        </li>
                      ))}
                    </ul>
                  </td>
                  <td data-label="Prüfung" className="stacked:flex-[1_0_100%]">
                    <ContainerVerdict verdict={g.verdict} checkedAt={g.checked_at} />
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
