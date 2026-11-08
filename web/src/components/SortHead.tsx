import { NavIcon } from "./Icons";

/** Sortierbarer Tabellenkopf: Button in `<th aria-sort>`, Pfeil zeigt Richtung, graues Doppelpfeil-Icon sonst. */
export function SortHead({
  label,
  active,
  dir,
  num,
  className = "",
  tip,
  onSort,
}: {
  label: string;
  active: boolean;
  dir: "asc" | "desc";
  num?: boolean;
  className?: string;
  /** Erklärung als Tooltip am Kopf. */
  tip?: string;
  onSort: () => void;
}) {
  return (
    <th scope="col" className={`${num ? "num" : ""} ${className}`} aria-sort={active ? (dir === "asc" ? "ascending" : "descending") : "none"}>
      <button type="button" onClick={onSort} title={tip}>
        {label}
        <span aria-hidden="true" className={active ? "text-accent" : "text-fg3"}>
          <NavIcon name={active ? dir : "sort"} />
        </span>
      </button>
    </th>
  );
}
