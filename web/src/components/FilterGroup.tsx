/** Gruppe von Umschaltknöpfen (genau einer aktiv, `aria-pressed`); Trefferfläche 32 px, Touch 44 px. */
export function FilterGroup<T extends string | number>({
  label,
  options,
  value,
  onChange,
}: {
  label: string;
  options: readonly { id: T; label: string }[];
  value: T;
  onChange: (id: T) => void;
}) {
  return (
    <div role="group" aria-label={label} className="flex flex-wrap gap-1">
      {options.map((o) => (
        <button
          key={o.id}
          type="button"
          aria-pressed={value === o.id}
          onClick={() => onChange(o.id)}
          className={`min-h-8 rounded-xs border px-2 text-xs font-medium max-md:min-h-11 max-md:px-3 ${value === o.id ? "border-accent bg-accent text-bg" : "border-line bg-sunk text-fg hover:bg-surface"}`}
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}
