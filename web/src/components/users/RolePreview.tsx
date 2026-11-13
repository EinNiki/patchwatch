import { Icon } from "@/components/Icons";
import { previewRows, type PermGroup, type RoleInfo } from "@/lib/roles";

/** Rechtevorschau einer Rolle: je Recht Symbol und Text ("darf" / "darf nicht"), nie nur Farbe. Quelle ist `GET /roles`. */
export function RolePreview({ role, groups }: { role: RoleInfo | undefined; groups: readonly PermGroup[] }) {
  const rows = previewRows(role, groups);
  return (
    <section tabIndex={0} aria-label={`Rechtevorschau ${role?.title ?? ""}`} className="max-h-56 overflow-y-auto border-y border-line py-2">
      {rows.map((g) => (
        <div key={g.title} className="mb-2 last:mb-0">
          <h3 className="mb-0.5 text-xs font-semibold text-fg2">{g.title}</h3>
          <ul className="m-0 list-none p-0">
            {g.items.map((i) => (
              <li key={i.label} className="flex items-center gap-2 py-0.5 text-sm">
                <span className={i.allowed ? "text-ok" : "text-fg3"}>
                  <Icon name={i.allowed ? "ok" : "pending"} />
                </span>
                <span className={i.allowed ? "" : "text-fg3"}>{i.label}</span>
                <span className="ml-auto text-xs text-fg3">{i.allowed ? "darf" : "darf nicht"}</span>
              </li>
            ))}
          </ul>
        </div>
      ))}
      <p className="m-0 mt-1 flex items-center gap-2 border-t border-line pt-2 text-sm">
        <span className="text-fg3">
          <Icon name="pending" />
        </span>
        <span>Kann Geheimnisse sehen</span>
        <span className="ml-auto text-xs text-fg3">nein</span>
      </p>
    </section>
  );
}
