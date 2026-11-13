import { Switch } from "@/components/Controls";
import { dependents, type PermGroup } from "@/lib/roles";

/**
 * Rechte als Schalter, nach Gruppen. Einschalten nimmt Voraussetzungen mit, Ausschalten abhängige Rechte (Logik in `lib/roles`).
 * `grantable`: Rechte, die der Ausführende selbst hat; alle anderen sind gesperrt (nur eigene Rechte vergeben). `locked`: alles gesperrt.
 */
export function PermissionSwitches({
  groups,
  value,
  grantable,
  locked = false,
  lockedReason,
  onToggle,
}: {
  groups: readonly PermGroup[];
  value: readonly string[];
  grantable: readonly string[];
  locked?: boolean;
  lockedReason?: string;
  onToggle: (name: string, on: boolean) => void;
}) {
  return (
    <div className="flex flex-col gap-3">
      {groups.map((g) => (
        <fieldset key={g.title} className="m-0 min-w-0 border-0 p-0">
          <legend className="mb-0.5 p-0 text-xs font-semibold text-fg2">{g.title}</legend>
          <div className="flex flex-col divide-y divide-line">
            {g.permissions.map((p) => {
              const on = value.includes(p.name);
              const own = grantable.includes(p.name);
              const dep = on ? dependents(p.name, value, groups) : [];
              const reason = locked ? lockedReason : !own ? "Du hast dieses Recht selbst nicht." : undefined;
              const notes = [p.sensitive ? "Verlangt beim Vergeben dein Passwort." : null, dep.length > 0 ? `Schaltet ${dep.length} abhängige${dep.length === 1 ? "s" : ""} Recht${dep.length === 1 ? "" : "e"} mit aus.` : null, reason ?? null].filter(Boolean);
              return (
                <Switch
                  key={p.name}
                  label={p.label}
                  hint={p.description}
                  note={notes.length > 0 ? notes.join(" ") : undefined}
                  checked={on}
                  disabled={locked || !own}
                  onChange={(e) => onToggle(p.name, e.target.checked)}
                />
              );
            })}
          </div>
        </fieldset>
      ))}
    </div>
  );
}
