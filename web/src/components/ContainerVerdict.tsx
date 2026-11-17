import { StatusBadge } from "@/components/StatusBadge";
import { RelTime } from "@/components/RelTime";
import { CodeField } from "@/components/CopyButton";
import { verdictView } from "@/lib/containers";
import type { ContainerItem, ContainerVerdict as Verdict } from "@/lib/types";

/** Bewertung eines Containers oder Images: Chip (Symbol, Text, Farbe), Erklärung, Prüfzeit und der Befehl zum Kopieren. */
export function ContainerVerdict({ verdict, checkedAt, command }: { verdict: Verdict; checkedAt: string | null; command?: ContainerItem["command"] }) {
  const v = verdictView(verdict);
  return (
    <div className="flex min-w-0 flex-col items-start gap-1">
      <StatusBadge info={v.info} />
      {v.detail ? <span className="text-xs text-fg2">{v.detail}</span> : null}
      {checkedAt ? (
        <span className="text-xs text-fg3">
          geprüft <RelTime iso={checkedAt} />
        </span>
      ) : null}
      {command ? (
        <div className="w-full max-w-xl">
          <span className="mb-0.5 block text-xs text-fg3">Zum Aktualisieren (nur Text, patchwatch führt ihn nie aus):</span>
          <CodeField text={command} label="Befehl kopieren" />
        </div>
      ) : null}
    </div>
  );
}
