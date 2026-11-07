"use client";

import { bootLabel, liveUptimeSeconds, uptime } from "@/lib/format";
import { useNow } from "@/lib/useNow";

/**
 * Uptime des Hosts. Der Agent meldet sie nur beim Report; angezeigt wird sie aus der Bootzeit
 * (Reportzeit minus gemeldete Uptime) und der aktuellen Zeit, sie steht also nicht auf dem Wert des Reports still.
 * Nach einem Neustart stimmt die Anzeige mit dem nächsten Report wieder.
 */
export function Uptime({ lastReportAt, seconds, withBoot = false }: { lastReportAt: string | null; seconds: number | null; withBoot?: boolean }) {
  const now = useNow(60_000);
  const boot = bootLabel(lastReportAt, seconds);
  return (
    <span title={boot ?? undefined}>
      {uptime(liveUptimeSeconds(lastReportAt, seconds, now))}
      {withBoot && boot ? <span className="text-fg3"> · {boot}</span> : null}
    </span>
  );
}
