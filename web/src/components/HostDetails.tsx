"use client";

import { absTime, kernelBase } from "@/lib/format";
import type { Feed, Host } from "@/lib/types";
import type { FeedNotice } from "@/lib/hostCves";
import { Uptime } from "@/components/Uptime";
import { RelTime } from "@/components/RelTime";
import { Mono } from "@/components/Version";
import { StatusBadge } from "@/components/StatusBadge";
import { FEED_STATE } from "@/components/FeedSources";
import { Icon } from "@/components/Icons";

function Fact({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <>
      <dt className="text-fg3">{label}</dt>
      <dd className="m-0 min-w-0 break-words">{children}</dd>
    </>
  );
}

/** Quellen, die für diesen Host zählen: die Distributions-Quelle plus aktive Anreicherungsquellen. */
function responsibleFeeds(feeds: Feed[] | undefined, osId: string | null): Feed[] {
  return (feeds ?? []).filter((f) => f.enabled && (f.type === osId || f.enrich_only));
}

/** Host-Details: ab 1280 px als rechte Spalte, darunter als aufklappbarer Abschnitt (siehe Seite). */
export function HostDetails({ host: h, feeds, notice }: { host: Host; feeds: Feed[] | undefined; notice: FeedNotice }) {
  const newer = h.newest_kernel && h.running_kernel && h.newest_kernel !== h.running_kernel;
  const used = responsibleFeeds(feeds, h.os_id);
  const issue = h.cve_source_issue ?? null;
  return (
    <dl className="grid grid-cols-[max-content_minmax(0,1fr)] gap-x-4 gap-y-1.5 text-sm">
      <Fact label="Distribution">
        {h.pretty_name ?? "–"} {h.os_codename ? <span className="text-fg3">({h.os_codename})</span> : null}
      </Fact>
      <Fact label="Laufender Kernel">
        <Mono>{h.running_kernel ?? "–"}</Mono>
      </Fact>
      <Fact label="Neuester Kernel">
        {h.newest_kernel ? (
          <>
            <Mono>{h.newest_kernel}</Mono> <Mono className="text-fg2">{h.newest_kernel_version}</Mono>
          </>
        ) : (
          "–"
        )}
      </Fact>
      <Fact label="Kernel-Paket">
        {h.kernel_package ? (
          <>
            <Mono>{h.kernel_package}</Mono> <Mono className="text-fg2">{h.kernel_package_version}</Mono>
          </>
        ) : (
          <span className="text-fg3">nicht ermittelt</span>
        )}
      </Fact>
      <Fact label="Neustart nötig">
        {h.reboot_needed ? (
          <span className="inline-flex flex-wrap items-center gap-x-2 text-warn">
            <Icon name="reboot" /> Ja
            <span className="text-fg2">
              {newer ? `Kernel ${kernelBase(h.running_kernel)} → ${kernelBase(h.newest_kernel)}` : null}
              {newer && h.reboot_required_file ? " · " : null}
              {h.reboot_required_file ? "/var/run/reboot-required vorhanden" : null}
            </span>
          </span>
        ) : (
          "Nein"
        )}
      </Fact>
      <Fact label="Uptime">
        <Uptime lastReportAt={h.last_report_at} seconds={h.uptime_seconds} withBoot />
      </Fact>
      <Fact label="Letzter Report">
        <RelTime iso={h.last_report_at} /> <span className="text-fg3">· {absTime(h.last_report_at)}</span>
      </Fact>
      <Fact label="Letzter Check-in">
        {h.last_checkin_at ? (
          <>
            <RelTime iso={h.last_checkin_at} /> <span className="text-fg3">· {absTime(h.last_checkin_at)}</span>
          </>
        ) : (
          <span className="text-fg3">noch keiner</span>
        )}
      </Fact>
      <Fact label="Agent">{h.agent_version ? <Mono>{h.agent_version}</Mono> : <span className="text-fg3">unbekannt</span>}</Fact>
      <Fact label="Offene Updates">
        {h.updates_pending == null ? (
          <span className="text-fg3">unbekannt</span>
        ) : (
          <>
            {h.updates_pending ? (
              <a href="#updates" className="underline">
                {h.updates_pending} anzeigen
              </a>
            ) : (
              h.updates_pending
            )}
            {h.updates_security ? <span className="font-semibold text-crit"> · davon {h.updates_security} Sicherheit</span> : <span className="text-fg3"> · davon 0 Sicherheit</span>}
          </>
        )}
      </Fact>
      {h.is_proxmox ? (
        <Fact label="Proxmox VE">
          <Mono>{h.proxmox_version}</Mono>
        </Fact>
      ) : null}
      <Fact label="Datenquellen">
        {used.length === 0 ? (
          <span className="text-warn">keine aktive Quelle für {h.os_id ?? "diese Distribution"}</span>
        ) : (
          <span className="flex flex-wrap gap-1">
            {used.map((f) => (
              <span key={f.source} className="inline-flex items-center gap-1" title={`${f.label}: ${FEED_STATE[f.state].label}`}>
                <span className="text-fg2">{f.label}</span>
                <StatusBadge info={FEED_STATE[f.state]} />
              </span>
            ))}
          </span>
        )}
      </Fact>
      <Fact label="Bewertung">
        {notice.restricted || issue ? (
          <span className="text-warn">eingeschränkt{issue ? `: ${issue}` : ""}</span>
        ) : (
          <span>vollständig</span>
        )}
      </Fact>
      {h.cve_unknown === 0 ? (
        <Fact label="Unbekannt">
          <span className="text-fg3">keine CVE ohne Aussage</span>
        </Fact>
      ) : null}
    </dl>
  );
}
