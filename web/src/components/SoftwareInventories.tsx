"use client";

import { useState, type FormEvent } from "react";
import Link from "next/link";
import { useAuth } from "./AuthProvider";
import { Button, TextInput } from "./Controls";
import { Dialog } from "./Dialog";
import { ConfirmDialog } from "./ConfirmDialog";
import { ErrorNote } from "./States";
import { RelTime } from "./RelTime";
import { api } from "@/lib/api";
import { useApi } from "@/lib/useApi";
import type { SoftwareResponse } from "@/lib/software";

interface Inventory {
  id: number; host_id: number; host_name: string; inventory_key: string; label: string;
  kind: string; identity: string | null; format: string; spec_version: string;
  imported_at: string; scanned_at: string | null; scan_error: string | null; component_count: number;
}
const KINDS: Record<string,string> = { application: "Anwendung / Projekt", container: "Container-Image", manual: "Manuelle Installation" };
const INPUT = "min-h-8 max-w-full rounded-[3px] border border-control bg-sunk px-2 py-1 text-sm text-fg max-md:min-h-11";

export function SoftwareInventories({ hosts, hostFilter, onChanged }: {
  hosts: SoftwareResponse["hosts"]; hostFilter: string | null; onChanged: () => Promise<void>;
}) {
  const { me } = useAuth();
  const mayWrite = me.permissions?.includes("hosts.write") ?? false;
  const mayScan = (me.permissions?.includes("sources.run") && me.permissions?.includes("cves.read")) ?? false;
  const inventories = useApi<{ items: Inventory[]; osv_ready: boolean }>(`/software/inventories${hostFilter ? `?host_id=${encodeURIComponent(hostFilter)}` : ""}`, 60_000, ["software_inventory"]);
  const [open, setOpen] = useState(false);
  const [replacing, setReplacing] = useState<Inventory | null>(null);
  const [removing, setRemoving] = useState<Inventory | null>(null);
  const [host, setHost] = useState("");
  const [key, setKey] = useState("");
  const [label, setLabel] = useState("");
  const [kind, setKind] = useState("application");
  const [identity, setIdentity] = useState("");
  const [bom, setBom] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [result, setResult] = useState<string | null>(null);

  function start(item: Inventory | null = null) {
    setReplacing(item); setHost(String(item?.host_id ?? hostFilter ?? hosts[0]?.id ?? ""));
    setKey(item?.inventory_key ?? ""); setLabel(item?.label ?? ""); setKind(item?.kind ?? "application");
    setIdentity(item?.identity ?? ""); setBom(""); setError(null); setOpen(true);
  }
  async function reload() { await Promise.all([inventories.reload(), onChanged()]); }
  async function submit(event: FormEvent) {
    event.preventDefault(); setError(null);
    if (new Blob([bom]).size > 8 * 1024 * 1024) { setError("Die SBOM darf höchstens 8 MB groß sein."); return; }
    let sbom: unknown;
    try { sbom = JSON.parse(bom); } catch { setError("Die SBOM ist kein gültiges JSON."); return; }
    setBusy("import");
    try {
      await api.put(`/hosts/${host}/inventories/${encodeURIComponent(key)}`, { label, kind, identity: identity.trim() || null, sbom }, { silent: true });
      setOpen(false); setResult(`Inventar „${label}“ importiert. Eine Sicherheitsprüfung kann jetzt gestartet werden.`);
      await reload();
    } catch (error) { setError(error instanceof Error ? error.message : "Import fehlgeschlagen"); }
    finally { setBusy(null); }
  }
  async function scan(item: Inventory) {
    setBusy(`scan:${item.id}`); setError(null); setResult(null);
    try {
      const result = await api.post<{ ok: boolean; checked: number; unmatched?: number; error?: string }>(`/software/inventories/${item.id}/scan`, {}, { silent: true });
      if (result.ok) setResult(`${result.checked} Paketversionen bei OSV geprüft; ${result.unmatched ?? 0} Komponenten nicht zuordenbar.`);
      else setError(result.error ?? "Prüfung unvollständig");
      await reload();
    } catch (error) { setError(error instanceof Error ? error.message : "Prüfung fehlgeschlagen"); }
    finally { setBusy(null); }
  }
  async function remove() {
    if (!removing) return;
    setBusy("remove"); setError(null);
    try { await api.del(`/hosts/${removing.host_id}/inventories/${encodeURIComponent(removing.inventory_key)}`); setRemoving(null); await reload(); }
    catch (error) { setError(error instanceof Error ? error.message : "Entfernen fehlgeschlagen"); }
    finally { setBusy(null); }
  }

  return <section className="mb-5 border-y border-line py-3" aria-labelledby="inventories-title">
    <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
      <h2 id="inventories-title" className="text-lg font-semibold">Anwendungen und Container</h2>
      {mayWrite ? <Button disabled={!hosts.length || busy !== null} onClick={() => start()}>SBOM importieren</Button> : null}
    </div>
    <p className="mb-2 max-w-prose text-sm text-fg2">Importiere eine Software-Stückliste aus einem Build, einem Container-Image oder einer manuellen Installation. Jede Quelle besitzt ein eigenes Inventar.</p>
    {!open && error ? <ErrorNote message={error} /> : null}
    {inventories.error ? <ErrorNote message={inventories.error} /> : null}
    {result ? <p role="status" className="mb-2 text-sm text-fg2">{result}</p> : null}
    {inventories.data?.items.length === 0 ? <p className="text-sm text-fg3">Noch keine zusätzlichen Inventare importiert.</p> : null}
    {inventories.data?.items.length ? <>
      <p className="mb-2 max-w-prose text-xs text-fg3">„Bei OSV prüfen“ übermittelt eindeutig zuordenbare Paketkennungen und Versionen an die aktive OSV-Quelle. {inventories.data.osv_ready ? "" : "Aktiviere dafür zuerst eine OSV-Quelle unter CVEs → Quellen."} <Link href="/cves#feeds">Quellen verwalten</Link></p>
      <ul className="divide-y divide-line">{inventories.data.items.map((item) => <li key={item.id} className="flex flex-wrap items-start justify-between gap-3 py-2">
        <div className="min-w-0 flex-1 [overflow-wrap:anywhere]">
          <p className="font-semibold">{item.label} <span className="text-xs font-normal text-fg3">{KINDS[item.kind]} · {item.host_name}</span></p>
          {item.identity ? <p className="mono text-xs text-fg2">{item.identity}</p> : null}
          <p className="text-xs text-fg3">{item.component_count} Komponenten · {item.format} {item.spec_version} · Import <RelTime iso={item.imported_at} /> · {item.scanned_at ? <>Prüfung <RelTime iso={item.scanned_at} /></> : "Noch nicht geprüft"}</p>
          {item.scan_error ? <p className="mt-1 text-xs text-warn">{item.scan_error}</p> : null}
        </div>
        <div className="flex flex-wrap gap-2">
          {mayScan ? <Button busy={busy === `scan:${item.id}`} disabled={busy !== null && busy !== `scan:${item.id}` || !inventories.data?.osv_ready} onClick={() => void scan(item)}>Bei OSV prüfen</Button> : null}
          {mayWrite ? <><Button disabled={busy !== null} onClick={() => start(item)}>Ersetzen</Button><Button disabled={busy !== null} onClick={() => setRemoving(item)}>Entfernen</Button></> : null}
        </div>
      </li>)}</ul>
    </> : null}
    <Dialog open={open} title={replacing ? "Inventar ersetzen" : "SBOM importieren"} onClose={() => { if (!busy) setOpen(false); }} dismissible={!busy}>
      <form onSubmit={(event) => void submit(event)} className="flex flex-col gap-3">
        <label className="flex flex-col gap-1 text-sm font-semibold">Host<select className={INPUT} required disabled={!!replacing || !!busy} value={host} onChange={(e) => setHost(e.target.value)}><option value="" disabled>Host wählen</option>{hosts.map((h) => <option key={h.id} value={h.id}>{h.name}</option>)}</select></label>
        <label className="flex flex-col gap-1 text-sm font-semibold">Inventarschlüssel<TextInput required maxLength={80} pattern="[A-Za-z0-9._-]+" readOnly={!!replacing} value={key} onChange={(e) => setKey(e.target.value)} placeholder="z. B. webshop-production" /><span className="text-xs font-normal text-fg3">Derselbe Schlüssel ersetzt beim nächsten Import genau dieses Inventar.</span></label>
        <label className="flex flex-col gap-1 text-sm font-semibold">Bezeichnung<TextInput required maxLength={200} value={label} onChange={(e) => setLabel(e.target.value)} placeholder="z. B. Webshop" /></label>
        <label className="flex flex-col gap-1 text-sm font-semibold">Art<select className={INPUT} value={kind} onChange={(e) => setKind(e.target.value)}>{Object.entries(KINDS).map(([k,v]) => <option key={k} value={k}>{v}</option>)}</select></label>
        <label className="flex flex-col gap-1 text-sm font-semibold">Image-Digest oder Installationsort (optional)<TextInput maxLength={512} value={identity} onChange={(e) => setIdentity(e.target.value)} placeholder="z. B. registry.example/app@sha256:… oder /opt/app" /></label>
        <label className="flex flex-col gap-1 text-sm font-semibold">SBOM-Datei<input type="file" accept="application/json,.json" className={INPUT} onChange={(event) => {
          const file = event.target.files?.[0];
          if (!file) return;
          if (file.size > 8 * 1024 * 1024) { setError("Die SBOM darf höchstens 8 MB groß sein."); return; }
          void file.text().then(setBom).catch(() => setError("Datei konnte nicht gelesen werden."));
        }} /><span className="text-xs font-normal text-fg3">CycloneDX JSON 1.4–1.7 oder SPDX JSON 2.2/2.3, höchstens 8 MB und 5000 Komponenten.</span></label>
        <label className="flex flex-col gap-1 text-sm font-semibold">SBOM als JSON<textarea required rows={6} className={`${INPUT} mono w-full text-xs`} value={bom} onChange={(event) => setBom(event.target.value)} /></label>
        {error ? <ErrorNote message={error} /> : null}
        {replacing ? <p className="text-sm text-fg2">Die Komponenten dieses Inventars werden vollständig ersetzt. Die neue Version muss erneut geprüft werden.</p> : null}
        <div className="flex justify-end gap-2"><Button disabled={!!busy} onClick={() => setOpen(false)}>Abbrechen</Button><Button variant="primary" type="submit" busy={busy === "import"}>Importieren</Button></div>
      </form>
    </Dialog>
    <ConfirmDialog open={!!removing} title="Inventar entfernen" confirmLabel="Entfernen" danger onCancel={() => { if (!busy) setRemoving(null); }} onConfirm={() => { if (!busy) void remove(); }}>
      Das Inventar „{removing?.label}“ und seine Komponenten werden entfernt. Du kannst es aus einer SBOM erneut importieren.
    </ConfirmDialog>
  </section>;
}
