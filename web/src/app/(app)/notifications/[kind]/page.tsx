"use client";

import { use, useMemo, useState } from "react";
import Link from "next/link";
import { api, ApiError } from "@/lib/api";
import { useApi } from "@/lib/useApi";
import { channelLabel, EVENTS, isChannelKind, type ChannelKind } from "@/lib/channels";
import type { ChannelView, NotificationsResponse } from "@/lib/types";
import { Button, Checkbox, Field, Select, TextInput } from "@/components/Controls";
import { Icon } from "@/components/Icons";
import { PageHeader } from "@/components/PageHeader";
import { RelTime } from "@/components/RelTime";
import { ErrorNote, Loading } from "@/components/States";
import { Mono } from "@/components/Version";

interface FieldDef {
  key: string;
  label: string;
  placeholder: string;
  hint?: string;
  /** Feste Auswahl statt Freitext. */
  options?: { value: string; label: string }[];
  /** Kein Monospace (Namen, Adressen mit Anzeigename). */
  plain?: boolean;
}

interface Spec {
  config: FieldDef[];
  /** Beschriftung des Geheimnisfelds; `null`: der Kanal hat keines. */
  secret: { label: string; hint: string; required: boolean } | null;
  intro: string;
}

const SPEC: Record<ChannelKind, Spec> = {
  ntfy: {
    intro: "Push-Nachrichten über einen ntfy-Server (ntfy.sh oder selbst gehostet).",
    config: [
      { key: "url", label: "Server-URL", placeholder: "https://ntfy.example.org" },
      { key: "topic", label: "Topic", placeholder: "patchwatch", hint: "Buchstaben, Ziffern, Unterstrich und Bindestrich." },
    ],
    secret: { label: "Zugriffstoken", hint: "Nur nötig, wenn das Topic geschützt ist.", required: false },
  },
  matrix: {
    intro: "Nachricht in einen Matrix-Raum, gesendet mit dem Zugangstoken eines Bot-Kontos.",
    config: [
      { key: "homeserver", label: "Homeserver-URL", placeholder: "https://matrix.example.org" },
      { key: "room_id", label: "Raum-ID", placeholder: "!abcdef:example.org", hint: "Die interne ID (beginnt mit !), nicht der Alias." },
    ],
    secret: { label: "Access-Token", hint: "Token des Bot-Kontos, das im Raum Mitglied sein muss.", required: true },
  },
  gotify: {
    intro: "Push-Nachrichten über einen Gotify-Server.",
    config: [{ key: "url", label: "Server-URL", placeholder: "https://gotify.example.org" }],
    secret: { label: "App-Token", hint: "Token der Gotify-Anwendung.", required: true },
  },
  discord: {
    intro: "Nachricht in einen Discord-Kanal per Webhook. Erwähnungen (@everyone, @here) sind abgeschaltet.",
    config: [],
    secret: { label: "Webhook-URL", hint: "Die URL enthält ein Geheimnis und wird deshalb wie ein Token behandelt.", required: true },
  },
  telegram: {
    intro: "Nachricht über einen Telegram-Bot an einen Chat, eine Gruppe oder einen Kanal.",
    config: [{ key: "chat_id", label: "Chat-ID", placeholder: "123456789", hint: "Zahl (bei Gruppen negativ) oder @kanalname. Der Bot muss im Chat Mitglied sein." }],
    secret: { label: "Bot-Token", hint: "Token von @BotFather, Format 123456:ABC….", required: true },
  },
  slack: {
    intro: "Nachricht in einen Slack-Kanal über einen eingehenden Webhook. Erlaubt ist nur hooks.slack.com.",
    config: [],
    secret: { label: "Webhook-URL", hint: "https://hooks.slack.com/services/… enthält ein Geheimnis und wird deshalb wie ein Token behandelt.", required: true },
  },
  smtp: {
    intro: "E-Mail über einen SMTP-Server. Die Verbindung ist immer verschlüsselt und das Zertifikat wird geprüft.",
    config: [
      { key: "host", label: "SMTP-Server", placeholder: "mail.example.org", hint: "Interne Server müssen in PATCHWATCH_NOTIFY_ALLOWED_HOSTS stehen." },
      {
        key: "port",
        label: "Port",
        placeholder: "587",
        options: [
          { value: "587", label: "587 (STARTTLS)" },
          { value: "465", label: "465 (TLS)" },
          { value: "25", label: "25" },
          { value: "2525", label: "2525" },
        ],
      },
      {
        key: "security",
        label: "Verschlüsselung",
        placeholder: "",
        options: [
          { value: "starttls", label: "STARTTLS" },
          { value: "tls", label: "TLS (implizit)" },
        ],
      },
      { key: "username", label: "Benutzer", placeholder: "patchwatch@example.org", hint: "Leer lassen, wenn der Server keine Anmeldung verlangt." },
      { key: "from", label: "Absender", placeholder: "patchwatch <patchwatch@example.org>", plain: true },
      { key: "to", label: "Empfänger", placeholder: "admin@example.org, ops@example.org", hint: "Bis zu 10 Adressen, durch Komma getrennt.", plain: true },
    ],
    secret: { label: "Passwort", hint: "Nur nötig, wenn ein Benutzer gesetzt ist.", required: false },
  },
  webhook: {
    intro: "POST mit festem JSON an eine eigene URL: version, event, title, text, priority, tags, time. Ein Token wird als Bearer-Header gesendet.",
    config: [{ key: "url", label: "URL", placeholder: "https://hooks.example.org/patchwatch" }],
    secret: { label: "Bearer-Token", hint: "Optional, falls der Empfänger eine Anmeldung verlangt.", required: false },
  },
  browser: {
    intro: "Meldungen erscheinen als Hinweis unten rechts, solange patchwatch in einem Browser-Tab geöffnet ist. Es wird nichts nach außen gesendet.",
    config: [],
    secret: null,
  },
};

const COMMON_ZONES = ["Europe/Berlin", "Europe/Vienna", "Europe/Zurich", "Europe/London", "UTC"];

/** Vorbelegung: gespeicherter Wert, sonst bei Auswahlfeldern die erste Option (z. B. Port 587 mit STARTTLS). */
const initialValue = (f: FieldDef, saved: string | undefined): string => saved ?? f.options?.[0]?.value ?? "";

function zones(): string[] {
  try {
    const f = (Intl as unknown as { supportedValuesOf?: (k: string) => string[] }).supportedValuesOf;
    return f ? f("timeZone") : COMMON_ZONES;
  } catch {
    return COMMON_ZONES;
  }
}

export default function ChannelPage({ params }: { params: Promise<{ kind: string }> }) {
  const { kind } = use(params);
  if (!isChannelKind(kind)) return <ErrorNote message="Unbekannter Kanal." />;
  return <Channel kind={kind} />;
}

function Channel({ kind }: { kind: ChannelKind }) {
  const all = useApi<NotificationsResponse>("/notifications");
  const ch = all.data?.channels.find((c) => c.kind === kind);
  if (all.error && !all.data) return <ErrorNote message={all.error} />;
  if (!all.data || !ch) return <Loading what="Kanaldaten" />;
  return <Form key={kind} kind={kind} ch={ch} secretStorage={all.data.secret_storage} reload={all.reload} />;
}

function Form({ kind, ch, secretStorage, reload }: { kind: ChannelKind; ch: ChannelView; secretStorage: boolean; reload: () => Promise<void> }) {
  const spec = SPEC[kind];
  const [enabled, setEnabled] = useState(ch.enabled);
  const [config, setConfig] = useState<Record<string, string>>(() => Object.fromEntries(spec.config.map((f) => [f.key, initialValue(f, ch.config[f.key])])));
  const [events, setEvents] = useState<string[]>(ch.events);
  const [time, setTime] = useState(ch.summary_time ?? "08:00");
  const [tz, setTz] = useState(ch.timezone ?? "Europe/Berlin");
  const [replacing, setReplacing] = useState(!ch.secret_set);
  const [secret, setSecret] = useState("");
  const [clearSecret, setClearSecret] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const [testing, setTesting] = useState(false);
  const [test, setTest] = useState<{ ok: boolean; result: string } | null>(null);
  const zoneList = useMemo(() => zones(), []);

  const label = channelLabel(kind);
  const needsSecret = spec.secret?.required === true && !ch.secret_set && secret === "";
  const keyMissing = spec.secret !== null && !secretStorage;
  const dirty =
    enabled !== ch.enabled ||
    secret !== "" ||
    clearSecret ||
    spec.config.some((f) => (config[f.key] ?? "") !== initialValue(f, ch.config[f.key])) ||
    events.slice().sort().join() !== ch.events.slice().sort().join() ||
    (events.includes("daily_summary") && (time !== (ch.summary_time ?? "08:00") || tz !== (ch.timezone ?? "Europe/Berlin")));

  async function save(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setSaved(false);
    setTest(null);
    if (enabled && needsSecret) {
      setError(`${spec.secret?.label ?? "Zugangsdaten"} fehlt. Trage ihn ein oder schalte den Kanal aus.`);
      return;
    }
    setSaving(true);
    try {
      const body: Record<string, unknown> = { enabled, config: Object.fromEntries(spec.config.map((f) => [f.key, config[f.key]?.trim() ?? ""])), events };
      if (secret !== "") body.secret = secret;
      if (clearSecret) body.clear_secret = true;
      if (events.includes("daily_summary")) {
        body.summary_time = time;
        body.timezone = tz.trim();
      }
      await api.put(`/notifications/${kind}`, body);
      // Nach dem Speichern zeigt das Feld wieder „Gespeichert“ (oder bleibt offen, wenn nichts gespeichert ist).
      setReplacing(clearSecret ? true : !(secret !== "" || ch.secret_set));
      setSecret("");
      setClearSecret(false);
      setSaved(true);
      await reload();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Speichern fehlgeschlagen.");
    } finally {
      setSaving(false);
    }
  }

  async function sendTest() {
    setTesting(true);
    setTest(null);
    setError(null);
    try {
      setTest(await api.post<{ ok: boolean; result: string }>(`/notifications/${kind}/test`));
      await reload();
    } catch (err) {
      setError(err instanceof ApiError && err.status === 429 ? `Zu viele Testnachrichten. Erneut möglich in ${err.retryAfter ?? 60} Sek.` : "Testnachricht konnte nicht gestartet werden.");
    } finally {
      setTesting(false);
    }
  }

  return (
    <>
      <PageHeader title={label}>
        <Button onClick={() => void sendTest()} busy={testing} disabled={dirty || !ch.enabled}>
          Testnachricht senden
        </Button>
      </PageHeader>
      <p className="mb-4 max-w-prose text-fg2">{spec.intro}</p>

      {ch.from_env ? (
        <p className="mb-4 max-w-prose border-l-4 border-accent bg-accent-soft px-3 py-2">
          Aus Umgebungsvariablen vorbelegt (<Mono>PATCHWATCH_NTFY_*</Mono>). Speichern legt die Werte in der Datenbank an; sie haben dann Vorrang.
        </p>
      ) : null}
      {keyMissing ? (
        <p className="mb-4 max-w-prose border-l-4 border-warn bg-warn-soft px-3 py-2 text-warn">
          <Mono>PATCHWATCH_SECRET_KEY</Mono> ist auf dem Server nicht gesetzt: {spec.secret?.label} lässt sich nicht speichern. Erzeuge einen Schlüssel mit{" "}
          <Mono>openssl rand -base64 32</Mono>, sichere ihn getrennt von der Datenbank und starte den Server neu.
        </p>
      ) : null}
      {error ? <div className="mb-4 max-w-prose"><ErrorNote message={error} /></div> : null}
      {test ? (
        <p role="status" className={`mb-4 flex max-w-prose items-start gap-2 border-l-4 px-3 py-2 ${test.ok ? "border-ok bg-ok-soft text-ok" : "border-warn bg-warn-soft text-warn"}`}>
          <Icon name={test.ok ? "ok" : "warn"} />
          {test.ok ? "Testnachricht gesendet." : `Testnachricht nicht zugestellt: ${test.result}.`}
        </p>
      ) : null}
      {saved ? <p role="status" className="mb-4 text-ok">Gespeichert.</p> : null}

      <form onSubmit={(e) => void save(e)} className="max-w-xl">
        <Checkbox className="mb-4" label="Kanal aktiv" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />

        {spec.config.length > 0 || spec.secret ? (
          <fieldset className="mb-6 flex flex-col gap-4">
            <legend className="mb-2 text-lg font-semibold">Zugang</legend>
            {spec.config.map((f) => (
              <div key={f.key}>
                <Field label={f.label}>
                  {f.options ? (
                    <Select value={config[f.key] ?? ""} onChange={(e) => setConfig({ ...config, [f.key]: e.target.value })}>
                      {f.options.map((o) => (
                        <option key={o.value} value={o.value}>
                          {o.label}
                        </option>
                      ))}
                    </Select>
                  ) : (
                    <TextInput
                      value={config[f.key] ?? ""}
                      onChange={(e) => setConfig({ ...config, [f.key]: e.target.value })}
                      placeholder={f.placeholder}
                      autoComplete="off"
                      spellCheck={false}
                      maxLength={300}
                      className={f.plain ? "" : "font-mono"}
                    />
                  )}
                </Field>
                {f.hint ? <p className="mt-1 text-xs text-fg3">{f.hint}</p> : null}
              </div>
            ))}
            {spec.secret ? (
              <div>
                {ch.secret_set && !replacing ? (
                  <>
                    <p className="mb-1 text-xs font-semibold text-fg2">{spec.secret.label}</p>
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="inline-flex min-h-8 items-center gap-1.5 border border-line bg-sunk px-2 text-fg2">
                        <Icon name="ok" /> Gespeichert
                      </span>
                      <Button onClick={() => setReplacing(true)} disabled={keyMissing}>
                        Ersetzen
                      </Button>
                      {!spec.secret.required || !enabled ? (
                        <Button variant="danger" onClick={() => setClearSecret(!clearSecret)} aria-pressed={clearSecret}>
                          {clearSecret ? "Entfernen zurücknehmen" : "Entfernen"}
                        </Button>
                      ) : null}
                    </div>
                    {clearSecret ? <p className="mt-1 text-xs text-warn">Wird beim Speichern entfernt.</p> : null}
                  </>
                ) : (
                  <>
                    <Field label={`${spec.secret.label}${ch.secret_set ? " (ersetzt den gespeicherten)" : spec.secret.required ? "" : " (optional)"}`}>
                      <TextInput
                        type="password"
                        value={secret}
                        onChange={(e) => setSecret(e.target.value)}
                        autoComplete="new-password"
                        spellCheck={false}
                        maxLength={2048}
                        disabled={keyMissing}
                        className="font-mono"
                      />
                    </Field>
                    {ch.secret_set ? (
                      <Button
                        className="mt-2"
                        onClick={() => {
                          setReplacing(false);
                          setSecret("");
                        }}
                      >
                        Gespeicherten behalten
                      </Button>
                    ) : null}
                  </>
                )}
                <p className="mt-1 text-xs text-fg3">{spec.secret.hint} Wird verschlüsselt gespeichert und nie wieder angezeigt.</p>
              </div>
            ) : null}
          </fieldset>
        ) : null}

        <fieldset className="mb-6">
          <legend className="mb-2 text-lg font-semibold">Ereignisse</legend>
          <ul className="flex flex-col gap-1">
            {EVENTS.map((ev) => (
              <li key={ev.id}>
                <Checkbox
                  label={ev.label}
                  hint={ev.hint}
                  checked={events.includes(ev.id)}
                  onChange={(e) => setEvents(e.target.checked ? [...events, ev.id] : events.filter((x) => x !== ev.id))}
                />
              </li>
            ))}
          </ul>
          {events.includes("daily_summary") ? (
            <div className="mt-4 flex flex-wrap gap-4 border-l-4 border-line pl-3">
              <Field label="Uhrzeit">
                <TextInput type="time" value={time} onChange={(e) => setTime(e.target.value)} required className="w-32" />
              </Field>
              <Field label="Zeitzone">
                <TextInput list="zones" value={tz} onChange={(e) => setTz(e.target.value)} required maxLength={64} className="w-56" autoComplete="off" />
              </Field>
              <datalist id="zones">
                {zoneList.map((z) => (
                  <option key={z} value={z} />
                ))}
              </datalist>
            </div>
          ) : null}
          <p className="mt-3 text-xs text-fg3">Proxmox-Hosts mit unbekannter CVE-Lage lösen bewusst keinen Alarm aus.</p>
        </fieldset>

        <div className="flex flex-wrap items-center gap-3">
          <Button type="submit" variant="primary" busy={saving} disabled={!dirty}>
            Speichern
          </Button>
          <Link href="/notifications" className="inline-flex items-center max-md:min-h-11">Zur Übersicht</Link>
        </div>
        {dirty ? <p className="mt-2 text-xs text-fg3">Ungespeicherte Änderungen. Die Testnachricht nutzt die gespeicherte Konfiguration.</p> : null}
      </form>

      <section aria-labelledby="res-h" className="mt-8 max-w-xl">
        <h2 id="res-h" className="mb-1 text-lg font-semibold">
          Letztes Ergebnis
        </h2>
        {ch.last_error ? (
          <p className="text-warn">Fehler: {ch.last_error}</p>
        ) : ch.last_ok_at ? (
          <p>
            Zuletzt erfolgreich gesendet <RelTime iso={ch.last_ok_at} />.
          </p>
        ) : (
          <p className="text-fg3">Noch nichts gesendet.</p>
        )}
      </section>
    </>
  );
}
