/** Anzeigenamen der Benachrichtigungskanäle (Schlüssel = `kind` der API). */
export const CHANNELS = [
  { kind: "ntfy", label: "ntfy" },
  { kind: "matrix", label: "Matrix" },
  { kind: "gotify", label: "Gotify" },
  { kind: "discord", label: "Discord" },
  { kind: "telegram", label: "Telegram" },
  { kind: "slack", label: "Slack" },
  { kind: "smtp", label: "E-Mail (SMTP)" },
  { kind: "webhook", label: "Webhook" },
  { kind: "browser", label: "Live im Browser" },
] as const;

export type ChannelKind = (typeof CHANNELS)[number]["kind"];

export const channelLabel = (kind: string): string => CHANNELS.find((c) => c.kind === kind)?.label ?? kind;
export const isChannelKind = (kind: string): kind is ChannelKind => CHANNELS.some((c) => c.kind === kind);

/** Ereignisarten wie im Server (notify/events.rs) mit Erklärung für die UI. */
export const EVENTS: { id: string; label: string; hint: string }[] = [
  { id: "host_status", label: "Host-Status ändert sich", hint: "z. B. von „Aktuell“ zu „Sicherheitsupdates offen“." },
  { id: "agent_silent", label: "Agent meldet sich nicht mehr", hint: "Host wechselt zu „Meldet sich nicht“." },
  { id: "watchlist_cve", label: "Neue Lage zu einer CVE auf der Watchlist", hint: "Neue CVE oder geänderter Status einer beobachteten CVE." },
  { id: "fix_available", label: "Fix verfügbar", hint: "Nur für Releases, die auf einem deiner Hosts laufen." },
  { id: "feed_failing", label: "CVE-Feed fällt aus", hint: "Ein Feed liefert wiederholt Fehler." },
  { id: "daily_summary", label: "Tageszusammenfassung", hint: "Einmal täglich zur eingestellten Uhrzeit." },
];
