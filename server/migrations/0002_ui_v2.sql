-- UI v2: Agent-Check-in, Benachrichtigungskanäle in der DB, Einstellungen.

-- Check-in: Der Server teilt dem Agent nur mit, ob ein Report gewünscht ist (kein Befehl, kein Pfad).
--   report_requested_at   offene Anfrage (wird vom nächsten Report gelöscht)
--   report_dispatched_at  Zeitpunkt, zu dem der Check-in "ja" geantwortet hat (genau ein Report je Anfrage)
--   last_report_request_at Grundlage des Rate-Limits (1 Anfrage je Host und Minute), wird nie gelöscht
ALTER TABLE hosts
    ADD COLUMN agent_version          TEXT,
    ADD COLUMN last_checkin_at        TIMESTAMPTZ,
    ADD COLUMN report_requested_at    TIMESTAMPTZ,
    ADD COLUMN report_dispatched_at   TIMESTAMPTZ,
    ADD COLUMN last_report_request_at TIMESTAMPTZ;

-- Ein Kanal je Art. `config` enthält nur Unkritisches (URL, Topic, Raum, Server);
-- `secret` ist XChaCha20-Poly1305 (Nonce || Ciphertext), Kanalname als Associated Data.
CREATE TABLE notification_channels (
    kind         TEXT PRIMARY KEY CHECK (kind IN ('ntfy', 'matrix', 'gotify', 'discord', 'browser')),
    enabled      BOOLEAN NOT NULL DEFAULT false,
    config       JSONB NOT NULL DEFAULT '{}',
    secret       BYTEA,
    events       TEXT[] NOT NULL DEFAULT '{}',
    summary_time TIME,
    timezone     TEXT,
    last_error   TEXT,
    last_ok_at   TIMESTAMPTZ,
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE settings (
    key        TEXT PRIMARY KEY,
    value      JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
