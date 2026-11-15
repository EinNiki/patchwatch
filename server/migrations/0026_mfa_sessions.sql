-- Zwei-Faktor-Anmeldung (TOTP) und Sitzungsübersicht.
ALTER TABLE admin_users
    -- "enc:<base64>" (verschlüsselt mit PATCHWATCH_SECRET_KEY) oder "plain:<base32>" (ohne Schlüssel); NULL = nicht eingerichtet.
    ADD COLUMN totp_secret    TEXT,
    ADD COLUMN totp_enabled   BOOLEAN NOT NULL DEFAULT false,
    -- Zuletzt akzeptierter Zeitschritt: derselbe Code gilt nicht zweimal.
    ADD COLUMN totp_last_step BIGINT;

-- Wiederherstellungscodes (nur als Hash; je Code einmal verwendbar).
CREATE TABLE totp_recovery_codes (
    id        BIGSERIAL PRIMARY KEY,
    admin_id  BIGINT      NOT NULL REFERENCES admin_users (id) ON DELETE CASCADE,
    code_hash BYTEA       NOT NULL,
    used_at   TIMESTAMPTZ,
    UNIQUE (admin_id, code_hash)
);

ALTER TABLE sessions
    -- Kennung für die Oberfläche (der Cookie-Wert und sein Hash bleiben geheim).
    ADD COLUMN public_id    UUID        NOT NULL DEFAULT gen_random_uuid(),
    ADD COLUMN ip           TEXT,
    ADD COLUMN user_agent   TEXT,
    ADD COLUMN method       TEXT        NOT NULL DEFAULT 'password',
    ADD COLUMN last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now();
CREATE UNIQUE INDEX sessions_public_id ON sessions (public_id);
CREATE INDEX sessions_admin ON sessions (admin_id);
