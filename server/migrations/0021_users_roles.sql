-- Benutzer und Rollen: die Tabelle admin_users wird zur Benutzertabelle erweitert (additiv, nichts geht verloren).
-- Alle bestehenden Konten werden Administrator und bleiben aktiv; bestehende Sitzungen bleiben gültig.
ALTER TABLE admin_users
    ADD COLUMN role           TEXT        NOT NULL DEFAULT 'admin',
    ADD COLUMN status         TEXT        NOT NULL DEFAULT 'active',
    ADD COLUMN display_name   TEXT,
    ADD COLUMN email          TEXT,
    ADD COLUMN auth_kind      TEXT        NOT NULL DEFAULT 'local',
    ADD COLUMN oidc_issuer    TEXT,
    ADD COLUMN oidc_subject   TEXT,
    ADD COLUMN created_by     BIGINT REFERENCES admin_users(id) ON DELETE SET NULL,
    ADD COLUMN last_login_at  TIMESTAMPTZ,
    ADD COLUMN deleted_at     TIMESTAMPTZ;

-- OIDC-Konten haben kein Passwort.
ALTER TABLE admin_users ALTER COLUMN password_hash DROP NOT NULL;

-- Früher wurden OIDC-Konten über die E-Mail-Adresse ("oidc:<mail>") identifiziert und waren volle Administratoren.
-- Eine E-Mail-Adresse ist kein Schlüssel: Diese Konten werden ausstehend (ohne Zugriff) und müssen von einem
-- Administrator ausdrücklich freigegeben und mit (Issuer, Subject) verknüpft werden. Lokale Administratoren bleiben.
UPDATE admin_users SET auth_kind = 'oidc', status = 'pending', role = 'viewer',
       email = substr(username, 6), password_hash = NULL
 WHERE username LIKE 'oidc:%';
DELETE FROM sessions WHERE admin_id IN (SELECT id FROM admin_users WHERE status = 'pending');

UPDATE admin_users SET display_name = left(username, 120) WHERE display_name IS NULL;
ALTER TABLE admin_users ALTER COLUMN display_name SET NOT NULL;
-- Ohne Angabe ist der Anzeigename der Benutzername (auch für Konten, die der Code ohne Anzeigenamen anlegt).
CREATE FUNCTION admin_default_display_name() RETURNS trigger AS $$
BEGIN
    NEW.display_name := COALESCE(NEW.display_name, left(NEW.username, 120));
    RETURN NEW;
END $$ LANGUAGE plpgsql;
CREATE TRIGGER admin_display_name BEFORE INSERT ON admin_users FOR EACH ROW EXECUTE FUNCTION admin_default_display_name();

ALTER TABLE admin_users
    ADD CONSTRAINT admin_role_known     CHECK (role IN ('admin', 'operator', 'viewer')),
    ADD CONSTRAINT admin_status_known   CHECK (status IN ('active', 'locked', 'pending')),
    ADD CONSTRAINT admin_auth_kind      CHECK (auth_kind IN ('local', 'oidc')),
    ADD CONSTRAINT admin_local_has_hash CHECK (auth_kind <> 'local' OR deleted_at IS NOT NULL OR password_hash IS NOT NULL),
    ADD CONSTRAINT admin_local_no_oidc  CHECK (auth_kind <> 'local' OR (oidc_issuer IS NULL AND oidc_subject IS NULL)),
    ADD CONSTRAINT admin_oidc_pair      CHECK ((oidc_issuer IS NULL) = (oidc_subject IS NULL)),
    ADD CONSTRAINT admin_display_len    CHECK (char_length(display_name) BETWEEN 1 AND 120);
CREATE UNIQUE INDEX admin_oidc_identity ON admin_users (oidc_issuer, oidc_subject) WHERE oidc_subject IS NOT NULL;
CREATE UNIQUE INDEX admin_display_name_unique ON admin_users (lower(display_name)) WHERE deleted_at IS NULL;

-- Aktivitätsprotokoll: nur feste Felder, nie Passwörter, Tokens, Secrets oder Sitzungs-IDs. Die Quell-IP ist gekürzt (IPv4 /24, IPv6 /48).
CREATE TABLE audit_log (
    id         BIGSERIAL PRIMARY KEY,
    at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor_id   BIGINT REFERENCES admin_users(id) ON DELETE SET NULL,
    actor_name TEXT NOT NULL,
    action     TEXT NOT NULL,
    target     TEXT,
    result     TEXT NOT NULL CHECK (result IN ('ok', 'denied', 'failed')),
    ip         TEXT,
    CONSTRAINT audit_text_len CHECK (char_length(actor_name) <= 200 AND char_length(action) <= 80 AND char_length(coalesce(target, '')) <= 300)
);
CREATE INDEX audit_log_at ON audit_log (at DESC);
