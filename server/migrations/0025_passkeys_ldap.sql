-- Passkeys (WebAuthn) je Benutzer, LDAP als weitere Anmeldeart, eigener Schalter „Anmeldung per Passwort aus“.
ALTER TABLE admin_users
    ADD COLUMN password_login_disabled BOOLEAN NOT NULL DEFAULT false,
    -- Stabile, zufällige Kennung des Benutzers für WebAuthn (user.id); verrät nichts über Name oder Konto.
    ADD COLUMN webauthn_handle UUID NOT NULL DEFAULT gen_random_uuid();
ALTER TABLE admin_users DROP CONSTRAINT admin_auth_kind;
ALTER TABLE admin_users ADD CONSTRAINT admin_auth_kind CHECK (auth_kind IN ('local', 'oidc', 'ldap'));
CREATE UNIQUE INDEX admin_webauthn_handle ON admin_users (webauthn_handle);

CREATE TABLE passkeys (
    id            BIGSERIAL PRIMARY KEY,
    admin_id      BIGINT      NOT NULL REFERENCES admin_users (id) ON DELETE CASCADE,
    -- Öffentliche Credential-Daten (kein Geheimnis: der private Schlüssel verlässt das Gerät nie).
    credential_id BYTEA       NOT NULL UNIQUE,
    credential    JSONB       NOT NULL,
    name          TEXT        NOT NULL CHECK (char_length(name) BETWEEN 1 AND 60),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at  TIMESTAMPTZ
);
CREATE INDEX passkeys_admin ON passkeys (admin_id);
