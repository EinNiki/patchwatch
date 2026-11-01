-- Laufende OpenID-Connect-Anmeldungen: state, nonce und PKCE-Verifier bis zum Callback (einmalig verwendbar).
CREATE TABLE oidc_states (
    state_hash BYTEA PRIMARY KEY,
    nonce      TEXT NOT NULL,
    verifier   TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);
