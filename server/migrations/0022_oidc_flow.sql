-- OIDC: Rücksprungziel je laufender Anmeldung und die vom Anbieter gewünschte (noch nicht bestätigte) Rolle.
ALTER TABLE oidc_states ADD COLUMN return_to TEXT;
ALTER TABLE admin_users ADD COLUMN requested_role TEXT CHECK (requested_role IN ('admin', 'operator', 'viewer'));
