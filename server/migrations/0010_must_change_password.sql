-- Konten mit bekanntem oder erzeugtem Start-Passwort dürfen sich nur anmelden, um das Passwort zu ändern.
ALTER TABLE admin_users ADD COLUMN must_change_password BOOLEAN NOT NULL DEFAULT false;
