-- Einzelrechte je Benutzer (additiv): NULL = die Rechte folgen der Rolle (Vorlage), sonst die gespeicherten Rechtenamen.
-- Unbekannte Namen werden beim Lesen ignoriert (nicht gewährt). Bestehende Konten bleiben NULL: Verhalten unverändert.
ALTER TABLE admin_users ADD COLUMN permissions TEXT[];
