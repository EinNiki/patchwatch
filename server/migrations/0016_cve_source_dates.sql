-- „Aktualisiert“ der CVE-Liste zeigte bisher `cves.updated_at`. Der Import schrieb dort `COALESCE(Quelldatum, now())`: Quellen
-- ohne Datum (Ubuntu-OVAL, Debian) setzten bei jedem Import den Importzeitpunkt. Jetzt getrennt (rein additiv, nichts wird
-- gelöscht oder überschrieben):
--   source_updated_at  letzte Änderung laut Quelle (bei mehreren Quellen die neueste); NULL = keine Quelle liefert ein Datum
--   last_synced_at     letzter Abgleich mit einer Quelle ("Zuletzt abgeglichen"); NULL = noch nie von einer Quelle geliefert
-- Die Altspalte `updated_at` bleibt unverändert bestehen, wird aber nicht mehr gelesen.
ALTER TABLE cves ADD COLUMN source_updated_at TIMESTAMPTZ;
ALTER TABLE cves ADD COLUMN last_synced_at TIMESTAMPTZ;
-- Der bisherige Wert war (zumindest für Quellen ohne Datum) der Importzeitpunkt: er wird zum letzten Abgleich.
-- Ein Quelldatum lässt sich aus den gespeicherten Rohdaten nicht rekonstruieren (sie enthalten keine Daten); es wird
-- beim nächsten Import der jeweiligen Quelle nachgefüllt, sofern sie eines liefert.
UPDATE cves SET last_synced_at = updated_at;

-- Sortierung nach „Aktualisiert“ (NULL zuletzt).
CREATE INDEX cves_source_updated_idx ON cves (source_updated_at DESC NULLS LAST, id DESC);
