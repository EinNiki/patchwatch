-- Debian: Status und Version je Suite (Archiv und Security) stehen im Tracker unter `repositories`. Der Adapter legt sie
-- jetzt in `raw->'suites'` ab; die Spalte `suites` macht sie abfragbar. Rein additiv: nichts wird gelöscht oder
-- überschrieben, bestehende Zeilen haben zunächst `suites = NULL` (= "Security: unbekannt" in der Anzeige).
ALTER TABLE cve_source_status ADD COLUMN suites JSONB GENERATED ALWAYS AS (raw->'suites') STORED;

-- Einmaliger Neuabruf der Debian-Quellen, damit `raw->'suites'` für bestehende Zeilen nachgefüllt wird (nur die
-- Validatoren des bedingten Abrufs werden geleert; Daten und Zustand bleiben).
UPDATE feed_state SET etag = NULL, last_modified = NULL
WHERE source IN (SELECT id FROM cve_sources WHERE kind = 'debian');
