-- CVE-Quellen mit stabiler ID, Anzeigename und Typ; Quellen lassen sich löschen (auch Debian/Ubuntu).
--
-- Die bisherige Spalte `name` war zugleich Typ und Schlüssel. Sie wird zur stabilen `id`; bestehende Zeilen behalten
-- ihren Wert (debian, ubuntu, osv, nvd, cisa_kev). Damit bleiben alle Verweise unverändert gültig und verlustfrei:
-- feed_state.source, cve_source_status.source_id, die Intervall-Keys in `settings` und die AAD der Geheimnisse
-- (`cve_source:<id>`), es muss also nichts neu verschlüsselt werden. Neue Quellen bekommen `<typ>-<zufall>`.

ALTER TABLE cve_sources DROP CONSTRAINT IF EXISTS cve_sources_name_check;
ALTER TABLE cve_sources RENAME COLUMN name TO id;
ALTER TABLE cve_sources
    ADD COLUMN kind       TEXT,
    ADD COLUMN label      TEXT,
    ADD COLUMN ecosystem  TEXT,
    ADD COLUMN deleted_at TIMESTAMPTZ;

UPDATE cve_sources SET kind = id,
    label = CASE id WHEN 'debian' THEN 'Debian' WHEN 'ubuntu' THEN 'Ubuntu' WHEN 'osv' THEN 'OSV'
                    WHEN 'nvd' THEN 'NVD' WHEN 'cisa_kev' THEN 'CISA KEV' ELSE id END;

ALTER TABLE cve_sources
    ALTER COLUMN kind SET NOT NULL,
    ALTER COLUMN label SET NOT NULL,
    ADD CONSTRAINT cve_sources_kind_check CHECK (kind IN ('debian', 'ubuntu', 'osv', 'nvd', 'cisa_kev')),
    ADD CONSTRAINT cve_sources_label_check CHECK (char_length(label) BETWEEN 1 AND 40);

-- Name eindeutig (ohne Groß-/Kleinschreibung); gleiche Konfiguration nur einmal je Typ. Gelöschte Quellen zählen nicht.
CREATE UNIQUE INDEX cve_sources_label_uq ON cve_sources (lower(label)) WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX cve_sources_config_uq ON cve_sources (kind, COALESCE(base_url, ''), COALESCE(ecosystem, ''))
    WHERE deleted_at IS NULL;

-- Welche Quelle hat die Zeile zuletzt geliefert? `source` bleibt der Typ (die Bewertung wertet danach aus).
ALTER TABLE cve_source_status ADD COLUMN source_id TEXT;
UPDATE cve_source_status SET source_id = source;
CREATE INDEX cve_source_status_source_id ON cve_source_status (source_id);
