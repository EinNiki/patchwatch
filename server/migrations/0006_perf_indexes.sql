-- Nur Indizes, keine Datenänderung. Messung und Begründung: docs/perf.md.
-- Zähler je CVE in der Liste und im Detail suchen nach cve_id (der Primärschlüssel beginnt mit host_id).
CREATE INDEX IF NOT EXISTS host_cve_status_cve ON host_cve_status (cve_id);
-- Standardsortierung der CVE-Liste.
CREATE INDEX IF NOT EXISTS cves_updated ON cves (updated_at DESC, id DESC);
