-- Verwaltete CVE-Quellen: an/aus, optionaler Spiegel (SSRF-geprüft) und optionales verschlüsseltes Geheimnis (NVD-Schlüssel).
-- debian und ubuntu sind eingebaut (nicht löschbar), osv, nvd und cisa_kev lassen sich hinzufügen.
-- Der Quellenname geht als Associated Data in die Verschlüsselung ein ("cve_source:<name>").
CREATE TABLE cve_sources (
    name       TEXT PRIMARY KEY CHECK (name IN ('debian', 'ubuntu', 'osv', 'nvd', 'cisa_kev')),
    enabled    BOOLEAN NOT NULL DEFAULT true,
    base_url   TEXT,
    secret     BYTEA,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
