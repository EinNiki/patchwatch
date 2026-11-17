-- Pakete und ausstehende Updates je Host (rein additiv: keine Spalte und keine Zeile wird entfernt oder verändert).

-- Installierte Pakete: Architektur und erste Sichtung; Suche nach Name über alle Hosts.
ALTER TABLE host_packages ADD COLUMN arch TEXT;
ALTER TABLE host_packages ADD COLUMN first_seen TIMESTAMPTZ;
CREATE INDEX host_packages_name ON host_packages (name);

-- Stand der Paketliste und der Updates je Host (Hash der zuletzt gespeicherten Liste, Alter der apt-Listen).
ALTER TABLE hosts ADD COLUMN packages_hash TEXT;
ALTER TABLE hosts ADD COLUMN packages_count INTEGER;
ALTER TABLE hosts ADD COLUMN packages_truncated BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE hosts ADD COLUMN packages_updated_at TIMESTAMPTZ;
ALTER TABLE hosts ADD COLUMN apt_lists_updated_at TIMESTAMPTZ;
ALTER TABLE hosts ADD COLUMN updates_listed BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE hosts ADD COLUMN updates_remove INTEGER;

-- Ausstehende Updates je Host mit erster und letzter Sichtung. Ersetzt `hosts.updates_list` (JSONB), das als Altlast
-- liegen bleibt und nicht mehr beschrieben wird.
CREATE TABLE host_updates (
    host_id    BIGINT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    kind       TEXT NOT NULL CHECK (kind IN ('upgrade', 'new', 'remove')),
    installed  TEXT,
    candidate  TEXT,
    origin     TEXT NOT NULL DEFAULT '',
    security   BOOLEAN NOT NULL DEFAULT false,
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen  TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (host_id, name)
);
CREATE INDEX host_updates_security ON host_updates (host_id) WHERE security;

-- Bestehende Listen übernehmen, damit die Oberfläche bis zum nächsten Report nichts verliert.
INSERT INTO host_updates (host_id, name, kind, installed, candidate, origin, security, first_seen, last_seen)
SELECT h.id, e->>'name',
       CASE WHEN e->>'from' IS NULL THEN 'new' ELSE 'upgrade' END,
       e->>'from', e->>'to', COALESCE(e->>'origin', ''), COALESCE((e->>'security')::boolean, false),
       COALESCE(h.last_report_at, now()), COALESCE(h.last_report_at, now())
FROM hosts h, jsonb_array_elements(h.updates_list) AS e
WHERE jsonb_typeof(h.updates_list) = 'array' AND e->>'name' IS NOT NULL
ON CONFLICT (host_id, name) DO NOTHING;
UPDATE hosts SET updates_listed = true WHERE jsonb_typeof(updates_list) = 'array';
