-- Persistente Abruf-Läufe der CVE-Quellen (additiv): jeder Abruf (manuell oder geplant) bekommt eine Zeile mit Phase,
-- Fortschritt und Ergebnis. So bleibt sichtbar, was läuft, was zuletzt passiert ist und warum etwas fehlschlug.
-- Gespeichert werden nie Antwortinhalte oder Zugangsdaten, nur Zähler und eine kurze Fehlermeldung.
CREATE TABLE feed_runs (
    id           BIGSERIAL PRIMARY KEY,
    source       TEXT NOT NULL,
    trigger      TEXT NOT NULL CHECK (trigger IN ('manual', 'scheduled')),
    started_by   TEXT,
    status       TEXT NOT NULL DEFAULT 'queued'
                 CHECK (status IN ('queued', 'running', 'ok', 'not_modified', 'incomplete', 'failed', 'skipped', 'interrupted')),
    phase        TEXT NOT NULL DEFAULT 'connect'
                 CHECK (phase IN ('connect', 'download', 'parse', 'store', 'evaluate', 'done')),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at   TIMESTAMPTZ,
    finished_at  TIMESTAMPTZ,
    -- Lebenszeichen des ausführenden Prozesses: Läufe ohne frisches Lebenszeichen gelten als unterbrochen.
    heartbeat_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    bytes        BIGINT NOT NULL DEFAULT 0,
    items        INTEGER,
    hosts        INTEGER,
    error        TEXT,
    -- Dauer je Phase in Millisekunden, z. B. {"connect": 120, "download": 4300}
    phases       JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX feed_runs_source_idx ON feed_runs (source, id DESC);
-- Höchstens ein offener Lauf je Quelle: ein zweiter Start hängt sich an den laufenden an, statt zu scheitern.
CREATE UNIQUE INDEX feed_runs_one_active ON feed_runs (source) WHERE status IN ('queued', 'running');
