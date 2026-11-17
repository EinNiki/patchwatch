-- Docker-Container und Image-Versionen (rein additiv: keine Spalte und keine Zeile wird entfernt oder verändert).

-- Zustand der Docker-Erfassung je Host. NULL = nicht aktiviert (der Agent sendet dann keinen Docker-Block).
ALTER TABLE hosts ADD COLUMN docker_state TEXT CHECK (docker_state IN ('ok', 'unavailable'));
ALTER TABLE hosts ADD COLUMN docker_reason TEXT;
ALTER TABLE hosts ADD COLUMN docker_checked_at TIMESTAMPTZ;

-- Container laut letztem Docker-Block. Nichts wird gelöscht: was in der letzten Meldung fehlt, behält seinen alten
-- `last_seen` und wird nach 7 Tagen von den Abfragen ausgeblendet.
CREATE TABLE host_containers (
    host_id         BIGINT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    container_id    TEXT NOT NULL,
    name            TEXT NOT NULL,
    state           TEXT NOT NULL,
    created_at      TIMESTAMPTZ,
    status_text     TEXT NOT NULL DEFAULT '',
    image_ref       TEXT NOT NULL DEFAULT '',
    image_id        TEXT NOT NULL DEFAULT '',
    repo_digests    TEXT[] NOT NULL DEFAULT '{}',
    os              TEXT,
    arch            TEXT,
    variant         TEXT,
    compose_project TEXT,
    compose_service TEXT,
    first_seen      TIMESTAMPTZ NOT NULL,
    last_seen       TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (host_id, container_id)
);
CREATE INDEX host_containers_image ON host_containers (image_ref);

-- Ergebnis der Registry-Prüfung je (Registry, Repository, Tag, Plattform); ein Abruf gilt für alle Hosts.
CREATE TABLE container_image_checks (
    registry               TEXT NOT NULL,
    repository             TEXT NOT NULL,
    tag                    TEXT NOT NULL,
    platform               TEXT NOT NULL DEFAULT '',
    checked_at             TIMESTAMPTZ NOT NULL,
    status                 TEXT NOT NULL,
    registry_digest        TEXT,
    platform_digest        TEXT,
    platform_config_digest TEXT,
    newest_patch           TEXT,
    newest_minor           TEXT,
    newest_major           TEXT,
    tags_incomplete        BOOLEAN NOT NULL DEFAULT false,
    -- GET-Anfragen dieser Prüfung (Docker Hub zählt sie auf das Abruflimit; HEAD nicht).
    get_count              INTEGER NOT NULL DEFAULT 0,
    error                  TEXT,
    -- Stand, für den das Ereignis „Neues Image verfügbar“ schon gesendet wurde.
    notified_for           TEXT,
    PRIMARY KEY (registry, repository, tag, platform)
);
CREATE INDEX container_image_checks_checked ON container_image_checks (checked_at);
