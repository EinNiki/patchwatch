-- Hosts: Token nur als SHA-256-Hash, letzter Report denormalisiert für schnelle Listen.
CREATE TABLE hosts (
    id                     BIGSERIAL PRIMARY KEY,
    name                   TEXT NOT NULL UNIQUE,
    token_hash             BYTEA NOT NULL UNIQUE,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_report_at         TIMESTAMPTZ,
    hostname               TEXT,
    os_id                  TEXT,
    os_version             TEXT,
    os_codename            TEXT,
    pretty_name            TEXT,
    running_kernel         TEXT,
    kernel_package         TEXT,
    kernel_package_version TEXT,
    kernel_source          TEXT,
    kernel_source_version  TEXT,
    newest_kernel          TEXT,
    newest_kernel_version  TEXT,
    reboot_needed_kernel   BOOLEAN,
    reboot_required_file   BOOLEAN,
    updates_pending        INTEGER,
    updates_security       INTEGER,
    uptime_seconds         BIGINT,
    is_proxmox             BOOLEAN NOT NULL DEFAULT false,
    proxmox_version        TEXT,
    status                 TEXT NOT NULL DEFAULT 'pending',
    status_changed_at      TIMESTAMPTZ
);

-- Verlauf (Rohdaten ohne Paketliste), wird per Cleanup-Job gekürzt.
CREATE TABLE reports (
    id               BIGSERIAL PRIMARY KEY,
    host_id          BIGINT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    received_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    running_kernel   TEXT,
    updates_pending  INTEGER,
    updates_security INTEGER,
    reboot_needed    BOOLEAN NOT NULL DEFAULT false,
    status           TEXT NOT NULL,
    raw              JSONB NOT NULL
);
CREATE INDEX reports_host_time ON reports (host_id, received_at DESC);
CREATE INDEX reports_time ON reports (received_at);

CREATE TABLE host_packages (
    host_id        BIGINT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    name           TEXT NOT NULL,
    version        TEXT NOT NULL,
    source_name    TEXT,
    source_version TEXT,
    last_seen      TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (host_id, name)
);

CREATE TABLE cves (
    id            TEXT PRIMARY KEY,
    description   TEXT,
    priority      TEXT,
    published_at  TIMESTAMPTZ,
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Normalisierter Status je (CVE, Quelle, Release, Paket); Datenmodell für beliebige Pakete.
CREATE TABLE cve_source_status (
    cve_id      TEXT NOT NULL REFERENCES cves(id) ON DELETE CASCADE,
    source      TEXT NOT NULL,
    release     TEXT NOT NULL,
    package     TEXT NOT NULL,
    status      TEXT NOT NULL,
    fix_version TEXT,
    raw         JSONB,
    first_seen  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (cve_id, source, release, package)
);
CREATE INDEX cve_source_status_pkg ON cve_source_status (package, release);

CREATE TABLE host_cve_status (
    host_id     BIGINT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    cve_id      TEXT NOT NULL REFERENCES cves(id) ON DELETE CASCADE,
    status      TEXT NOT NULL,
    computed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    reason      TEXT NOT NULL,
    sources     JSONB NOT NULL DEFAULT '[]',
    PRIMARY KEY (host_id, cve_id)
);

CREATE TABLE cve_watchlist (
    cve_id   TEXT PRIMARY KEY,
    note     TEXT,
    added_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Manuelle Prüfung (z. B. Proxmox-Kernel ohne CVE-Quelle).
CREATE TABLE manual_reviews (
    host_id        BIGINT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    cve_id         TEXT NOT NULL,
    reviewed_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    reviewed_by    TEXT NOT NULL,
    kernel_version TEXT NOT NULL,
    PRIMARY KEY (host_id, cve_id)
);

CREATE TABLE feed_state (
    source               TEXT PRIMARY KEY,
    etag                 TEXT,
    last_modified        TEXT,
    cursor               TEXT,
    last_attempt_at      TIMESTAMPTZ,
    last_success_at      TIMESTAMPTZ,
    last_error           TEXT,
    last_error_at        TIMESTAMPTZ,
    consecutive_failures INTEGER NOT NULL DEFAULT 0
);

-- Events und Job-Queue in Postgres (SKIP LOCKED + LISTEN/NOTIFY), kein Redis.
CREATE TABLE events (
    id           BIGSERIAL PRIMARY KEY,
    kind         TEXT NOT NULL,
    payload      JSONB NOT NULL DEFAULT '{}',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    processed_at TIMESTAMPTZ
);
CREATE INDEX events_unprocessed ON events (id) WHERE processed_at IS NULL;

CREATE TABLE jobs (
    id         BIGSERIAL PRIMARY KEY,
    kind       TEXT NOT NULL,
    payload    JSONB NOT NULL DEFAULT '{}',
    dedupe_key TEXT UNIQUE,
    run_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    locked_at  TIMESTAMPTZ,
    attempts   INTEGER NOT NULL DEFAULT 0,
    done_at    TIMESTAMPTZ,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX jobs_due ON jobs (run_at) WHERE done_at IS NULL;

CREATE TABLE admin_users (
    id            BIGSERIAL PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Session-ID nur als Hash gespeichert; csrf_token gehört zur Session.
CREATE TABLE sessions (
    id_hash    BYTEA PRIMARY KEY,
    admin_id   BIGINT NOT NULL REFERENCES admin_users(id) ON DELETE CASCADE,
    csrf_token TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX sessions_expiry ON sessions (expires_at);
