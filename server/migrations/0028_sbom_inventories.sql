CREATE TABLE software_inventories (
    id BIGSERIAL PRIMARY KEY,
    host_id BIGINT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    inventory_key TEXT NOT NULL,
    label TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('application', 'container', 'manual')),
    identity TEXT,
    format TEXT NOT NULL,
    spec_version TEXT NOT NULL,
    generation BIGINT NOT NULL DEFAULT 1,
    imported_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    scanned_at TIMESTAMPTZ,
    scan_source_id TEXT,
    scan_error TEXT,
    UNIQUE (host_id, inventory_key)
);
CREATE TABLE software_components (
    id BIGSERIAL PRIMARY KEY,
    inventory_id BIGINT NOT NULL REFERENCES software_inventories(id) ON DELETE CASCADE,
    component_ref TEXT NOT NULL,
    name TEXT NOT NULL,
    version TEXT,
    purl TEXT,
    ecosystem TEXT,
    location TEXT,
    assessment TEXT NOT NULL DEFAULT 'unknown',
    assessed_at TIMESTAMPTZ,
    findings JSONB NOT NULL DEFAULT '[]'::jsonb,
    UNIQUE (inventory_id, component_ref)
);
CREATE TABLE software_osv_cache (
    source_id TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    purl TEXT NOT NULL,
    fetched_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    findings JSONB NOT NULL,
    PRIMARY KEY (source_id, endpoint, purl)
);
CREATE INDEX software_osv_cache_age ON software_osv_cache (fetched_at);
