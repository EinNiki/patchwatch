-- An empty inventory is distinct from an agent that does not send packages.
ALTER TABLE hosts ADD COLUMN packages_reported_at TIMESTAMPTZ;
UPDATE hosts h SET packages_reported_at = p.seen
FROM (SELECT host_id, max(last_seen) AS seen FROM host_packages GROUP BY host_id) p
WHERE h.id = p.host_id;

-- Existing imports only covered kernels. Re-fetch Debian and restart Ubuntu's
-- incremental history with the wider package scope, retaining known CVE rows.
UPDATE feed_state SET last_modified = NULL, etag = NULL, cursor = NULL,
    covered_since = NULL, backfill = NULL, backfill_parked = NULL,
    last_success_at = NULL, usable_until = NULL
WHERE source IN (SELECT id FROM cve_sources WHERE kind IN ('debian', 'ubuntu'));
