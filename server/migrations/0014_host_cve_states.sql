-- Host-Ansicht: alle CVE-Zustände (auch "gefixt" und "nicht betroffen") werden gespeichert.
-- Rein additiv: nur ein Index für Filter/Sortierung je Host; bestehende Zeilen bleiben unverändert.
-- Die neuen Zeilen entstehen durch die einmalige Neubewertung beim Start (siehe main.rs).
CREATE INDEX IF NOT EXISTS host_cve_status_host_status_idx ON host_cve_status (host_id, status, computed_at DESC);
