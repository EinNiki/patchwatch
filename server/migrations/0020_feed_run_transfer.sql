-- Übertragung je Abruf-Lauf getrennt ausweisen (additiv, nur Zahlen):
--   bytes_wire     über das Netz übertragene Bytes, NULL wenn nicht messbar (der HTTP-Client entpackt gzip selbst)
--   bytes_unpacked entpackte Bytes (so viel hat der Parser gesehen)
--   rows_written   tatsächlich geschriebene Zeilen in cve_source_status (unveränderte Zeilen zählen nicht)
-- Der Server speichert Downloads nie als Datei; es gibt keine temporären Dateien.
ALTER TABLE feed_runs
    ADD COLUMN bytes_wire     BIGINT,
    ADD COLUMN bytes_unpacked BIGINT,
    ADD COLUMN rows_written   BIGINT;
