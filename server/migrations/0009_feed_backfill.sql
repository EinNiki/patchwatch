-- Fortschritt eines laufenden Rückstandsabbaus (Ubuntu: mehr Änderungen seit dem letzten Lauf als Seiten pro Lauf).
-- Solange `backfill` gesetzt ist, bleibt `cursor` der zuletzt BESTÄTIGTE Stand (alles darüber ist vollständig
-- geladen); der Fortschritt steht ausschließlich hier. Erst wenn die Lücke geschlossen ist, wird `cursor` auf
-- `backfill.pending` gesetzt und `backfill` gelöscht. Inhalt (JSON): target, pending, next_offset, pages_done,
-- runs, started_at.
ALTER TABLE feed_state ADD COLUMN backfill JSONB;
