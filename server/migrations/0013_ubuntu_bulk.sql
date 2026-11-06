-- Ubuntu-Hybridquelle: Zustand der Massendaten (je Release) und des stündlichen Abrufs sowie ein geparkter
-- Rückstandsabbau. Rein additiv: vorhandene Daten, Cursor und Fortschritt bleiben unverändert.
ALTER TABLE feed_state ADD COLUMN bulk JSONB;
ALTER TABLE feed_state ADD COLUMN backfill_parked JSONB;
