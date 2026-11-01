-- Liste der offenen Paket-Updates je Host (vom Agent mitgeschickt; NULL = Agent sendet noch keine Liste).
ALTER TABLE hosts ADD COLUMN updates_list JSONB;
