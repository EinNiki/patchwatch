-- Messwerte je Abruf-Lauf (additiv): wie viele Anfragen, Wiederholungen und Wartezeiten, damit sichtbar wird, wo ein
-- langsamer Abruf seine Zeit verliert. Gespeichert werden nur Zahlen, nie Antwortinhalte oder Adressen.
ALTER TABLE feed_runs
    ADD COLUMN requests   INTEGER,
    ADD COLUMN retries    INTEGER,
    -- Wartezeit durch Backoff, Retry-After und Seitenpausen in Millisekunden
    ADD COLUMN wait_ms    BIGINT,
    ADD COLUMN page_size  INTEGER,
    -- Anzahl je HTTP-Statuscode, z. B. {"200": 10, "503": 1} (0 = kein Status, Netzwerkfehler)
    ADD COLUMN statuses   JSONB NOT NULL DEFAULT '{}'::jsonb,
    -- Je Anfrage [Status, Bytes, Millisekunden], höchstens 200 Einträge
    ADD COLUMN page_stats JSONB NOT NULL DEFAULT '[]'::jsonb;
