-- Wiederholungsleiter nach Fehlschlägen: Anzahl der Fehlläufe in Folge und frühester nächster Versuch.
-- NULL bei next_attempt_at heißt: normales Intervall (letzter Versuch + Intervall). Ein Erfolg setzt beides zurück.
ALTER TABLE feed_state ADD COLUMN retry_step INT NOT NULL DEFAULT 0;
ALTER TABLE feed_state ADD COLUMN next_attempt_at TIMESTAMPTZ;
