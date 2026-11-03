-- Wann der letzte vollständige Abruf einer Quelle "veraltet" wird (max(3 x Intervall, 6 h) nach dem Erfolg);
-- steht in der Datenbank, damit der Host-Status ohne Konfiguration und Scheduler-Wissen daraus ableiten kann,
-- ob die Quelle für die Bewertung nutzbar ist.
ALTER TABLE feed_state ADD COLUMN usable_until TIMESTAMPTZ;
-- Bis zu welchem Zeitpunkt (Horizont) der Erstabruf die Quelle vollständig geladen hat. NULL bei Quellen,
-- die noch nie vollständig geladen wurden (auch Altbestände aus der Zeit, als der Erstabruf nach 5 Seiten
-- als vollständig galt).
ALTER TABLE feed_state ADD COLUMN covered_since TIMESTAMPTZ;
-- Bestehende Installationen: bis zum nächsten Erfolg gilt der letzte Abruf noch 6 Stunden als frisch.
UPDATE feed_state SET usable_until = last_success_at + interval '6 hours' WHERE last_success_at IS NOT NULL;
