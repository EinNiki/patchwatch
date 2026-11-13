-- Seit wann eine Quelle in ihrem jetzigen Zustand (ok, incomplete, stale, ...) ist: nur bei einem Zustandswechsel
-- neu gesetzt, nicht bei jedem Lauf (additiv).
ALTER TABLE feed_state
    ADD COLUMN state_label TEXT,
    ADD COLUMN state_since TIMESTAMPTZ;
