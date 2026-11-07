-- Profilbild des Administrators: nur das im Browser neu kodierte, vom Server streng geprüfte Bild (PNG/WebP, 128x128, höchstens 64 KB).
ALTER TABLE admin_users
    ADD COLUMN avatar            BYTEA,
    ADD COLUMN avatar_type       TEXT,
    ADD COLUMN avatar_updated_at TIMESTAMPTZ,
    ADD CONSTRAINT admin_avatar_size CHECK (avatar IS NULL OR octet_length(avatar) <= 65536),
    ADD CONSTRAINT admin_avatar_type CHECK (avatar_type IS NULL OR avatar_type IN ('image/png', 'image/webp'));
