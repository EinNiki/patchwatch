-- Weitere Benachrichtigungskanäle: E-Mail (SMTP), Telegram, Slack, generischer Webhook.
ALTER TABLE notification_channels DROP CONSTRAINT notification_channels_kind_check;
ALTER TABLE notification_channels ADD CONSTRAINT notification_channels_kind_check
    CHECK (kind IN ('ntfy', 'matrix', 'gotify', 'discord', 'browser', 'smtp', 'telegram', 'slack', 'webhook'));
