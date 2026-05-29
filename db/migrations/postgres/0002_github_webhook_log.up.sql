-- 0002_github_webhook_log.up.sql (postgres)
-- Raw webhook payloads for replay/debug.

CREATE TABLE github_webhook_log (
    id            UUID PRIMARY KEY,
    delivery_id   TEXT NOT NULL,
    event_type    TEXT NOT NULL,
    action        TEXT,
    payload_json  JSONB NOT NULL,
    signature     TEXT,
    received_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    processed_at  TIMESTAMPTZ,
    process_error TEXT
);
CREATE UNIQUE INDEX idx_github_webhook_delivery ON github_webhook_log(delivery_id);
CREATE INDEX idx_github_webhook_event ON github_webhook_log(event_type, received_at);
