-- NetControl schema, version 1.
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS networks (
    id          TEXT PRIMARY KEY,
    interface   TEXT NOT NULL,
    kind        TEXT NOT NULL,
    ssid        TEXT,
    cidr        TEXT NOT NULL,
    local_ip    TEXT,
    gateway     TEXT,
    dns         TEXT NOT NULL DEFAULT '[]',
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    UNIQUE(interface, cidr)
);

CREATE TABLE IF NOT EXISTS network_interfaces (
    name        TEXT PRIMARY KEY,
    kind        TEXT NOT NULL,
    mac         TEXT,
    is_up       INTEGER NOT NULL DEFAULT 0,
    details     TEXT NOT NULL DEFAULT '{}',
    last_seen   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS devices (
    id                  TEXT PRIMARY KEY,
    mac                 TEXT UNIQUE,
    ip                  TEXT,
    ipv6                TEXT,
    hostname            TEXT,
    vendor              TEXT,
    category            TEXT NOT NULL DEFAULT 'unknown',
    category_source     TEXT NOT NULL DEFAULT 'auto',
    custom_name         TEXT,
    notes               TEXT,
    interface           TEXT,
    ssid                TEXT,
    online              INTEGER NOT NULL DEFAULT 0,
    first_seen          TEXT NOT NULL,
    last_seen           TEXT NOT NULL,
    last_scan_id        TEXT,
    open_ports          TEXT NOT NULL DEFAULT '[]',
    services            TEXT NOT NULL DEFAULT '[]',
    sources             TEXT NOT NULL DEFAULT '[]',
    is_trusted          INTEGER NOT NULL DEFAULT 0,
    blocked             INTEGER NOT NULL DEFAULT 0,
    blocked_until       TEXT,
    block_source        TEXT,
    limit_download_kbps INTEGER,
    limit_upload_kbps   INTEGER,
    limit_expires_at    TEXT,
    priority            INTEGER,
    enforcement         TEXT NOT NULL DEFAULT 'none',
    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_devices_ip ON devices(ip);
CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_devices_interface ON devices(interface);

CREATE TABLE IF NOT EXISTS device_history (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id   TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    ts          TEXT NOT NULL,
    event       TEXT NOT NULL,
    detail      TEXT,
    scan_id     TEXT
);
CREATE INDEX IF NOT EXISTS idx_history_device ON device_history(device_id, ts DESC);

CREATE TABLE IF NOT EXISTS scanning_sessions (
    id          TEXT PRIMARY KEY,
    interface   TEXT NOT NULL,
    cidr        TEXT NOT NULL,
    methods     TEXT NOT NULL,
    started_at  TEXT NOT NULL,
    finished_at TEXT,
    status      TEXT NOT NULL,
    hosts_found INTEGER NOT NULL DEFAULT 0,
    error       TEXT,
    privileged  INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_scans_started ON scanning_sessions(started_at DESC);

CREATE TABLE IF NOT EXISTS router_configs (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    kind            TEXT NOT NULL,
    host            TEXT NOT NULL,
    port            INTEGER NOT NULL,
    username        TEXT,
    secret_enc      TEXT,
    site            TEXT,
    interface_hint  TEXT,
    tls             INTEGER NOT NULL DEFAULT 0,
    tls_insecure    INTEGER NOT NULL DEFAULT 0,
    enabled         INTEGER NOT NULL DEFAULT 1,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS access_rules (
    id                  TEXT PRIMARY KEY,
    device_id           TEXT REFERENCES devices(id) ON DELETE SET NULL,
    mac                 TEXT,
    ip                  TEXT,
    action              TEXT NOT NULL,
    reason              TEXT,
    gateway_config_id   TEXT REFERENCES router_configs(id) ON DELETE SET NULL,
    state               TEXT NOT NULL,
    created_by          TEXT,
    created_at          TEXT NOT NULL,
    expires_at          TEXT,
    last_error          TEXT
);
CREATE INDEX IF NOT EXISTS idx_access_rules_device ON access_rules(device_id);

CREATE TABLE IF NOT EXISTS bandwidth_rules (
    id                  TEXT PRIMARY KEY,
    device_id           TEXT REFERENCES devices(id) ON DELETE SET NULL,
    mac                 TEXT,
    ip                  TEXT,
    download_kbps       INTEGER,
    upload_kbps         INTEGER,
    priority            INTEGER,
    gateway_config_id   TEXT REFERENCES router_configs(id) ON DELETE SET NULL,
    state               TEXT NOT NULL,
    created_at          TEXT NOT NULL,
    expires_at          TEXT,
    last_error          TEXT
);
CREATE INDEX IF NOT EXISTS idx_bandwidth_rules_device ON bandwidth_rules(device_id);

CREATE TABLE IF NOT EXISTS trusted_devices (
    device_id   TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    added_at    TEXT NOT NULL,
    note        TEXT
);

CREATE TABLE IF NOT EXISTS monitoring_records (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    ts                  TEXT NOT NULL,
    interface           TEXT,
    device_id           TEXT REFERENCES devices(id) ON DELETE CASCADE,
    rx_bps              INTEGER NOT NULL DEFAULT 0,
    tx_bps              INTEGER NOT NULL DEFAULT 0,
    rx_bytes            INTEGER,
    tx_bytes            INTEGER,
    source              TEXT NOT NULL,
    gateway_config_id   TEXT
);
CREATE INDEX IF NOT EXISTS idx_monitoring_ts ON monitoring_records(ts DESC);
CREATE INDEX IF NOT EXISTS idx_monitoring_interface ON monitoring_records(interface, ts DESC);
CREATE INDEX IF NOT EXISTS idx_monitoring_device ON monitoring_records(device_id, ts DESC);

CREATE TABLE IF NOT EXISTS app_settings (
    key     TEXT PRIMARY KEY,
    value   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT NOT NULL,
    actor       TEXT NOT NULL,
    action      TEXT NOT NULL,
    target      TEXT,
    outcome     TEXT NOT NULL,
    detail      TEXT,
    remote_addr TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_logs(ts DESC);

CREATE TABLE IF NOT EXISTS users (
    id              TEXT PRIMARY KEY,
    username        TEXT NOT NULL UNIQUE,
    password_hash   TEXT NOT NULL,
    role            TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    disabled        INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS auth_sessions (
    token_hash  TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at  TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    last_used   TEXT NOT NULL,
    user_agent  TEXT
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON auth_sessions(user_id);

CREATE TABLE IF NOT EXISTS notifications (
    id          TEXT PRIMARY KEY,
    ts          TEXT NOT NULL,
    level       TEXT NOT NULL,
    title       TEXT NOT NULL,
    message     TEXT NOT NULL,
    device_id   TEXT,
    acknowledged INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_notifications_ts ON notifications(ts DESC);
