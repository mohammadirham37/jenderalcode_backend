CREATE TABLE users (
    id          TEXT PRIMARY KEY,
    google_sub  TEXT NOT NULL UNIQUE,
    email       TEXT NOT NULL,
    name        TEXT NOT NULL,
    created_at  INTEGER NOT NULL
);

CREATE TABLE devices (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind        TEXT NOT NULL CHECK (kind IN ('desktop', 'mobile')),
    name        TEXT NOT NULL,
    public_key  TEXT NOT NULL,
    token_hash  TEXT NOT NULL UNIQUE,
    created_at  INTEGER NOT NULL,
    last_seen   INTEGER,
    revoked_at  INTEGER
);
CREATE INDEX devices_user ON devices(user_id);

CREATE TABLE pairs (
    desktop_id  TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    mobile_id   TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    created_at  INTEGER NOT NULL,
    PRIMARY KEY (desktop_id, mobile_id)
);
CREATE INDEX pairs_mobile ON pairs(mobile_id);

CREATE TABLE pairings (
    id                   TEXT PRIMARY KEY,
    code_hash            TEXT NOT NULL UNIQUE,
    wait_secret_hash     TEXT NOT NULL,
    desktop_public_key   TEXT NOT NULL,
    desktop_name         TEXT NOT NULL,
    existing_desktop_id  TEXT REFERENCES devices(id) ON DELETE CASCADE,
    claimed_by           TEXT REFERENCES devices(id) ON DELETE CASCADE,
    expires_at           INTEGER NOT NULL,
    consumed_at          INTEGER
);
CREATE INDEX pairings_expires ON pairings(expires_at);
