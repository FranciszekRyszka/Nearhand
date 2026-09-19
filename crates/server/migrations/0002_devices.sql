-- Managed devices: the machines enrolled with this server, the groups they
-- are sorted into, and the tokens that enroll them.
--
-- A device is known by its key: `fingerprint` is the SHA-256 of its
-- certificate, and its ten-digit ID is derived from that. Whether it is
-- online is not stored — the server knows from the connection it keeps —
-- but when it was last seen is.

CREATE TABLE device_groups (
    id          INTEGER PRIMARY KEY,
    name        TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    created_at  INTEGER NOT NULL
);

CREATE TABLE devices (
    id            INTEGER PRIMARY KEY,
    fingerprint   BLOB    NOT NULL UNIQUE,
    name          TEXT    NOT NULL,
    group_id      INTEGER REFERENCES device_groups (id) ON DELETE SET NULL,
    -- What the agent said it runs on, and which version it is.
    os            TEXT    NOT NULL,
    version       TEXT    NOT NULL,
    enrolled_at   INTEGER NOT NULL,
    last_seen_at  INTEGER,
    -- The address the server last saw it connect from.
    last_address  TEXT
);

-- Tokens that enroll devices, by the SHA-256 of the token. `uses_left` NULL
-- means any number, until it expires.
CREATE TABLE enroll_tokens (
    id           INTEGER PRIMARY KEY,
    token_hash   BLOB    NOT NULL UNIQUE,
    name         TEXT    NOT NULL,
    -- Deleting a group deletes the tokens that enroll into it.
    group_id     INTEGER REFERENCES device_groups (id) ON DELETE CASCADE,
    uses_left    INTEGER,
    used         INTEGER NOT NULL DEFAULT 0,
    created_by   INTEGER REFERENCES users (id) ON DELETE SET NULL,
    created_at   INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL
);
