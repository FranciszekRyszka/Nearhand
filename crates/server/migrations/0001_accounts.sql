-- Accounts: the people who use the console and the API.
--
-- Times are Unix seconds. Secrets that authenticate — sign-in sessions, API
-- tokens, setup tokens — are stored as their SHA-256, never as themselves:
-- a copy of the database does not let anyone sign in.

CREATE TABLE users (
    id              INTEGER PRIMARY KEY,
    name            TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    -- Argon2id, as a PHC string.
    password_hash   TEXT    NOT NULL,
    admin           INTEGER NOT NULL DEFAULT 0,
    disabled        INTEGER NOT NULL DEFAULT 0,
    -- TOTP, once confirmed; a secret waiting for its first code is pending.
    totp_secret     BLOB,
    totp_pending    BLOB,
    -- The last 30-second step a code was used in: each code works once.
    totp_last_step  INTEGER,
    created_at      INTEGER NOT NULL
);

-- Signed-in console sessions, by the SHA-256 of their cookie.
CREATE TABLE logins (
    token_hash  BLOB    PRIMARY KEY,
    user_id     INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL
);

-- Tokens for the REST API, by the SHA-256 of the token.
CREATE TABLE api_tokens (
    id            INTEGER PRIMARY KEY,
    user_id       INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    name          TEXT    NOT NULL,
    token_hash    BLOB    NOT NULL UNIQUE,
    created_at    INTEGER NOT NULL,
    last_used_at  INTEGER,
    expires_at    INTEGER
);

-- The one-time link that creates the first administrator.
CREATE TABLE setup_tokens (
    token_hash  BLOB    PRIMARY KEY,
    expires_at  INTEGER NOT NULL
);
