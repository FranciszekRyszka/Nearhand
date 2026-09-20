-- Agent releases this server holds for its agents, and which of them each
-- product and platform is offered. The packages are files in the data
-- folder's `releases`, named by their SHA-256; `signature` is the signature
-- file that came with each, as uploaded, for agents to check.

CREATE TABLE releases (
    id          INTEGER PRIMARY KEY,
    product     TEXT    NOT NULL,
    platform    TEXT    NOT NULL,
    version     TEXT    NOT NULL,
    package     TEXT    NOT NULL,
    sha256      BLOB    NOT NULL UNIQUE,
    size        INTEGER NOT NULL,
    signature   TEXT    NOT NULL,
    uploaded_at INTEGER NOT NULL,
    offered     INTEGER NOT NULL DEFAULT 0
);

-- At most one release on offer per product and platform.
CREATE UNIQUE INDEX releases_offered ON releases (product, platform) WHERE offered = 1;
