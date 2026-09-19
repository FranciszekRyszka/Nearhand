-- The audit log: who did what, when, from where. Rows are only ever added.
-- `actor` is the user's name as it was then, so the log still reads right
-- after a user is renamed or deleted.

CREATE TABLE audit_log (
    id       INTEGER PRIMARY KEY,
    at       INTEGER NOT NULL,
    actor    TEXT,
    address  TEXT,
    action   TEXT    NOT NULL,
    target   TEXT,
    detail   TEXT
);

CREATE INDEX audit_log_at ON audit_log (at);
