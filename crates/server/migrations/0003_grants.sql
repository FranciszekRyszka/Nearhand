-- Who may connect to what: users are put in user groups, devices in device
-- groups, and a grant lets a user group at a device group with a role.
-- A user's role on a device is the highest any of their grants gives.

CREATE TABLE user_groups (
    id          INTEGER PRIMARY KEY,
    name        TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    created_at  INTEGER NOT NULL
);

CREATE TABLE user_group_members (
    user_group_id  INTEGER NOT NULL REFERENCES user_groups (id) ON DELETE CASCADE,
    user_id        INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    PRIMARY KEY (user_group_id, user_id)
);

CREATE TABLE grants (
    id               INTEGER PRIMARY KEY,
    user_group_id    INTEGER NOT NULL REFERENCES user_groups (id) ON DELETE CASCADE,
    device_group_id  INTEGER NOT NULL REFERENCES device_groups (id) ON DELETE CASCADE,
    role             TEXT    NOT NULL CHECK (role IN ('view', 'control', 'full')),
    created_at       INTEGER NOT NULL,
    UNIQUE (user_group_id, device_group_id)
);
