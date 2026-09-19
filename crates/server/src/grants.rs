//! Who may connect to what. Users are put in user groups and devices in
//! device groups; a grant lets a user group at a device group with a role
//! (`nearhand_core::grant::Role`). A user's role on a device is the highest
//! any of their grants gives; none, and they cannot reach it.
//!
//! Administrators manage all of this, and are no exception to it: to
//! connect to a device, an administrator needs a grant like anyone else.
//!
//! When a user asks for a device, the rendezvous signs a grant for it with
//! the server's key, and the agent checks that (`nearhand_transport::grant`).

use std::collections::HashMap;

use nearhand_core::grant::{Grant, LIFETIME_SECS, Role, SignedGrant};
use nearhand_transport::{Fingerprint, Identity};
use ring::rand::{SecureRandom, SystemRandom};
use serde::Serialize;
use sqlx::SqlitePool;

use crate::accounts::{Refused, check_name, internal};
use crate::db::now;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UserGroup {
    pub id: i64,
    pub name: String,
    pub members: Vec<Member>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Member {
    pub id: i64,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GrantRule {
    pub id: i64,
    pub user_group_id: i64,
    pub user_group: String,
    pub device_group_id: i64,
    pub device_group: String,
    pub role: String,
}

/// A device a user may reach, and how.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reachable {
    /// The device's row.
    pub id: i64,
    pub fingerprint: Fingerprint,
    pub role: Role,
}

pub struct Grants {
    pool: SqlitePool,
}

/// A grant for `user` on `device`, signed with the server's key: good for
/// [`LIFETIME_SECS`], once.
pub fn issue(identity: &Identity, device: &Reachable, user: &str) -> anyhow::Result<SignedGrant> {
    let mut nonce = [0u8; 16];
    SystemRandom::new()
        .fill(&mut nonce)
        .map_err(|_| anyhow::anyhow!("the system random number generator failed"))?;
    let issued_at = now().max(0) as u64;
    let grant = Grant {
        device: *device.fingerprint.as_bytes(),
        user: user.to_owned(),
        role: device.role,
        issued_at,
        expires_at: issued_at + LIFETIME_SECS,
        nonce,
    };
    Ok(identity.sign_grant(&grant)?)
}

type GrantRow = (i64, i64, String, i64, String, String);

impl Grants {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    // --- User groups ------------------------------------------------------------------

    pub async fn user_groups(&self) -> Result<Vec<UserGroup>, Refused> {
        let groups: Vec<(i64, String)> =
            sqlx::query_as("SELECT id, name FROM user_groups ORDER BY name")
                .fetch_all(&self.pool)
                .await
                .map_err(internal)?;
        let members: Vec<(i64, i64, String)> = sqlx::query_as(
            "SELECT user_group_id, users.id, users.name FROM user_group_members \
             JOIN users ON users.id = user_group_members.user_id ORDER BY users.name",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(internal)?;
        Ok(groups
            .into_iter()
            .map(|(id, name)| UserGroup {
                id,
                name,
                members: members
                    .iter()
                    .filter(|(group, _, _)| *group == id)
                    .map(|(_, id, name)| Member {
                        id: *id,
                        name: name.clone(),
                    })
                    .collect(),
            })
            .collect())
    }

    pub async fn user_group(&self, id: i64) -> Result<UserGroup, Refused> {
        self.user_groups()
            .await?
            .into_iter()
            .find(|g| g.id == id)
            .ok_or(Refused::NotFound)
    }

    pub async fn create_user_group(&self, name: &str) -> Result<UserGroup, Refused> {
        check_name(name)?;
        let (id,): (i64,) = sqlx::query_as(
            "INSERT INTO user_groups (name, created_at) VALUES (?, ?) \
             ON CONFLICT (name) DO NOTHING RETURNING id",
        )
        .bind(name)
        .bind(now())
        .fetch_optional(&self.pool)
        .await
        .map_err(internal)?
        .ok_or_else(|| Refused::Invalid(format!("there is a group called {name} already")))?;
        self.user_group(id).await
    }

    pub async fn rename_user_group(&self, id: i64, name: &str) -> Result<UserGroup, Refused> {
        check_name(name)?;
        let taken: Option<(i64,)> =
            sqlx::query_as("SELECT id FROM user_groups WHERE name = ? AND id != ?")
                .bind(name)
                .bind(id)
                .fetch_optional(&self.pool)
                .await
                .map_err(internal)?;
        if taken.is_some() {
            return Err(Refused::Invalid(format!(
                "there is a group called {name} already"
            )));
        }
        let changed = sqlx::query("UPDATE user_groups SET name = ? WHERE id = ?")
            .bind(name)
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(internal)?;
        if changed.rows_affected() == 0 {
            return Err(Refused::NotFound);
        }
        self.user_group(id).await
    }

    /// Delete a user group, and its grants. Its members stay.
    pub async fn delete_user_group(&self, id: i64) -> Result<(), Refused> {
        let deleted = sqlx::query("DELETE FROM user_groups WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(internal)?;
        if deleted.rows_affected() == 0 {
            return Err(Refused::NotFound);
        }
        Ok(())
    }

    pub async fn add_member(&self, group: i64, user: i64) -> Result<UserGroup, Refused> {
        self.user_group(group).await?;
        let exists: Option<(i64,)> = sqlx::query_as("SELECT id FROM users WHERE id = ?")
            .bind(user)
            .fetch_optional(&self.pool)
            .await
            .map_err(internal)?;
        if exists.is_none() {
            return Err(Refused::NotFound);
        }
        sqlx::query(
            "INSERT INTO user_group_members (user_group_id, user_id) VALUES (?, ?) \
             ON CONFLICT DO NOTHING",
        )
        .bind(group)
        .bind(user)
        .execute(&self.pool)
        .await
        .map_err(internal)?;
        self.user_group(group).await
    }

    pub async fn remove_member(&self, group: i64, user: i64) -> Result<UserGroup, Refused> {
        let removed =
            sqlx::query("DELETE FROM user_group_members WHERE user_group_id = ? AND user_id = ?")
                .bind(group)
                .bind(user)
                .execute(&self.pool)
                .await
                .map_err(internal)?;
        if removed.rows_affected() == 0 {
            return Err(Refused::NotFound);
        }
        self.user_group(group).await
    }

    // --- Grants -------------------------------------------------------------------

    pub async fn grants(&self) -> Result<Vec<GrantRule>, Refused> {
        let rows: Vec<GrantRow> = sqlx::query_as(
            "SELECT grants.id, user_groups.id, user_groups.name, \
             device_groups.id, device_groups.name, grants.role \
             FROM grants \
             JOIN user_groups ON user_groups.id = grants.user_group_id \
             JOIN device_groups ON device_groups.id = grants.device_group_id \
             ORDER BY user_groups.name, device_groups.name",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(internal)?;
        Ok(rows
            .into_iter()
            .map(
                |(id, user_group_id, user_group, device_group_id, device_group, role)| GrantRule {
                    id,
                    user_group_id,
                    user_group,
                    device_group_id,
                    device_group,
                    role,
                },
            )
            .collect())
    }

    async fn grant(&self, id: i64) -> Result<GrantRule, Refused> {
        self.grants()
            .await?
            .into_iter()
            .find(|g| g.id == id)
            .ok_or(Refused::NotFound)
    }

    /// Let `user_group` at `device_group` with `role`; replaces the role of
    /// a grant between the two that exists already.
    pub async fn set_grant(
        &self,
        user_group: i64,
        device_group: i64,
        role: Role,
    ) -> Result<GrantRule, Refused> {
        let groups: Option<(i64, i64)> = sqlx::query_as(
            "SELECT (SELECT count(*) FROM user_groups WHERE id = ?), \
             (SELECT count(*) FROM device_groups WHERE id = ?)",
        )
        .bind(user_group)
        .bind(device_group)
        .fetch_optional(&self.pool)
        .await
        .map_err(internal)?;
        if groups != Some((1, 1)) {
            return Err(Refused::NotFound);
        }
        let (id,): (i64,) = sqlx::query_as(
            "INSERT INTO grants (user_group_id, device_group_id, role, created_at) \
             VALUES (?, ?, ?, ?) \
             ON CONFLICT (user_group_id, device_group_id) DO UPDATE SET role = excluded.role \
             RETURNING id",
        )
        .bind(user_group)
        .bind(device_group)
        .bind(role.as_str())
        .bind(now())
        .fetch_one(&self.pool)
        .await
        .map_err(internal)?;
        self.grant(id).await
    }

    pub async fn delete_grant(&self, id: i64) -> Result<(), Refused> {
        let deleted = sqlx::query("DELETE FROM grants WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(internal)?;
        if deleted.rows_affected() == 0 {
            return Err(Refused::NotFound);
        }
        Ok(())
    }

    /// Every device `user` may reach, with the highest role their grants
    /// give on it.
    pub async fn reachable(&self, user: i64) -> Result<Vec<Reachable>, Refused> {
        let rows: Vec<(i64, Vec<u8>, String)> = sqlx::query_as(
            "SELECT devices.id, devices.fingerprint, grants.role \
             FROM user_group_members \
             JOIN grants ON grants.user_group_id = user_group_members.user_group_id \
             JOIN devices ON devices.group_id = grants.device_group_id \
             JOIN users ON users.id = user_group_members.user_id \
             WHERE user_group_members.user_id = ? AND NOT users.disabled",
        )
        .bind(user)
        .fetch_all(&self.pool)
        .await
        .map_err(internal)?;
        let mut best: HashMap<i64, Reachable> = HashMap::new();
        for (id, fingerprint, role) in rows {
            let (Ok(fingerprint), Ok(role)) = (<[u8; 32]>::try_from(fingerprint), role.parse())
            else {
                continue;
            };
            let entry = best.entry(id).or_insert(Reachable {
                id,
                fingerprint: Fingerprint::from_bytes(fingerprint),
                role,
            });
            entry.role = entry.role.max(role);
        }
        let mut reachable: Vec<Reachable> = best.into_values().collect();
        reachable.sort_by_key(|r| r.id);
        Ok(reachable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::{Accounts, User};
    use crate::devices::Devices;
    use nearhand_core::rendezvous::Enrollment;

    struct World {
        accounts: Accounts,
        devices: Devices,
        grants: Grants,
        admin: User,
    }

    async fn world() -> World {
        let pool = crate::db::in_memory().await;
        let accounts = Accounts::new(pool.clone());
        let token = accounts.new_setup_token().await.expect("token");
        let admin = accounts
            .setup(&token, "ada", "correct horse battery")
            .await
            .expect("setup");
        World {
            accounts,
            devices: Devices::new(pool.clone()),
            grants: Grants::new(pool),
            admin,
        }
    }

    impl World {
        /// Enroll a device with key `n` into `group`.
        async fn device(&self, n: u8, group: Option<i64>) -> i64 {
            let (_, token) = self
                .devices
                .new_enroll_token(&self.admin, "t", group, Some(1), 1)
                .await
                .expect("token");
            self.devices
                .enroll(
                    &Fingerprint::from_bytes([n; 32]),
                    &Enrollment {
                        token,
                        name: format!("PC-{n}"),
                        os: "windows".into(),
                        version: "0.1.0".into(),
                    },
                    "192.0.2.1:1".parse().expect("addr"),
                )
                .await
                .expect("enroll")
                .id
        }
    }

    #[tokio::test]
    async fn the_highest_role_any_grant_gives_wins() {
        let w = world().await;
        let bob = w
            .accounts
            .create_user("bob", "bobs long password", false)
            .await
            .expect("bob");
        let office = w.devices.create_group("Office").await.expect("group");
        let lab = w.devices.create_group("Lab").await.expect("group");
        let pc_office = w.device(1, Some(office.id)).await;
        let pc_lab = w.device(2, Some(lab.id)).await;
        let _loose = w.device(3, None).await;

        let helpdesk = w.grants.create_user_group("Helpdesk").await.expect("group");
        let admins = w.grants.create_user_group("IT").await.expect("group");
        w.grants
            .add_member(helpdesk.id, bob.id)
            .await
            .expect("member");
        w.grants
            .add_member(admins.id, bob.id)
            .await
            .expect("member");
        w.grants
            .set_grant(helpdesk.id, office.id, Role::View)
            .await
            .expect("grant");
        w.grants
            .set_grant(helpdesk.id, lab.id, Role::Control)
            .await
            .expect("grant");
        w.grants
            .set_grant(admins.id, office.id, Role::Full)
            .await
            .expect("grant");

        let reach = w.grants.reachable(bob.id).await.expect("reach");
        let roles: Vec<(i64, Role)> = reach.iter().map(|r| (r.id, r.role)).collect();
        assert_eq!(roles, [(pc_office, Role::Full), (pc_lab, Role::Control)]);
        assert!(
            w.grants
                .reachable(w.admin.id)
                .await
                .expect("reach")
                .is_empty(),
            "administrators need grants too"
        );

        // Setting a grant again changes its role; leaving the group loses it.
        w.grants
            .set_grant(helpdesk.id, lab.id, Role::View)
            .await
            .expect("regrant");
        assert_eq!(w.grants.grants().await.expect("grants").len(), 3);
        w.grants
            .remove_member(admins.id, bob.id)
            .await
            .expect("leave");
        let roles: Vec<Role> = w
            .grants
            .reachable(bob.id)
            .await
            .expect("reach")
            .iter()
            .map(|r| r.role)
            .collect();
        assert_eq!(roles, [Role::View, Role::View]);
    }

    #[tokio::test]
    async fn disabled_users_and_deleted_groups_reach_nothing() {
        let w = world().await;
        let bob = w
            .accounts
            .create_user("bob", "bobs long password", false)
            .await
            .expect("bob");
        let office = w.devices.create_group("Office").await.expect("group");
        w.device(1, Some(office.id)).await;
        let staff = w.grants.create_user_group("Staff").await.expect("group");
        w.grants.add_member(staff.id, bob.id).await.expect("member");
        let rule = w
            .grants
            .set_grant(staff.id, office.id, Role::Control)
            .await
            .expect("grant");
        assert_eq!(rule.role, "control");
        assert_eq!(rule.user_group, "Staff");
        assert_eq!(w.grants.reachable(bob.id).await.expect("reach").len(), 1);

        w.accounts
            .update_user(bob.id, None, Some(true))
            .await
            .expect("disable");
        assert!(w.grants.reachable(bob.id).await.expect("reach").is_empty());
        w.accounts
            .update_user(bob.id, None, Some(false))
            .await
            .expect("enable");

        w.devices.delete_group(office.id).await.expect("delete");
        assert!(w.grants.grants().await.expect("grants").is_empty());
        assert!(w.grants.reachable(bob.id).await.expect("reach").is_empty());
        w.grants.delete_user_group(staff.id).await.expect("delete");
        assert!(w.grants.user_groups().await.expect("groups").is_empty());
    }

    #[tokio::test]
    async fn groups_check_what_they_are_given() {
        let w = world().await;
        let staff = w.grants.create_user_group("Staff").await.expect("group");
        assert!(w.grants.create_user_group("staff").await.is_err());
        assert_eq!(
            w.grants.add_member(staff.id, 999).await,
            Err(Refused::NotFound)
        );
        assert_eq!(
            w.grants.add_member(999, w.admin.id).await,
            Err(Refused::NotFound)
        );
        assert_eq!(
            w.grants.set_grant(staff.id, 999, Role::View).await,
            Err(Refused::NotFound)
        );
        let with_ada = w
            .grants
            .add_member(staff.id, w.admin.id)
            .await
            .expect("add");
        assert_eq!(with_ada.members[0].name, "ada");
        let again = w
            .grants
            .add_member(staff.id, w.admin.id)
            .await
            .expect("again");
        assert_eq!(again.members.len(), 1);
        let renamed = w
            .grants
            .rename_user_group(staff.id, "Everyone")
            .await
            .expect("rename");
        assert_eq!(renamed.name, "Everyone");
    }
}
