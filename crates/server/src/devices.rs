//! Managed devices: the machines enrolled with this server, the groups they
//! are sorted into, and the tokens that enroll them.
//!
//! * An administrator makes an enrollment token: for one device or many,
//!   for a while, optionally into a group. It is a random 256-bit value
//!   handed out once and kept only as its SHA-256, like every other token.
//! * An agent installed with it connects with its certificate and sends it
//!   (`nearhand_core::rendezvous::ToServer::Enroll`); the server records the
//!   certificate's fingerprint. Enrolling again — a reinstall that kept its
//!   key — updates the same device.
//! * Whether a device is online is not stored: the rendezvous registry knows.
//!   When it was last seen, and from where, is.

use std::net::SocketAddr;

use anyhow::Result;
use nearhand_core::rendezvous::{DeviceId, Enrollment};
use nearhand_transport::Fingerprint;
use ring::rand::SystemRandom;
use serde::Serialize;
use sqlx::SqlitePool;

use crate::accounts::{Refused, User, check_name, hash, internal, random_token};
use crate::db::now;

const ENROLL_PREFIX: &str = "nhe_";
/// The longest an enrollment token lasts: a rollout, not a standing secret.
pub const MAX_ENROLL_DAYS: u32 = 90;
/// Longest name, OS or version an agent may report; longer is cut.
const MAX_REPORTED: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Device {
    pub id: i64,
    /// The ten-digit ID, spaced as people read it.
    pub device_id: String,
    /// SHA-256 of the device's certificate, in hex: what viewers pin.
    pub fingerprint: String,
    pub name: String,
    pub group_id: Option<i64>,
    pub group: Option<String>,
    pub os: String,
    pub version: String,
    pub enrolled_at: i64,
    pub last_seen_at: Option<i64>,
    pub last_address: Option<String>,
    /// Filled in by whoever knows: the registry.
    pub online: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Group {
    pub id: i64,
    pub name: String,
    pub devices: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EnrollToken {
    pub id: i64,
    pub name: String,
    pub group_id: Option<i64>,
    /// None: any number, until it expires.
    pub uses_left: Option<i64>,
    pub used: i64,
    pub created_at: i64,
    pub expires_at: i64,
}

type DeviceRow = (
    i64,
    Vec<u8>,
    String,
    Option<i64>,
    Option<String>,
    String,
    String,
    i64,
    Option<i64>,
    Option<String>,
);

fn device_of(
    (
        id,
        fingerprint,
        name,
        group_id,
        group,
        os,
        version,
        enrolled_at,
        last_seen_at,
        last_address,
    ): DeviceRow,
) -> Device {
    let (device_id, fingerprint) = match <[u8; 32]>::try_from(fingerprint.as_slice()) {
        Ok(bytes) => (
            DeviceId::from_fingerprint(&bytes).to_string(),
            Fingerprint::from_bytes(bytes).to_string(),
        ),
        Err(_) => (String::new(), String::new()),
    };
    Device {
        id,
        device_id,
        fingerprint,
        name,
        group_id,
        group,
        os,
        version,
        enrolled_at,
        last_seen_at,
        last_address,
        online: false,
    }
}

type TokenRow = (i64, String, Option<i64>, Option<i64>, i64, i64, i64);

fn token_of(
    (id, name, group_id, uses_left, used, created_at, expires_at): TokenRow,
) -> EnrollToken {
    EnrollToken {
        id,
        name,
        group_id,
        uses_left,
        used,
        created_at,
        expires_at,
    }
}

pub struct Devices {
    pool: SqlitePool,
    random: SystemRandom,
}

impl Devices {
    pub fn new(pool: SqlitePool) -> Self {
        Self {
            pool,
            random: SystemRandom::new(),
        }
    }

    // --- Groups -------------------------------------------------------------------

    pub async fn groups(&self) -> Result<Vec<Group>, Refused> {
        let rows: Vec<(i64, String, i64)> = sqlx::query_as(
            "SELECT device_groups.id, device_groups.name, count(devices.id) \
             FROM device_groups LEFT JOIN devices ON devices.group_id = device_groups.id \
             GROUP BY device_groups.id ORDER BY device_groups.name",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(internal)?;
        Ok(rows
            .into_iter()
            .map(|(id, name, devices)| Group { id, name, devices })
            .collect())
    }

    async fn group(&self, id: i64) -> Result<Group, Refused> {
        self.groups()
            .await?
            .into_iter()
            .find(|g| g.id == id)
            .ok_or(Refused::NotFound)
    }

    pub async fn create_group(&self, name: &str) -> Result<Group, Refused> {
        check_name(name)?;
        let (id,): (i64,) = sqlx::query_as(
            "INSERT INTO device_groups (name, created_at) VALUES (?, ?) \
             ON CONFLICT (name) DO NOTHING RETURNING id",
        )
        .bind(name)
        .bind(now())
        .fetch_optional(&self.pool)
        .await
        .map_err(internal)?
        .ok_or_else(|| Refused::Invalid(format!("there is a group called {name} already")))?;
        self.group(id).await
    }

    pub async fn rename_group(&self, id: i64, name: &str) -> Result<Group, Refused> {
        check_name(name)?;
        let taken: Option<(i64,)> =
            sqlx::query_as("SELECT id FROM device_groups WHERE name = ? AND id != ?")
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
        let changed = sqlx::query("UPDATE device_groups SET name = ? WHERE id = ?")
            .bind(name)
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(internal)?;
        if changed.rows_affected() == 0 {
            return Err(Refused::NotFound);
        }
        self.group(id).await
    }

    /// Delete a group. Its devices stay, in no group; the tokens that
    /// enroll into it go.
    pub async fn delete_group(&self, id: i64) -> Result<(), Refused> {
        let deleted = sqlx::query("DELETE FROM device_groups WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(internal)?;
        if deleted.rows_affected() == 0 {
            return Err(Refused::NotFound);
        }
        Ok(())
    }

    // --- Enrollment tokens ----------------------------------------------------------

    /// A new enrollment token, shown this once. `uses` None means any
    /// number of devices until it expires.
    pub async fn new_enroll_token(
        &self,
        by: &User,
        name: &str,
        group_id: Option<i64>,
        uses: Option<u32>,
        lifetime_days: u32,
    ) -> Result<(EnrollToken, String), Refused> {
        check_name(name)?;
        if !(1..=MAX_ENROLL_DAYS).contains(&lifetime_days) {
            return Err(Refused::Invalid(format!(
                "an enrollment token lasts 1 to {MAX_ENROLL_DAYS} days"
            )));
        }
        if uses == Some(0) {
            return Err(Refused::Invalid(
                "a token for no devices enrolls none".into(),
            ));
        }
        if let Some(group) = group_id {
            self.group(group).await?;
        }
        let token = random_token(&self.random, ENROLL_PREFIX).map_err(internal)?;
        let (id,): (i64,) = sqlx::query_as(
            "INSERT INTO enroll_tokens \
             (token_hash, name, group_id, uses_left, created_by, created_at, expires_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING id",
        )
        .bind(hash(&token))
        .bind(name)
        .bind(group_id)
        .bind(uses.map(i64::from))
        .bind(by.id)
        .bind(now())
        .bind(now() + i64::from(lifetime_days) * 86_400)
        .fetch_one(&self.pool)
        .await
        .map_err(internal)?;
        let listed = self
            .enroll_tokens()
            .await?
            .into_iter()
            .find(|t| t.id == id)
            .ok_or(Refused::NotFound)?;
        Ok((listed, token))
    }

    /// The tokens that still enroll: not expired, not used up. The rest are
    /// deleted on the way.
    pub async fn enroll_tokens(&self) -> Result<Vec<EnrollToken>, Refused> {
        sqlx::query("DELETE FROM enroll_tokens WHERE expires_at <= ? OR uses_left = 0")
            .bind(now())
            .execute(&self.pool)
            .await
            .map_err(internal)?;
        let rows: Vec<TokenRow> = sqlx::query_as(
            "SELECT id, name, group_id, uses_left, used, created_at, expires_at \
             FROM enroll_tokens ORDER BY created_at DESC, id DESC",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(internal)?;
        Ok(rows.into_iter().map(token_of).collect())
    }

    pub async fn delete_enroll_token(&self, id: i64) -> Result<(), Refused> {
        let deleted = sqlx::query("DELETE FROM enroll_tokens WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(internal)?;
        if deleted.rows_affected() == 0 {
            return Err(Refused::NotFound);
        }
        Ok(())
    }

    /// Enroll the device with this certificate, if the token is good: it
    /// counts one use of it. A device enrolled already is updated, and moved
    /// into the token's group if it names one.
    pub async fn enroll(
        &self,
        fingerprint: &Fingerprint,
        enrollment: &Enrollment,
        from: SocketAddr,
    ) -> Result<Device, Refused> {
        let mut tx = self.pool.begin().await.map_err(internal)?;
        let token: Option<(i64, Option<i64>)> = sqlx::query_as(
            "UPDATE enroll_tokens SET used = used + 1, uses_left = uses_left - 1 \
             WHERE token_hash = ? AND expires_at > ? AND (uses_left IS NULL OR uses_left > 0) \
             RETURNING id, group_id",
        )
        .bind(hash(&enrollment.token))
        .bind(now())
        .fetch_optional(&mut *tx)
        .await
        .map_err(internal)?;
        let Some((_, group_id)) = token else {
            return Err(Refused::Forbidden);
        };
        let name = reported(&enrollment.name, "unnamed");
        let (id,): (i64,) = sqlx::query_as(
            "INSERT INTO devices \
             (fingerprint, name, group_id, os, version, enrolled_at, last_seen_at, last_address) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?) \
             ON CONFLICT (fingerprint) DO UPDATE SET \
             name = excluded.name, group_id = coalesce(excluded.group_id, devices.group_id), \
             os = excluded.os, version = excluded.version, enrolled_at = excluded.enrolled_at, \
             last_seen_at = excluded.last_seen_at, last_address = excluded.last_address \
             RETURNING id",
        )
        .bind(fingerprint.as_bytes().as_slice())
        .bind(&name)
        .bind(group_id)
        .bind(reported(&enrollment.os, "unknown"))
        .bind(reported(&enrollment.version, "unknown"))
        .bind(now())
        .bind(now())
        .bind(from.to_string())
        .fetch_one(&mut *tx)
        .await
        .map_err(internal)?;
        tx.commit().await.map_err(internal)?;
        self.device(id).await
    }

    // --- Devices --------------------------------------------------------------------

    pub async fn devices(&self) -> Result<Vec<Device>, Refused> {
        let rows: Vec<DeviceRow> = sqlx::query_as(
            "SELECT devices.id, fingerprint, devices.name, group_id, device_groups.name, \
             os, version, enrolled_at, last_seen_at, last_address \
             FROM devices LEFT JOIN device_groups ON device_groups.id = devices.group_id \
             ORDER BY devices.name COLLATE NOCASE, devices.id",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(internal)?;
        Ok(rows.into_iter().map(device_of).collect())
    }

    pub async fn device(&self, id: i64) -> Result<Device, Refused> {
        let row: Option<DeviceRow> = sqlx::query_as(
            "SELECT devices.id, fingerprint, devices.name, group_id, device_groups.name, \
             os, version, enrolled_at, last_seen_at, last_address \
             FROM devices LEFT JOIN device_groups ON device_groups.id = devices.group_id \
             WHERE devices.id = ?",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(internal)?;
        row.map(device_of).ok_or(Refused::NotFound)
    }

    /// Rename a device, or move it: `group` Some(None) takes it out of its
    /// group.
    pub async fn update_device(
        &self,
        id: i64,
        name: Option<&str>,
        group: Option<Option<i64>>,
    ) -> Result<Device, Refused> {
        self.device(id).await?;
        if let Some(name) = name {
            check_name(name)?;
            sqlx::query("UPDATE devices SET name = ? WHERE id = ?")
                .bind(name)
                .bind(id)
                .execute(&self.pool)
                .await
                .map_err(internal)?;
        }
        if let Some(group) = group {
            if let Some(group) = group {
                self.group(group).await?;
            }
            sqlx::query("UPDATE devices SET group_id = ? WHERE id = ?")
                .bind(group)
                .bind(id)
                .execute(&self.pool)
                .await
                .map_err(internal)?;
        }
        self.device(id).await
    }

    /// Forget a device. The agent can still register — it is no longer
    /// managed, and a new token enrolls it again.
    pub async fn delete_device(&self, id: i64) -> Result<(), Refused> {
        let deleted = sqlx::query("DELETE FROM devices WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(internal)?;
        if deleted.rows_affected() == 0 {
            return Err(Refused::NotFound);
        }
        Ok(())
    }

    pub async fn is_enrolled(&self, fingerprint: &Fingerprint) -> Result<bool> {
        let row: Option<(i64,)> = sqlx::query_as("SELECT id FROM devices WHERE fingerprint = ?")
            .bind(fingerprint.as_bytes().as_slice())
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.is_some())
    }

    /// Note that the device with this certificate is here now, from `from`;
    /// nothing if it is not enrolled.
    pub async fn seen(&self, fingerprint: &Fingerprint, from: SocketAddr) -> Result<()> {
        sqlx::query("UPDATE devices SET last_seen_at = ?, last_address = ? WHERE fingerprint = ?")
            .bind(now())
            .bind(from.to_string())
            .bind(fingerprint.as_bytes().as_slice())
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

/// Something an agent reported, fit to list: trimmed, cut short, and never
/// empty.
fn reported(text: &str, fallback: &str) -> String {
    let text: String = text
        .trim()
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_REPORTED)
        .collect();
    let text = text.trim();
    if text.is_empty() {
        fallback.to_owned()
    } else {
        text.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::Accounts;

    const HERE: SocketAddr = SocketAddr::V4(std::net::SocketAddrV4::new(
        std::net::Ipv4Addr::new(198, 51, 100, 7),
        50000,
    ));

    async fn with_admin() -> (Devices, User) {
        let pool = crate::db::in_memory().await;
        let accounts = Accounts::new(pool.clone());
        let token = accounts.new_setup_token().await.expect("token");
        let admin = accounts
            .setup(&token, "ada", "correct horse battery")
            .await
            .expect("setup");
        (Devices::new(pool), admin)
    }

    fn enrollment(token: &str, name: &str) -> Enrollment {
        Enrollment {
            token: token.into(),
            name: name.into(),
            os: "windows x86_64".into(),
            version: "0.1.0".into(),
        }
    }

    fn key(n: u8) -> Fingerprint {
        Fingerprint::from_bytes([n; 32])
    }

    #[tokio::test]
    async fn a_token_enrolls_as_many_devices_as_it_is_for() {
        let (devices, admin) = with_admin().await;
        let (listed, token) = devices
            .new_enroll_token(&admin, "office", None, Some(2), 7)
            .await
            .expect("token");
        assert!(token.starts_with("nhe_"));
        assert_eq!(listed.uses_left, Some(2));

        let first = devices
            .enroll(&key(1), &enrollment(&token, "RECEPTION"), HERE)
            .await
            .expect("first");
        assert_eq!(first.name, "RECEPTION");
        assert_eq!(
            first.device_id,
            DeviceId::from_fingerprint(&[1; 32]).to_string()
        );
        assert_eq!(first.last_address.as_deref(), Some("198.51.100.7:50000"));
        devices
            .enroll(&key(2), &enrollment(&token, "BACK-OFFICE"), HERE)
            .await
            .expect("second");
        assert_eq!(
            devices
                .enroll(&key(3), &enrollment(&token, "ONE-TOO-MANY"), HERE)
                .await,
            Err(Refused::Forbidden)
        );
        assert_eq!(devices.devices().await.expect("list").len(), 2);
        assert!(
            devices.enroll_tokens().await.expect("tokens").is_empty(),
            "used up, and gone"
        );
    }

    #[tokio::test]
    async fn wrong_and_deleted_tokens_enroll_nothing() {
        let (devices, admin) = with_admin().await;
        assert_eq!(
            devices
                .enroll(&key(1), &enrollment("nhe_guess", "X"), HERE)
                .await,
            Err(Refused::Forbidden)
        );
        let (listed, token) = devices
            .new_enroll_token(&admin, "any", None, None, 1)
            .await
            .expect("token");
        devices
            .delete_enroll_token(listed.id)
            .await
            .expect("delete");
        assert_eq!(
            devices
                .enroll(&key(1), &enrollment(&token, "X"), HERE)
                .await,
            Err(Refused::Forbidden)
        );
        assert!(
            devices
                .new_enroll_token(&admin, "forever", None, None, MAX_ENROLL_DAYS + 1)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn enrolling_again_updates_the_same_device() {
        let (devices, admin) = with_admin().await;
        let lab = devices.create_group("Lab").await.expect("group");
        let (_, into_lab) = devices
            .new_enroll_token(&admin, "lab", Some(lab.id), None, 1)
            .await
            .expect("token");
        let (_, anywhere) = devices
            .new_enroll_token(&admin, "any", None, None, 1)
            .await
            .expect("token");

        let first = devices
            .enroll(&key(1), &enrollment(&into_lab, "PC-1"), HERE)
            .await
            .expect("enroll");
        assert_eq!(first.group.as_deref(), Some("Lab"));
        let again = devices
            .enroll(&key(1), &enrollment(&anywhere, "PC-1-RENAMED"), HERE)
            .await
            .expect("again");
        assert_eq!(again.id, first.id);
        assert_eq!(again.name, "PC-1-RENAMED");
        assert_eq!(
            again.group_id,
            Some(lab.id),
            "a token without a group keeps it"
        );
        assert_eq!(devices.devices().await.expect("list").len(), 1);
    }

    #[tokio::test]
    async fn groups_hold_devices_and_let_them_go() {
        let (devices, admin) = with_admin().await;
        let lab = devices.create_group("Lab").await.expect("group");
        assert!(
            devices.create_group("lab").await.is_err(),
            "names are unique"
        );
        let (_, token) = devices
            .new_enroll_token(&admin, "lab", Some(lab.id), None, 1)
            .await
            .expect("token");
        let pc = devices
            .enroll(&key(1), &enrollment(&token, "PC"), HERE)
            .await
            .expect("enroll");
        assert_eq!(devices.groups().await.expect("groups")[0].devices, 1);

        let office = devices.create_group("Office").await.expect("group");
        let moved = devices
            .update_device(pc.id, Some("Front desk"), Some(Some(office.id)))
            .await
            .expect("move");
        assert_eq!(moved.name, "Front desk");
        assert_eq!(moved.group.as_deref(), Some("Office"));
        assert_eq!(
            devices.update_device(pc.id, None, Some(Some(999))).await,
            Err(Refused::NotFound)
        );
        assert!(devices.rename_group(lab.id, "office").await.is_err());
        devices
            .rename_group(lab.id, "Workshop")
            .await
            .expect("rename");

        devices.delete_group(office.id).await.expect("delete");
        let pc = devices.device(pc.id).await.expect("still there");
        assert_eq!(pc.group_id, None);
        devices.delete_group(lab.id).await.expect("delete");
        assert!(
            devices.enroll_tokens().await.expect("tokens").is_empty(),
            "the group's token went with it"
        );
    }

    #[tokio::test]
    async fn presence_is_noted_for_enrolled_devices_only() {
        let (devices, admin) = with_admin().await;
        let (_, token) = devices
            .new_enroll_token(&admin, "one", None, Some(1), 1)
            .await
            .expect("token");
        let pc = devices
            .enroll(&key(1), &enrollment(&token, "PC"), HERE)
            .await
            .expect("enroll");
        assert!(devices.is_enrolled(&key(1)).await.expect("query"));
        assert!(!devices.is_enrolled(&key(2)).await.expect("query"));
        let elsewhere: SocketAddr = "203.0.113.9:40000".parse().expect("addr");
        devices.seen(&key(1), elsewhere).await.expect("seen");
        devices
            .seen(&key(2), elsewhere)
            .await
            .expect("not enrolled");
        let pc = devices.device(pc.id).await.expect("device");
        assert_eq!(pc.last_address.as_deref(), Some("203.0.113.9:40000"));
        assert_eq!(devices.devices().await.expect("list").len(), 1);

        devices.delete_device(pc.id).await.expect("forget");
        assert!(!devices.is_enrolled(&key(1)).await.expect("query"));
    }

    #[test]
    fn reported_text_is_tidied() {
        assert_eq!(reported("  PC-1\n", "x"), "PC-1");
        assert_eq!(reported("\u{7}", "unnamed"), "unnamed");
        assert_eq!(reported(&"a".repeat(200), "x").len(), MAX_REPORTED);
    }
}
