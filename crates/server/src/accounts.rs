//! People: accounts, how they sign in, and the tokens that stand for them.
//!
//! * Passwords are hashed with Argon2id (its default parameters: 19 MiB,
//!   two passes), off the async threads.
//! * Signing in gives a session token for the console's cookie; the REST API
//!   takes API tokens a user makes for scripts. Both are random 256-bit
//!   values, handed out once and kept only as their SHA-256.
//! * TOTP is optional per user; once on, signing in needs a code, and each
//!   code works once.
//! * Wrong passwords are limited per address and per account name, so
//!   guessing gets a handful of tries every quarter of an hour.
//! * The first administrator comes from a one-time setup token the server
//!   prints on its first start, when there are no users.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use argon2::Argon2;
use argon2::password_hash::phc::PasswordHash;
use argon2::password_hash::{PasswordHasher, PasswordVerifier};
use ring::rand::{SecureRandom, SystemRandom};
use serde::Serialize;
use sqlx::SqlitePool;

use crate::db::now;
use crate::totp;

pub const MIN_PASSWORD: usize = 10;
const MAX_NAME: usize = 64;
/// How long a console sign-in lasts.
const LOGIN_LIFETIME: i64 = 12 * 3600;
const SETUP_LIFETIME: i64 = 24 * 3600;
/// Wrong passwords allowed per address, and per account name, per window.
const ATTEMPTS: usize = 10;
const ATTEMPT_WINDOW: Duration = Duration::from_secs(15 * 60);
/// Prefixes that make a leaked token recognisable for what it is.
const LOGIN_PREFIX: &str = "nhs_";
const API_PREFIX: &str = "nht_";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct User {
    pub id: i64,
    pub name: String,
    pub admin: bool,
    pub totp: bool,
    pub disabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ApiToken {
    pub id: i64,
    pub name: String,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
    pub expires_at: Option<i64>,
}

/// Why something was refused, in words fit for the person who asked.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Refused {
    #[error("wrong name or password")]
    WrongCredentials,
    #[error("a code from the authenticator app is needed")]
    TotpNeeded,
    #[error("wrong or already used code")]
    WrongCode,
    #[error("too many attempts; try again in a quarter of an hour")]
    TooManyAttempts,
    #[error("{0}")]
    Invalid(String),
    #[error("not allowed")]
    Forbidden,
    #[error("not found")]
    NotFound,
}

pub struct Accounts {
    pool: SqlitePool,
    attempts: Mutex<HashMap<String, VecDeque<Instant>>>,
    random: SystemRandom,
}

type UserRow = (i64, String, bool, Option<Vec<u8>>, bool);

fn user_of((id, name, admin, totp_secret, disabled): UserRow) -> User {
    User {
        id,
        name,
        admin,
        totp: totp_secret.is_some(),
        disabled,
    }
}

impl Accounts {
    pub fn new(pool: SqlitePool) -> Self {
        Self {
            pool,
            attempts: Mutex::default(),
            random: SystemRandom::new(),
        }
    }

    pub async fn has_users(&self) -> Result<bool> {
        let (count,): (i64,) = sqlx::query_as("SELECT count(*) FROM users")
            .fetch_one(&self.pool)
            .await?;
        Ok(count > 0)
    }

    /// A one-time token that creates the first administrator, good for a
    /// day. Earlier ones stop working.
    pub async fn new_setup_token(&self) -> Result<String> {
        let token = self.random_token("")?;
        sqlx::query("DELETE FROM setup_tokens")
            .execute(&self.pool)
            .await?;
        sqlx::query("INSERT INTO setup_tokens (token_hash, expires_at) VALUES (?, ?)")
            .bind(hash(&token))
            .bind(now() + SETUP_LIFETIME)
            .execute(&self.pool)
            .await?;
        Ok(token)
    }

    /// Create the first administrator with a setup token.
    pub async fn setup(&self, token: &str, name: &str, password: &str) -> Result<User, Refused> {
        check_name(name)?;
        check_password(password)?;
        let mut tx = self.pool.begin().await.map_err(internal)?;
        let valid: Option<(i64,)> =
            sqlx::query_as("SELECT 1 FROM setup_tokens WHERE token_hash = ? AND expires_at > ?")
                .bind(hash(token))
                .bind(now())
                .fetch_optional(&mut *tx)
                .await
                .map_err(internal)?;
        let (users,): (i64,) = sqlx::query_as("SELECT count(*) FROM users")
            .fetch_one(&mut *tx)
            .await
            .map_err(internal)?;
        if valid.is_none() || users > 0 {
            return Err(Refused::Forbidden);
        }
        let password_hash = hash_password(password.to_owned()).await.map_err(internal)?;
        let (id,): (i64,) = sqlx::query_as(
            "INSERT INTO users (name, password_hash, admin, created_at) VALUES (?, ?, 1, ?) RETURNING id",
        )
        .bind(name)
        .bind(password_hash)
        .bind(now())
        .fetch_one(&mut *tx)
        .await
        .map_err(internal)?;
        sqlx::query("DELETE FROM setup_tokens")
            .execute(&mut *tx)
            .await
            .map_err(internal)?;
        tx.commit().await.map_err(internal)?;
        self.user(id).await?.ok_or(Refused::NotFound)
    }

    pub async fn create_user(
        &self,
        name: &str,
        password: &str,
        admin: bool,
    ) -> Result<User, Refused> {
        check_name(name)?;
        check_password(password)?;
        let password_hash = hash_password(password.to_owned()).await.map_err(internal)?;
        let inserted: Result<(i64,), sqlx::Error> = sqlx::query_as(
            "INSERT INTO users (name, password_hash, admin, created_at) VALUES (?, ?, ?, ?) RETURNING id",
        )
        .bind(name)
        .bind(password_hash)
        .bind(admin)
        .bind(now())
        .fetch_one(&self.pool)
        .await;
        match inserted {
            Ok((id,)) => self.user(id).await?.ok_or(Refused::NotFound),
            Err(sqlx::Error::Database(e)) if e.is_unique_violation() => Err(Refused::Invalid(
                format!("there is already a user called {name}"),
            )),
            Err(e) => Err(internal(e)),
        }
    }

    pub async fn user(&self, id: i64) -> Result<Option<User>, Refused> {
        let row: Option<UserRow> =
            sqlx::query_as("SELECT id, name, admin, totp_secret, disabled FROM users WHERE id = ?")
                .bind(id)
                .fetch_optional(&self.pool)
                .await
                .map_err(internal)?;
        Ok(row.map(user_of))
    }

    pub async fn users(&self) -> Result<Vec<User>, Refused> {
        let rows: Vec<UserRow> = sqlx::query_as(
            "SELECT id, name, admin, totp_secret, disabled FROM users ORDER BY name",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(internal)?;
        Ok(rows.into_iter().map(user_of).collect())
    }

    /// Sign in; a session token for the console on success.
    pub async fn sign_in(
        &self,
        name: &str,
        password: &str,
        code: Option<&str>,
        from: IpAddr,
    ) -> Result<(String, User), Refused> {
        let keys = [
            format!("ip:{from}"),
            format!("name:{}", name.to_lowercase()),
        ];
        if keys.iter().any(|key| !self.may_try(key)) {
            return Err(Refused::TooManyAttempts);
        }
        type Row = (i64, String, bool, bool, Option<Vec<u8>>, Option<i64>);
        let row: Option<Row> = sqlx::query_as(
            "SELECT id, password_hash, admin, disabled, totp_secret, totp_last_step FROM users WHERE name = ?",
        )
        .bind(name)
        .fetch_optional(&self.pool)
        .await
        .map_err(internal)?;
        // Hash even for an unknown name, so the time taken does not say
        // which names exist.
        let stored = row
            .as_ref()
            .map(|r| r.1.clone())
            .unwrap_or_else(|| dummy_hash().to_owned());
        let right = verify_password(password.to_owned(), stored).await;
        let Some((id, _, _, disabled, totp_secret, last_step)) = row.filter(|_| right) else {
            self.failed(&keys);
            return Err(Refused::WrongCredentials);
        };
        if disabled {
            return Err(Refused::WrongCredentials);
        }
        if let Some(secret) = totp_secret {
            let Some(code) = code else {
                return Err(Refused::TotpNeeded);
            };
            match totp::verify(&secret, code, now() as u64) {
                Some(step) if last_step.is_none_or(|last| step as i64 > last) => {
                    sqlx::query("UPDATE users SET totp_last_step = ? WHERE id = ?")
                        .bind(step as i64)
                        .bind(id)
                        .execute(&self.pool)
                        .await
                        .map_err(internal)?;
                }
                _ => {
                    self.failed(&keys);
                    return Err(Refused::WrongCode);
                }
            }
        }
        let token = self.random_token(LOGIN_PREFIX).map_err(internal)?;
        sqlx::query(
            "INSERT INTO logins (token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
        )
        .bind(hash(&token))
        .bind(id)
        .bind(now())
        .bind(now() + LOGIN_LIFETIME)
        .execute(&self.pool)
        .await
        .map_err(internal)?;
        let user = self.user(id).await?.ok_or(Refused::NotFound)?;
        Ok((token, user))
    }

    /// The user a console session token belongs to, while it lasts.
    pub async fn session_user(&self, token: &str) -> Result<Option<User>, Refused> {
        if !token.starts_with(LOGIN_PREFIX) {
            return Ok(None);
        }
        let row: Option<UserRow> = sqlx::query_as(
            "SELECT users.id, name, admin, totp_secret, disabled \
             FROM logins JOIN users ON users.id = logins.user_id \
             WHERE token_hash = ? AND expires_at > ? AND NOT disabled",
        )
        .bind(hash(token))
        .bind(now())
        .fetch_optional(&self.pool)
        .await
        .map_err(internal)?;
        Ok(row.map(user_of))
    }

    pub async fn sign_out(&self, token: &str) -> Result<(), Refused> {
        sqlx::query("DELETE FROM logins WHERE token_hash = ?")
            .bind(hash(token))
            .execute(&self.pool)
            .await
            .map_err(internal)?;
        Ok(())
    }

    /// A new API token for `user`, shown this once.
    pub async fn new_api_token(
        &self,
        user: &User,
        name: &str,
        lifetime_days: Option<u32>,
    ) -> Result<(ApiToken, String), Refused> {
        check_name(name)?;
        let token = self.random_token(API_PREFIX).map_err(internal)?;
        let expires_at = lifetime_days.map(|days| now() + i64::from(days) * 86_400);
        let (id,): (i64,) = sqlx::query_as(
            "INSERT INTO api_tokens (user_id, name, token_hash, created_at, expires_at) \
             VALUES (?, ?, ?, ?, ?) RETURNING id",
        )
        .bind(user.id)
        .bind(name)
        .bind(hash(&token))
        .bind(now())
        .bind(expires_at)
        .fetch_one(&self.pool)
        .await
        .map_err(internal)?;
        let listed = self
            .api_tokens(user)
            .await?
            .into_iter()
            .find(|t| t.id == id)
            .ok_or(Refused::NotFound)?;
        Ok((listed, token))
    }

    /// The user an API token belongs to, while it is valid. Notes its use.
    pub async fn api_user(&self, token: &str) -> Result<Option<User>, Refused> {
        if !token.starts_with(API_PREFIX) {
            return Ok(None);
        }
        let token_hash = hash(token);
        let row: Option<UserRow> = sqlx::query_as(
            "SELECT users.id, users.name, admin, totp_secret, disabled \
             FROM api_tokens JOIN users ON users.id = api_tokens.user_id \
             WHERE token_hash = ? AND (expires_at IS NULL OR expires_at > ?) AND NOT disabled",
        )
        .bind(&token_hash)
        .bind(now())
        .fetch_optional(&self.pool)
        .await
        .map_err(internal)?;
        if row.is_some() {
            sqlx::query("UPDATE api_tokens SET last_used_at = ? WHERE token_hash = ?")
                .bind(now())
                .bind(&token_hash)
                .execute(&self.pool)
                .await
                .map_err(internal)?;
        }
        Ok(row.map(user_of))
    }

    pub async fn api_tokens(&self, user: &User) -> Result<Vec<ApiToken>, Refused> {
        type TokenRow = (i64, String, i64, Option<i64>, Option<i64>);
        let rows: Vec<TokenRow> = sqlx::query_as(
            "SELECT id, name, created_at, last_used_at, expires_at FROM api_tokens \
             WHERE user_id = ? ORDER BY id",
        )
        .bind(user.id)
        .fetch_all(&self.pool)
        .await
        .map_err(internal)?;
        Ok(rows
            .into_iter()
            .map(
                |(id, name, created_at, last_used_at, expires_at)| ApiToken {
                    id,
                    name,
                    created_at,
                    last_used_at,
                    expires_at,
                },
            )
            .collect())
    }

    pub async fn delete_api_token(&self, user: &User, id: i64) -> Result<(), Refused> {
        let done = sqlx::query("DELETE FROM api_tokens WHERE id = ? AND user_id = ?")
            .bind(id)
            .bind(user.id)
            .execute(&self.pool)
            .await
            .map_err(internal)?;
        if done.rows_affected() == 0 {
            return Err(Refused::NotFound);
        }
        Ok(())
    }

    pub async fn change_password(
        &self,
        user: &User,
        current: &str,
        new: &str,
    ) -> Result<(), Refused> {
        check_password(new)?;
        let (stored,): (String,) = sqlx::query_as("SELECT password_hash FROM users WHERE id = ?")
            .bind(user.id)
            .fetch_one(&self.pool)
            .await
            .map_err(internal)?;
        if !verify_password(current.to_owned(), stored).await {
            return Err(Refused::WrongCredentials);
        }
        let password_hash = hash_password(new.to_owned()).await.map_err(internal)?;
        sqlx::query("UPDATE users SET password_hash = ? WHERE id = ?")
            .bind(password_hash)
            .bind(user.id)
            .execute(&self.pool)
            .await
            .map_err(internal)?;
        // Whoever knew the old password may be signed in with it.
        sqlx::query("DELETE FROM logins WHERE user_id = ?")
            .bind(user.id)
            .execute(&self.pool)
            .await
            .map_err(internal)?;
        Ok(())
    }

    /// Start turning TOTP on: a new secret, not in force until confirmed with
    /// a code from it. Returns the secret, in base32, and the app link.
    pub async fn totp_begin(&self, user: &User) -> Result<(String, String), Refused> {
        let secret = totp::new_secret().map_err(internal)?;
        sqlx::query("UPDATE users SET totp_pending = ? WHERE id = ?")
            .bind(&secret)
            .bind(user.id)
            .execute(&self.pool)
            .await
            .map_err(internal)?;
        Ok((
            totp::base32(&secret),
            totp::uri(&secret, "Nearhand", &user.name),
        ))
    }

    pub async fn totp_confirm(&self, user: &User, code: &str) -> Result<(), Refused> {
        let (pending,): (Option<Vec<u8>>,) =
            sqlx::query_as("SELECT totp_pending FROM users WHERE id = ?")
                .bind(user.id)
                .fetch_one(&self.pool)
                .await
                .map_err(internal)?;
        let pending =
            pending.ok_or_else(|| Refused::Invalid("start setting up TOTP first".into()))?;
        let step = totp::verify(&pending, code, now() as u64).ok_or(Refused::WrongCode)?;
        sqlx::query(
            "UPDATE users SET totp_secret = totp_pending, totp_pending = NULL, totp_last_step = ? \
             WHERE id = ?",
        )
        .bind(step as i64)
        .bind(user.id)
        .execute(&self.pool)
        .await
        .map_err(internal)?;
        Ok(())
    }

    /// Turn TOTP off, with a current code: a stolen session alone cannot.
    pub async fn totp_disable(&self, user: &User, code: &str) -> Result<(), Refused> {
        let (secret,): (Option<Vec<u8>>,) =
            sqlx::query_as("SELECT totp_secret FROM users WHERE id = ?")
                .bind(user.id)
                .fetch_one(&self.pool)
                .await
                .map_err(internal)?;
        let secret = secret.ok_or_else(|| Refused::Invalid("TOTP is not on".into()))?;
        totp::verify(&secret, code, now() as u64).ok_or(Refused::WrongCode)?;
        sqlx::query("UPDATE users SET totp_secret = NULL, totp_last_step = NULL WHERE id = ?")
            .bind(user.id)
            .execute(&self.pool)
            .await
            .map_err(internal)?;
        Ok(())
    }

    /// Change another user's standing. The last active administrator
    /// cannot be demoted, disabled or deleted: someone must be left to
    /// administer.
    pub async fn update_user(
        &self,
        id: i64,
        admin: Option<bool>,
        disabled: Option<bool>,
    ) -> Result<User, Refused> {
        let user = self.user(id).await?.ok_or(Refused::NotFound)?;
        let losing_admin =
            user.admin && !user.disabled && (admin == Some(false) || disabled == Some(true));
        if losing_admin && self.active_admins().await? <= 1 {
            return Err(Refused::Invalid(
                "this is the last administrator; make another one first".into(),
            ));
        }
        if let Some(admin) = admin {
            sqlx::query("UPDATE users SET admin = ? WHERE id = ?")
                .bind(admin)
                .bind(id)
                .execute(&self.pool)
                .await
                .map_err(internal)?;
        }
        if let Some(disabled) = disabled {
            sqlx::query("UPDATE users SET disabled = ? WHERE id = ?")
                .bind(disabled)
                .bind(id)
                .execute(&self.pool)
                .await
                .map_err(internal)?;
            if disabled {
                sqlx::query("DELETE FROM logins WHERE user_id = ?")
                    .bind(id)
                    .execute(&self.pool)
                    .await
                    .map_err(internal)?;
            }
        }
        self.user(id).await?.ok_or(Refused::NotFound)
    }

    pub async fn delete_user(&self, id: i64) -> Result<(), Refused> {
        let user = self.user(id).await?.ok_or(Refused::NotFound)?;
        if user.admin && !user.disabled && self.active_admins().await? <= 1 {
            return Err(Refused::Invalid(
                "this is the last administrator; make another one first".into(),
            ));
        }
        sqlx::query("DELETE FROM users WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(internal)?;
        Ok(())
    }

    async fn active_admins(&self) -> Result<i64, Refused> {
        let (count,): (i64,) =
            sqlx::query_as("SELECT count(*) FROM users WHERE admin AND NOT disabled")
                .fetch_one(&self.pool)
                .await
                .map_err(internal)?;
        Ok(count)
    }

    fn random_token(&self, prefix: &str) -> Result<String> {
        random_token(&self.random, prefix)
    }

    fn may_try(&self, key: &str) -> bool {
        let now = Instant::now();
        let mut attempts = self.attempts.lock().unwrap_or_else(|p| p.into_inner());
        attempts.retain(|_, times| {
            times
                .back()
                .is_some_and(|t| now.duration_since(*t) < ATTEMPT_WINDOW)
        });
        attempts.get(key).is_none_or(|times| times.len() < ATTEMPTS)
    }

    fn failed(&self, keys: &[String]) {
        let now = Instant::now();
        let mut attempts = self.attempts.lock().unwrap_or_else(|p| p.into_inner());
        for key in keys {
            let times = attempts.entry(key.clone()).or_default();
            while times
                .front()
                .is_some_and(|t| now.duration_since(*t) >= ATTEMPT_WINDOW)
            {
                times.pop_front();
            }
            times.push_back(now);
        }
    }
}

pub(crate) fn check_name(name: &str) -> Result<(), Refused> {
    let length = name.chars().count();
    if length == 0 || length > MAX_NAME || name.chars().any(char::is_control) || name.trim() != name
    {
        return Err(Refused::Invalid(format!(
            "a name is 1 to {MAX_NAME} characters, without surrounding spaces"
        )));
    }
    Ok(())
}

fn check_password(password: &str) -> Result<(), Refused> {
    if password.chars().count() < MIN_PASSWORD {
        return Err(Refused::Invalid(format!(
            "a password is at least {MIN_PASSWORD} characters"
        )));
    }
    Ok(())
}

/// 256 random bits in hex, after `prefix`.
pub(crate) fn random_token(random: &SystemRandom, prefix: &str) -> Result<String> {
    let mut bytes = [0u8; 32];
    random
        .fill(&mut bytes)
        .map_err(|_| anyhow::anyhow!("the system random number generator failed"))?;
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    Ok(format!("{prefix}{hex}"))
}

pub fn hash(token: &str) -> Vec<u8> {
    ring::digest::digest(&ring::digest::SHA256, token.as_bytes())
        .as_ref()
        .to_vec()
}

async fn hash_password(password: String) -> Result<String> {
    tokio::task::spawn_blocking(move || {
        Argon2::default()
            .hash_password(password.as_bytes())
            .map(|h| h.to_string())
            .map_err(|e| anyhow::anyhow!("hashing the password: {e}"))
    })
    .await
    .context("the hashing task")?
}

async fn verify_password(password: String, stored: String) -> bool {
    tokio::task::spawn_blocking(move || {
        PasswordHash::new(&stored).is_ok_and(|parsed| {
            Argon2::default()
                .verify_password(password.as_bytes(), &parsed)
                .is_ok()
        })
    })
    .await
    .unwrap_or(false)
}

/// A hash no password matches, checked against for unknown names.
fn dummy_hash() -> &'static str {
    static DUMMY: OnceLock<String> = OnceLock::new();
    DUMMY.get_or_init(|| {
        Argon2::default()
            .hash_password(b"no account has this password, it is only for timing")
            .map(|h| h.to_string())
            .unwrap_or_default()
    })
}

pub(crate) fn internal(e: impl std::fmt::Display) -> Refused {
    tracing::error!(error = %e, "accounts");
    Refused::Invalid("the server failed; see its log".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOME: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1));

    async fn accounts() -> Accounts {
        Accounts::new(crate::db::in_memory().await)
    }

    async fn with_admin() -> (Accounts, User) {
        let accounts = accounts().await;
        let token = accounts.new_setup_token().await.expect("token");
        let admin = accounts
            .setup(&token, "ada", "correct horse battery")
            .await
            .expect("setup");
        (accounts, admin)
    }

    #[tokio::test]
    async fn the_setup_token_makes_one_administrator_once() {
        let accounts = accounts().await;
        assert!(!accounts.has_users().await.expect("count"));
        let token = accounts.new_setup_token().await.expect("token");
        assert_eq!(
            accounts
                .setup("wrong", "ada", "correct horse battery")
                .await,
            Err(Refused::Forbidden)
        );
        let admin = accounts
            .setup(&token, "ada", "correct horse battery")
            .await
            .expect("setup");
        assert!(admin.admin);
        assert!(accounts.has_users().await.expect("count"));
        assert_eq!(
            accounts.setup(&token, "eve", "correct horse battery").await,
            Err(Refused::Forbidden),
            "the token is spent, and there is an administrator now"
        );
    }

    #[tokio::test]
    async fn signing_in_gives_a_session_that_signs_out() {
        let (accounts, admin) = with_admin().await;
        let (token, user) = accounts
            .sign_in("ADA", "correct horse battery", None, HOME)
            .await
            .expect("sign in, name in any case");
        assert_eq!(user, admin);
        assert!(token.starts_with(LOGIN_PREFIX));
        assert_eq!(accounts.session_user(&token).await.expect("q"), Some(admin));
        accounts.sign_out(&token).await.expect("sign out");
        assert_eq!(accounts.session_user(&token).await.expect("q"), None);
    }

    #[tokio::test]
    async fn wrong_passwords_and_unknown_names_look_the_same_and_run_out() {
        let (accounts, _) = with_admin().await;
        assert_eq!(
            accounts.sign_in("ada", "wrong", None, HOME).await,
            Err(Refused::WrongCredentials)
        );
        assert_eq!(
            accounts.sign_in("nobody", "wrong", None, HOME).await,
            Err(Refused::WrongCredentials)
        );
        // With the two above, ten wrong passwords from this address.
        for i in 2..ATTEMPTS {
            let _ = accounts
                .sign_in(&format!("guess{i}"), "wrong", None, HOME)
                .await;
        }
        assert_eq!(
            accounts
                .sign_in("ada", "correct horse battery", None, HOME)
                .await,
            Err(Refused::TooManyAttempts),
            "the address is out of tries: even the right password, while it lasts"
        );
    }

    #[tokio::test]
    async fn guessing_one_name_from_many_addresses_runs_out_too() {
        let (accounts, _) = with_admin().await;
        for i in 0..ATTEMPTS {
            let from = IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, i as u8));
            assert_eq!(
                accounts.sign_in("ada", "wrong", None, from).await,
                Err(Refused::WrongCredentials)
            );
        }
        let elsewhere = IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 9));
        assert_eq!(
            accounts
                .sign_in("ada", "correct horse battery", None, elsewhere)
                .await,
            Err(Refused::TooManyAttempts),
            "the name is out of tries, from anywhere"
        );
    }

    #[tokio::test]
    async fn totp_once_on_is_needed_and_each_code_works_once() {
        let (accounts, admin) = with_admin().await;
        let (secret, uri) = accounts.totp_begin(&admin).await.expect("begin");
        assert!(uri.starts_with("otpauth://totp/Nearhand:ada?"));
        let secret = totp::from_base32(&secret).expect("secret");
        let code = |at: i64| format!("{:06}", totp_code(&secret, at));

        assert_eq!(
            accounts.totp_confirm(&admin, "000000").await,
            Err(Refused::WrongCode)
        );
        accounts
            .totp_confirm(&admin, &code(now()))
            .await
            .expect("confirm");

        assert_eq!(
            accounts
                .sign_in("ada", "correct horse battery", None, HOME)
                .await,
            Err(Refused::TotpNeeded)
        );
        // The code that confirmed is spent; the next step's is fresh.
        assert_eq!(
            accounts
                .sign_in("ada", "correct horse battery", Some(&code(now())), HOME)
                .await,
            Err(Refused::WrongCode)
        );
        let next = code(now() + 30);
        accounts
            .sign_in("ada", "correct horse battery", Some(&next), HOME)
            .await
            .expect("sign in with a fresh code");
        assert_eq!(
            accounts
                .sign_in("ada", "correct horse battery", Some(&next), HOME)
                .await,
            Err(Refused::WrongCode),
            "and it works once"
        );
    }

    fn totp_code(secret: &[u8], at: i64) -> u32 {
        totp::code_at(secret, at as u64)
    }

    #[tokio::test]
    async fn api_tokens_stand_for_their_user_until_deleted() {
        let (accounts, admin) = with_admin().await;
        let (listed, token) = accounts
            .new_api_token(&admin, "backup script", None)
            .await
            .expect("token");
        assert!(token.starts_with(API_PREFIX));
        assert_eq!(
            accounts.api_user(&token).await.expect("q"),
            Some(admin.clone())
        );
        assert!(
            accounts.api_tokens(&admin).await.expect("list")[0]
                .last_used_at
                .is_some()
        );
        // A session token is no API token, and the reverse.
        assert_eq!(accounts.session_user(&token).await.expect("q"), None);
        accounts
            .delete_api_token(&admin, listed.id)
            .await
            .expect("delete");
        assert_eq!(accounts.api_user(&token).await.expect("q"), None);
    }

    #[tokio::test]
    async fn the_last_administrator_stays() {
        let (accounts, admin) = with_admin().await;
        assert!(matches!(
            accounts.update_user(admin.id, Some(false), None).await,
            Err(Refused::Invalid(_))
        ));
        assert!(matches!(
            accounts.delete_user(admin.id).await,
            Err(Refused::Invalid(_))
        ));
        let other = accounts
            .create_user("grace", "another good password", true)
            .await
            .expect("second admin");
        accounts
            .update_user(admin.id, Some(false), None)
            .await
            .expect("now allowed");
        assert!(matches!(
            accounts
                .create_user("GRACE", "another good password", false)
                .await,
            Err(Refused::Invalid(_))
        ));
        let _ = other;
    }

    #[tokio::test]
    async fn disabling_a_user_ends_their_sessions_and_changing_a_password_too() {
        let (accounts, _) = with_admin().await;
        let bob = accounts
            .create_user("bob", "bobs password here", false)
            .await
            .expect("bob");
        let (session, _) = accounts
            .sign_in("bob", "bobs password here", None, HOME)
            .await
            .expect("sign in");
        accounts
            .change_password(&bob, "bobs password here", "bobs new password")
            .await
            .expect("change");
        assert_eq!(accounts.session_user(&session).await.expect("q"), None);

        let (session, _) = accounts
            .sign_in("bob", "bobs new password", None, HOME)
            .await
            .expect("sign in again");
        accounts
            .update_user(bob.id, None, Some(true))
            .await
            .expect("disable");
        assert_eq!(accounts.session_user(&session).await.expect("q"), None);
        assert_eq!(
            accounts
                .sign_in("bob", "bobs new password", None, HOME)
                .await,
            Err(Refused::WrongCredentials)
        );
    }
}
