//! Rows nobody will read again.
//!
//! A server meant to run on one small machine for years cannot keep
//! everything for ever. Three things pile up on their own: the audit log,
//! console sessions that have expired, and the one-time link for the first
//! administrator once nobody used it.
//!
//! Sessions and setup tokens past their time are dead weight — they are
//! checked against the clock before they are honoured, so removing them
//! changes nothing but the size of the file. The audit log is different:
//! it is the record of who did what, so it goes only after
//! `audit.keep_days`, which is a year by default and can be turned off.
//!
//! The sweep runs at start and then daily. Deleting rows does not shrink
//! the file — SQLite reuses the pages — but `nearhand-server backup`
//! writes out a compacted copy.

use std::time::Duration;

use sqlx::SqlitePool;

use crate::db;

/// Between sweeps. Long enough to be invisible, short enough that a server
/// left running keeps up.
const EVERY: Duration = Duration::from_secs(24 * 3600);

/// What one sweep removed.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Swept {
    pub audit_entries: u64,
    pub sessions: u64,
    pub setup_tokens: u64,
}

impl Swept {
    fn nothing(&self) -> bool {
        *self == Self::default()
    }
}

/// Sweep now, and then once a day for as long as the server runs.
pub async fn keep_tidy(pool: SqlitePool, keep_days: u32) {
    loop {
        match sweep(&pool, keep_days, db::now()).await {
            Ok(swept) if swept.nothing() => {}
            Ok(swept) => tracing::info!(
                audit_entries = swept.audit_entries,
                sessions = swept.sessions,
                setup_tokens = swept.setup_tokens,
                "swept away what nobody will read again"
            ),
            Err(e) => tracing::warn!(error = %e, "could not sweep the database"),
        }
        tokio::time::sleep(EVERY).await;
    }
}

/// One sweep, as of `now`. `keep_days` of 0 keeps the audit log for ever.
pub async fn sweep(pool: &SqlitePool, keep_days: u32, now: i64) -> Result<Swept, sqlx::Error> {
    let sessions = sqlx::query("DELETE FROM logins WHERE expires_at < ?")
        .bind(now)
        .execute(pool)
        .await?
        .rows_affected();
    let setup_tokens = sqlx::query("DELETE FROM setup_tokens WHERE expires_at < ?")
        .bind(now)
        .execute(pool)
        .await?
        .rows_affected();
    let audit_entries = if keep_days == 0 {
        0
    } else {
        let before = now - i64::from(keep_days) * 24 * 3600;
        sqlx::query("DELETE FROM audit_log WHERE at < ?")
            .bind(before)
            .execute(pool)
            .await?
            .rows_affected()
    };
    Ok(Swept {
        audit_entries,
        sessions,
        setup_tokens,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::Row;

    const DAY: i64 = 24 * 3600;
    const NOW: i64 = 1_800_000_000;

    async fn filled() -> SqlitePool {
        let pool = db::in_memory().await;
        for (at, action) in [
            (NOW - 400 * DAY, "long ago"),
            (NOW - 366 * DAY, "a year and a day ago"),
            (NOW - 300 * DAY, "within the year"),
            (NOW - DAY, "yesterday"),
        ] {
            sqlx::query("INSERT INTO audit_log (at, action) VALUES (?, ?)")
                .bind(at)
                .bind(action)
                .execute(&pool)
                .await
                .expect("an entry");
        }
        sqlx::query(
            "INSERT INTO users (id, name, password_hash, created_at) VALUES (1, 'ada', 'x', 0)",
        )
        .execute(&pool)
        .await
        .expect("a user");
        for (hash, expires_at) in [
            (b"expired".to_vec(), NOW - 60),
            (b"current".to_vec(), NOW + 60),
        ] {
            sqlx::query("INSERT INTO logins (token_hash, user_id, created_at, expires_at) VALUES (?, 1, 0, ?)")
                .bind(hash)
                .bind(expires_at)
                .execute(&pool)
                .await
                .expect("a session");
        }
        for (hash, expires_at) in [(b"stale".to_vec(), NOW - 1), (b"fresh".to_vec(), NOW + DAY)] {
            sqlx::query("INSERT INTO setup_tokens (token_hash, expires_at) VALUES (?, ?)")
                .bind(hash)
                .bind(expires_at)
                .execute(&pool)
                .await
                .expect("a setup token");
        }
        pool
    }

    async fn count(pool: &SqlitePool, table: &str) -> i64 {
        let query = match table {
            "audit_log" => "SELECT count(*) AS n FROM audit_log",
            "logins" => "SELECT count(*) AS n FROM logins",
            _ => "SELECT count(*) AS n FROM setup_tokens",
        };
        sqlx::query(query)
            .fetch_one(pool)
            .await
            .expect("count")
            .try_get("n")
            .expect("n")
    }

    #[tokio::test]
    async fn what_is_past_its_time_goes_and_the_rest_stays() {
        let pool = filled().await;
        let swept = sweep(&pool, 365, NOW).await.expect("sweep");
        assert_eq!(
            swept,
            Swept {
                audit_entries: 2,
                sessions: 1,
                setup_tokens: 1,
            }
        );
        assert_eq!(count(&pool, "audit_log").await, 2, "the year that is kept");
        assert_eq!(count(&pool, "logins").await, 1, "the session in use");
        assert_eq!(count(&pool, "setup_tokens").await, 1, "the link still good");

        // Again on the same day: there is nothing left to take.
        let swept = sweep(&pool, 365, NOW).await.expect("sweep");
        assert!(swept.nothing(), "{swept:?}");
    }

    /// Keeping the log for ever is a setting, not an accident.
    #[tokio::test]
    async fn zero_days_keeps_the_audit_log_whole() {
        let pool = filled().await;
        let swept = sweep(&pool, 0, NOW).await.expect("sweep");
        assert_eq!(swept.audit_entries, 0);
        assert_eq!(count(&pool, "audit_log").await, 4);
        // Sessions and setup tokens still go: nothing reads them again.
        assert_eq!(swept.sessions, 1);
        assert_eq!(swept.setup_tokens, 1);
    }

    #[tokio::test]
    async fn a_short_retention_leaves_only_what_is_recent() {
        let pool = filled().await;
        let swept = sweep(&pool, 7, NOW).await.expect("sweep");
        assert_eq!(swept.audit_entries, 3);
        assert_eq!(count(&pool, "audit_log").await, 1, "yesterday's");
    }
}
