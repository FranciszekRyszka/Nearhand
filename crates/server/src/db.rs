//! The database: one SQLite file beside the server key. Backing up the
//! server is copying those two (`docs/self-hosting.md`).

use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use sqlx::SqlitePool;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};

/// Open (creating if needed) the database at `path`, and bring its schema up
/// to date.
pub async fn open(path: &Path) -> Result<SqlitePool> {
    let options = SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(true)
        // Readers do not wait for the writer, and a crash cannot corrupt it.
        .journal_mode(SqliteJournalMode::Wal)
        .foreign_keys(true)
        .busy_timeout(Duration::from_secs(5));
    let pool = SqlitePoolOptions::new()
        .max_connections(8)
        .connect_with(options)
        .await
        .with_context(|| format!("opening {}", path.display()))?;
    migrate(&pool).await?;
    Ok(pool)
}

/// An empty database in memory, for tests. One connection: each connection
/// to `:memory:` would be a database of its own.
#[cfg(test)]
pub async fn in_memory() -> SqlitePool {
    use std::str::FromStr;
    let options = SqliteConnectOptions::from_str("sqlite::memory:")
        .expect("options")
        .foreign_keys(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .expect("in-memory database");
    migrate(&pool).await.expect("migrate");
    pool
}

async fn migrate(pool: &SqlitePool) -> Result<()> {
    sqlx::migrate!("./migrations")
        .run(pool)
        .await
        .context("updating the database schema")
}

/// Seconds since the Unix epoch.
pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_new_database_gets_the_schema() {
        let pool = in_memory().await;
        let tables: Vec<(String,)> =
            sqlx::query_as("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
                .fetch_all(&pool)
                .await
                .expect("tables");
        let names: Vec<&str> = tables.iter().map(|(n,)| n.as_str()).collect();
        for table in ["api_tokens", "logins", "setup_tokens", "users"] {
            assert!(names.contains(&table), "{table} missing from {names:?}");
        }
    }

    #[tokio::test]
    async fn a_file_database_is_created_and_reopened() {
        let dir = std::env::temp_dir().join(format!("nearhand-db-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("dir");
        let path = dir.join("nearhand.db");
        let pool = open(&path).await.expect("create");
        sqlx::query("INSERT INTO setup_tokens (token_hash, expires_at) VALUES (x'00', 1)")
            .execute(&pool)
            .await
            .expect("insert");
        pool.close().await;
        let pool = open(&path).await.expect("reopen");
        let (count,): (i64,) = sqlx::query_as("SELECT count(*) FROM setup_tokens")
            .fetch_one(&pool)
            .await
            .expect("count");
        assert_eq!(count, 1);
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }
}
