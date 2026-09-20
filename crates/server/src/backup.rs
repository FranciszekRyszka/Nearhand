//! `nearhand-server backup`: a copy of everything that cannot be rebuilt.
//!
//! The data folder holds two things that matter: the **server key**, which
//! every agent and viewer pinned — lose it and each of them has to be
//! reconfigured — and the **database**, which holds the accounts, devices,
//! groups, grants and the audit log.
//!
//! Copying the database file while the server runs is not enough: it is in
//! WAL mode, so the most recent writes are in `nearhand.db-wal` and a plain
//! copy can be short of them, or torn. This asks SQLite for a consistent
//! copy instead (`VACUUM INTO`), which is safe while the server serves and
//! comes out compacted. The distroless image has no shell to run `sqlite3`
//! in, so it is this or stopping the server.
//!
//! Release packages are not copied: they are large, and they can be
//! downloaded again from the project's releases.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};

use crate::config::{Config, Tls};

/// What one file cost.
struct Copied {
    name: &'static str,
    path: PathBuf,
    bytes: u64,
}

pub async fn run(config: Config, to: PathBuf) -> Result<()> {
    if to.exists() {
        bail!(
            "{} exists already: give a folder that does not, so a backup \
             cannot quietly overwrite another",
            to.display()
        );
    }
    std::fs::create_dir_all(&to).with_context(|| format!("creating {}", to.display()))?;

    let mut copied = Vec::new();
    copied.push(key(&config, &to)?);
    if let Some(database) = database(&config, &to).await? {
        copied.push(database);
    }
    copied.extend(certificate(&config, &to)?);

    println!("Backed up to {}:", to.display());
    for Copied { name, path, bytes } in &copied {
        let file = path.file_name().unwrap_or_default().to_string_lossy();
        println!("  {file:<16} {:>10}  {name}", size(*bytes));
    }
    println!();
    println!("Keep this off the server. The key is the one agents pinned:");
    println!("without it they all have to be installed again.");
    println!();
    println!(
        "To restore: stop the server, put these files in {}",
        config.data.dir.display()
    );
    println!("and start it. Release packages are not here; upload them again");
    println!("from the project's releases if agents update from this server.");
    Ok(())
}

/// The key behind the certificate every agent pinned.
fn key(config: &Config, to: &Path) -> Result<Copied> {
    let from = config.key_path();
    if !from.exists() {
        bail!(
            "{} has no server key: there is nothing here to back up yet",
            config.data.dir.display()
        );
    }
    let path = to.join("server.key");
    let bytes = std::fs::copy(&from, &path)
        .with_context(|| format!("copying {} to {}", from.display(), path.display()))?;
    restrict(&path)?;
    Ok(Copied {
        name: "the key agents pinned",
        path,
        bytes,
    })
}

/// A consistent copy, taken while the server may be writing.
async fn database(config: &Config, to: &Path) -> Result<Option<Copied>> {
    let from = config.database_path();
    if !from.exists() {
        println!("(no database yet: nothing but the key to back up)");
        return Ok(None);
    }
    let options = SqliteConnectOptions::new()
        .filename(&from)
        .create_if_missing(false)
        .read_only(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .with_context(|| format!("opening {}", from.display()))?;
    let path = to.join("nearhand.db");
    // A bound path, and a literal statement: SQLite takes the destination
    // as an expression, and refuses a file that exists.
    let taken = sqlx::query("VACUUM INTO ?")
        .bind(path.to_string_lossy().as_ref())
        .execute(&pool)
        .await;
    pool.close().await;
    taken.with_context(|| format!("copying the database into {}", path.display()))?;
    restrict(&path)?;
    let bytes = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
    Ok(Some(Copied {
        name: "accounts, devices, grants, audit log",
        path,
        bytes,
    }))
}

/// The HTTPS certificate, when it is one the server cannot make again.
fn certificate(config: &Config, to: &Path) -> Result<Vec<Copied>> {
    if config.http.tls != Tls::SelfSigned {
        // `files` belongs to whatever issued it; `none` has none.
        return Ok(Vec::new());
    }
    let mut copied = Vec::new();
    for (file, name) in [
        ("https.crt", "the certificate browsers saw"),
        ("https.key", "its key"),
    ] {
        let from = config.data.dir.join(file);
        if !from.exists() {
            continue;
        }
        let path = to.join(file);
        let bytes =
            std::fs::copy(&from, &path).with_context(|| format!("copying {}", from.display()))?;
        restrict(&path)?;
        copied.push(Copied { name, path, bytes });
    }
    Ok(copied)
}

/// A backup of a key is a key: readable by its owner only, where the
/// filesystem has an opinion about that.
fn restrict(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("restricting {}", path.display()))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn size(bytes: u64) -> String {
    match bytes {
        0..=9_999 => format!("{bytes} B"),
        10_000..=9_999_999 => format!("{:.0} KB", bytes as f64 / 1024.0),
        _ => format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::Row;

    fn scratch(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("nearhand-backup-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch");
        dir
    }

    fn config(dir: &Path) -> Config {
        let mut config = Config::default();
        config.data.dir = dir.to_path_buf();
        config
    }

    /// A server that is running keeps recent writes in the WAL; the backup
    /// must have them, and must open on its own.
    #[tokio::test]
    async fn a_backup_holds_the_key_and_every_row_written_so_far() {
        let dir = scratch("whole");
        let config = config(&dir);
        let identity =
            nearhand_transport::Identity::load_or_create(&config.key_path()).expect("a key");
        let pool = crate::db::open(&config.database_path()).await.expect("db");
        sqlx::query("INSERT INTO users (name, password_hash, created_at) VALUES (?, ?, 0)")
            .bind("ada")
            .bind("not-a-hash")
            .execute(&pool)
            .await
            .expect("a user");

        let to = dir.join("backup");
        run(config.clone(), to.clone()).await.expect("backup");
        // Still serving: the pool is open the whole time.
        assert!(!pool.is_closed());
        pool.close().await;

        assert_eq!(
            std::fs::read(to.join("server.key")).expect("the key"),
            std::fs::read(config.key_path()).expect("the original"),
            "the key came across whole"
        );
        let copy = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(
                SqliteConnectOptions::new()
                    .filename(to.join("nearhand.db"))
                    .create_if_missing(false)
                    .read_only(true),
            )
            .await
            .expect("the copy opens");
        let name: String = sqlx::query("SELECT name FROM users")
            .fetch_one(&copy)
            .await
            .expect("the row")
            .try_get("name")
            .expect("name");
        assert_eq!(name, "ada", "a row written just before the backup");
        copy.close().await;
        // The key still identifies the same server.
        let restored = nearhand_transport::Identity::load_or_create(&to.join("server.key"))
            .expect("the copied key");
        assert_eq!(restored.fingerprint(), identity.fingerprint());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_backup_never_overwrites_another() {
        let dir = scratch("twice");
        let config = config(&dir);
        nearhand_transport::Identity::load_or_create(&config.key_path()).expect("a key");
        let to = dir.join("backup");
        run(config.clone(), to.clone()).await.expect("the first");
        let error = run(config, to).await.expect_err("the second");
        assert!(format!("{error:#}").contains("exists already"), "{error:#}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_folder_with_no_key_has_nothing_to_back_up() {
        let dir = scratch("empty");
        let error = run(config(&dir), dir.join("backup"))
            .await
            .expect_err("nothing to copy");
        assert!(format!("{error:#}").contains("no server key"), "{error:#}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
