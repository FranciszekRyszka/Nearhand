//! Agent releases this server holds, and which one its agents are offered.
//!
//! An administrator uploads a package with its signature file
//! (`nearhand-release sign`). The server takes it only if the project's
//! release key signed it and the package is the one signed — the same checks
//! every agent makes again before installing — so what it offers can be
//! nothing else. Then the administrator offers it: at most one release per
//! product and platform, which agents older than it update to
//! (`nearhand_core::rendezvous::ToServer::Update`). Withdrawing it stops
//! the rollout; agents that updated stay updated.
//!
//! Packages are files in the data folder's `releases`, named by SHA-256.

use std::path::PathBuf;

use nearhand_core::release::{Release, SignedRelease, Version};
use nearhand_transport::release as signing;
use serde::Serialize;
use sqlx::SqlitePool;

use crate::accounts::{Refused, internal};
use crate::db::now;

/// The largest package taken: an MSI is a few MB.
pub const MAX_PACKAGE: usize = 256 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Listed {
    pub id: i64,
    pub product: String,
    pub platform: String,
    pub version: String,
    /// `msi`.
    pub package: String,
    /// In hex.
    pub sha256: String,
    pub size: i64,
    pub uploaded_at: i64,
    /// Whether agents are offered it now.
    pub offered: bool,
}

/// A release on offer, as an agent gets it.
#[derive(Debug, Clone)]
pub struct Offer {
    pub release: Release,
    pub signed: SignedRelease,
    /// The package file.
    pub path: PathBuf,
}

pub struct Releases {
    pool: SqlitePool,
    dir: PathBuf,
    /// The release key's public half: `nearhand_core::release::KEY`,
    /// except in tests.
    key: [u8; 32],
}

type Row = (i64, String, String, String, String, Vec<u8>, i64, i64, bool);

impl Releases {
    /// Releases kept in `dir`, checked against the release key `key`.
    pub fn new(pool: SqlitePool, dir: PathBuf, key: [u8; 32]) -> Self {
        Self { pool, dir, key }
    }

    /// Take `package`, if `signature` is the release key's signature over
    /// it.
    pub async fn add(&self, package: &[u8], signature: &str) -> Result<Listed, Refused> {
        let signed = SignedRelease::from_text(signature)
            .map_err(|e| Refused::Invalid(format!("not a signature file: {e}")))?;
        let release = signing::verify(&signed, &self.key)
            .map_err(|e| Refused::Invalid(format!("{e}: not a Nearhand release")))?;
        signing::check_package(&release, package)
            .map_err(|_| Refused::Invalid("the package is not the one that was signed".into()))?;

        let taken: Option<(i64,)> = sqlx::query_as("SELECT id FROM releases WHERE sha256 = ?")
            .bind(release.sha256.as_slice())
            .fetch_optional(&self.pool)
            .await
            .map_err(internal)?;
        if taken.is_some() {
            return Err(Refused::Invalid("this package is here already".into()));
        }
        self.store(&release.sha256, package).await?;
        let (id,): (i64,) = sqlx::query_as(
            "INSERT INTO releases \
             (product, platform, version, package, sha256, size, signature, uploaded_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?) RETURNING id",
        )
        .bind(&release.product)
        .bind(&release.platform)
        .bind(release.version.to_string())
        .bind(package_name(&release))
        .bind(release.sha256.as_slice())
        .bind(release.size as i64)
        .bind(signed.to_text())
        .bind(now())
        .fetch_one(&self.pool)
        .await
        .map_err(internal)?;
        self.release(id).await
    }

    /// Write the package where it is kept: under a temporary name first, so
    /// a file by its hash is always whole.
    async fn store(&self, sha256: &[u8; 32], package: &[u8]) -> Result<(), Refused> {
        tokio::fs::create_dir_all(&self.dir)
            .await
            .map_err(internal)?;
        let path = self.path(sha256);
        let partial = path.with_extension("partial");
        tokio::fs::write(&partial, package)
            .await
            .map_err(internal)?;
        tokio::fs::rename(&partial, &path).await.map_err(internal)
    }

    /// Every release held, newest version first.
    pub async fn list(&self) -> Result<Vec<Listed>, Refused> {
        let rows: Vec<Row> = sqlx::query_as(
            "SELECT id, product, platform, version, package, sha256, size, uploaded_at, offered \
             FROM releases",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(internal)?;
        let mut listed: Vec<Listed> = rows.into_iter().map(listed).collect();
        listed.sort_by(|a, b| {
            (&a.product, &a.platform)
                .cmp(&(&b.product, &b.platform))
                .then_with(|| version_of(&b.version).cmp(&version_of(&a.version)))
                .then(b.id.cmp(&a.id))
        });
        Ok(listed)
    }

    pub async fn release(&self, id: i64) -> Result<Listed, Refused> {
        let row: Option<Row> = sqlx::query_as(
            "SELECT id, product, platform, version, package, sha256, size, uploaded_at, offered \
             FROM releases WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(internal)?;
        row.map(listed).ok_or(Refused::NotFound)
    }

    /// Offer release `id` to its product and platform's agents, in place of
    /// whichever was offered.
    pub async fn offer(&self, id: i64) -> Result<Listed, Refused> {
        let release = self.release(id).await?;
        let mut tx = self.pool.begin().await.map_err(internal)?;
        sqlx::query("UPDATE releases SET offered = 0 WHERE product = ? AND platform = ?")
            .bind(&release.product)
            .bind(&release.platform)
            .execute(&mut *tx)
            .await
            .map_err(internal)?;
        sqlx::query("UPDATE releases SET offered = 1 WHERE id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(internal)?;
        tx.commit().await.map_err(internal)?;
        self.release(id).await
    }

    /// Stop offering release `id`.
    pub async fn withdraw(&self, id: i64) -> Result<Listed, Refused> {
        let changed = sqlx::query("UPDATE releases SET offered = 0 WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(internal)?;
        if changed.rows_affected() == 0 {
            return Err(Refused::NotFound);
        }
        self.release(id).await
    }

    /// Forget release `id` and delete its package. Not while it is offered:
    /// agents may be fetching it.
    pub async fn delete(&self, id: i64) -> Result<Listed, Refused> {
        let release = self.release(id).await?;
        if release.offered {
            return Err(Refused::Invalid(
                "withdraw the release before deleting it".into(),
            ));
        }
        let (sha256,): (Vec<u8>,) =
            sqlx::query_as("DELETE FROM releases WHERE id = ? RETURNING sha256")
                .bind(id)
                .fetch_one(&self.pool)
                .await
                .map_err(internal)?;
        if let Ok(sha256) = <[u8; 32]>::try_from(sha256.as_slice())
            && let Err(e) = tokio::fs::remove_file(self.path(&sha256)).await
        {
            tracing::warn!(error = %e, release = id, "could not delete a release's package");
        }
        Ok(release)
    }

    /// What an agent of `product` on `platform`, running `version`, is
    /// offered: the release on offer, if it is newer than that.
    pub async fn offer_for(
        &self,
        product: &str,
        platform: &str,
        version: Version,
    ) -> Result<Option<Offer>, Refused> {
        let row: Option<(String,)> = sqlx::query_as(
            "SELECT signature FROM releases WHERE product = ? AND platform = ? AND offered = 1",
        )
        .bind(product)
        .bind(platform)
        .fetch_optional(&self.pool)
        .await
        .map_err(internal)?;
        let Some((text,)) = row else { return Ok(None) };
        // Checked on the way in; checked again, since it is read back from
        // the database and agents will check it anyway.
        let signed = SignedRelease::from_text(&text).map_err(internal)?;
        let release = signing::verify(&signed, &self.key).map_err(internal)?;
        if release.version <= version {
            return Ok(None);
        }
        Ok(Some(Offer {
            path: self.path(&release.sha256),
            release,
            signed,
        }))
    }

    fn path(&self, sha256: &[u8; 32]) -> PathBuf {
        self.dir.join(format!("{}.pkg", hex(sha256)))
    }
}

fn package_name(release: &Release) -> &'static str {
    match release.package {
        nearhand_core::release::Package::Msi => "msi",
    }
}

fn listed(row: Row) -> Listed {
    let (id, product, platform, version, package, sha256, size, uploaded_at, offered) = row;
    Listed {
        id,
        product,
        platform,
        version,
        package,
        sha256: hex(&sha256),
        size,
        uploaded_at,
        offered,
    }
}

/// For sorting: a version that does not parse sorts first.
fn version_of(text: &str) -> Option<Version> {
    text.parse().ok()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use nearhand_core::release::{AGENT, Package, WINDOWS_X86_64};

    /// A release key of the tests' own, and packages signed with it.
    pub(crate) struct Signer {
        private: Vec<u8>,
        pub(crate) public: [u8; 32],
    }

    impl Signer {
        pub(crate) fn new() -> Self {
            let (private, public) = signing::generate_key().expect("key");
            Self { private, public }
        }

        /// A package for `version`, and its signature file.
        pub(crate) fn package(&self, version: &str) -> (Vec<u8>, String) {
            let package = format!("the agent, version {version}").into_bytes();
            let release = Release {
                product: AGENT.into(),
                version: version.parse().expect("version"),
                platform: WINDOWS_X86_64.into(),
                package: Package::Msi,
                sha256: signing::sha256(&package),
                size: package.len() as u64,
            };
            let signed = signing::sign(&self.private, &release).expect("sign");
            (package, signed.to_text())
        }
    }

    pub(crate) async fn releases(signer: &Signer) -> (Releases, tempdir::Dir) {
        let dir = tempdir::Dir::new();
        let releases = Releases::new(
            crate::db::in_memory().await,
            dir.path().to_path_buf(),
            signer.public,
        );
        (releases, dir)
    }

    /// A folder of its own for a test, removed after it.
    pub(crate) mod tempdir {
        use std::path::{Path, PathBuf};

        pub(crate) struct Dir(PathBuf);

        impl Dir {
            pub(crate) fn new() -> Self {
                static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
                let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let path = std::env::temp_dir()
                    .join(format!("nearhand-releases-{}-{n}", std::process::id()));
                let _ = std::fs::remove_dir_all(&path);
                Self(path)
            }

            pub(crate) fn path(&self) -> &Path {
                &self.0
            }
        }

        impl Drop for Dir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
    }

    fn version(s: &str) -> Version {
        s.parse().expect("version")
    }

    #[tokio::test]
    async fn only_signed_packages_are_taken() {
        let signer = Signer::new();
        let (releases, _dir) = releases(&signer).await;
        let (package, signature) = signer.package("0.2.0");

        // Signed with another key.
        let stranger = Signer::new();
        let (other, other_signature) = stranger.package("0.2.0");
        assert!(matches!(
            releases.add(&other, &other_signature).await,
            Err(Refused::Invalid(_))
        ));
        // The right signature, the wrong package.
        assert!(matches!(
            releases.add(b"something else", &signature).await,
            Err(Refused::Invalid(_))
        ));
        assert!(matches!(
            releases.add(&package, "release 00\n").await,
            Err(Refused::Invalid(_))
        ));

        let added = releases.add(&package, &signature).await.expect("add");
        assert_eq!(
            (added.version.as_str(), added.offered, added.size),
            ("0.2.0", false, package.len() as i64)
        );
        let stored = std::fs::read(releases.path(&signing::sha256(&package))).expect("file");
        assert_eq!(stored, package);
        assert!(matches!(
            releases.add(&package, &signature).await,
            Err(Refused::Invalid(_))
        ));
        assert_eq!(releases.list().await.expect("list").len(), 1);
    }

    #[tokio::test]
    async fn agents_are_offered_the_offered_release_if_it_is_newer() {
        let signer = Signer::new();
        let (releases, _dir) = releases(&signer).await;
        let (old, old_signature) = signer.package("0.2.0");
        let (new, new_signature) = signer.package("0.3.0");
        let old = releases.add(&old, &old_signature).await.expect("add");
        let new_id = releases.add(&new, &new_signature).await.expect("add").id;
        let offer = |v| releases.offer_for(AGENT, WINDOWS_X86_64, version(v));

        assert!(
            offer("0.1.0").await.expect("offer").is_none(),
            "none offered"
        );
        releases.offer(old.id).await.expect("offer");
        let offered = offer("0.1.0").await.expect("offer").expect("offered");
        assert_eq!(offered.release.version, version("0.2.0"));
        assert_eq!(
            std::fs::read(&offered.path).expect("package").len() as u64,
            offered.release.size
        );
        assert!(offer("0.2.0").await.expect("offer").is_none(), "not newer");
        assert!(
            offer("0.9.0").await.expect("offer").is_none(),
            "never older"
        );
        assert!(
            releases
                .offer_for(AGENT, "macos-aarch64", version("0.1.0"))
                .await
                .expect("offer")
                .is_none(),
            "another platform"
        );

        // Offering another replaces it.
        releases.offer(new_id).await.expect("offer");
        let listed = releases.list().await.expect("list");
        assert_eq!(
            listed
                .iter()
                .map(|r| (r.version.as_str(), r.offered))
                .collect::<Vec<_>>(),
            [("0.3.0", true), ("0.2.0", false)]
        );
        releases.withdraw(new_id).await.expect("withdraw");
        assert!(offer("0.1.0").await.expect("offer").is_none(), "withdrawn");
    }

    #[tokio::test]
    async fn an_offered_release_is_not_deleted() {
        let signer = Signer::new();
        let (releases, _dir) = releases(&signer).await;
        let (package, signature) = signer.package("0.2.0");
        let id = releases.add(&package, &signature).await.expect("add").id;
        releases.offer(id).await.expect("offer");
        assert!(matches!(
            releases.delete(id).await,
            Err(Refused::Invalid(_))
        ));
        releases.withdraw(id).await.expect("withdraw");
        releases.delete(id).await.expect("delete");
        assert!(!releases.path(&signing::sha256(&package)).exists());
        assert!(matches!(releases.release(id).await, Err(Refused::NotFound)));
    }
}
