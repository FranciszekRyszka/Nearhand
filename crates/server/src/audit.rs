//! The audit log: every change an administrator makes, every sign-in and
//! failed one, every device enrolled, and every session a grant opened or a
//! missing grant refused — who, when, from where.
//!
//! Rows are only added. Writing one must not stop what it records, so a
//! failure to write is logged rather than returned; the service log then
//! has it.

use std::net::IpAddr;

use serde::Serialize;
use sqlx::SqlitePool;

use crate::accounts::{Refused, internal};
use crate::db::now;

/// The most entries one request returns.
pub const MAX_PAGE: u32 = 500;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Entry {
    pub id: i64,
    pub at: i64,
    /// The user's name as it was; none for the server itself, or someone
    /// not signed in.
    pub actor: Option<String>,
    pub address: Option<String>,
    /// Dotted, such as `user.create` or `session.grant`.
    pub action: String,
    /// What it was done to, in words: a user's or device's name.
    pub target: Option<String>,
    pub detail: Option<String>,
}

/// One thing to record.
#[derive(Debug, Default, Clone)]
pub struct Event<'a> {
    pub actor: Option<&'a str>,
    pub address: Option<IpAddr>,
    pub action: &'a str,
    pub target: Option<&'a str>,
    pub detail: Option<String>,
}

type Row = (
    i64,
    i64,
    Option<String>,
    Option<String>,
    String,
    Option<String>,
    Option<String>,
);

pub struct Audit {
    pool: SqlitePool,
}

impl Audit {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn record(&self, event: Event<'_>) {
        tracing::info!(
            actor = event.actor.unwrap_or("-"),
            address = ?event.address,
            target = event.target.unwrap_or("-"),
            detail = event.detail.as_deref().unwrap_or("-"),
            "audit: {}",
            event.action
        );
        let written = sqlx::query(
            "INSERT INTO audit_log (at, actor, address, action, target, detail) \
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(now())
        .bind(event.actor)
        .bind(event.address.map(|a| a.to_canonical().to_string()))
        .bind(event.action)
        .bind(event.target)
        .bind(event.detail.as_deref())
        .execute(&self.pool)
        .await;
        if let Err(e) = written {
            tracing::error!(error = %e, action = event.action, "could not write to the audit log");
        }
    }

    /// The newest entries first, up to `limit`, older than entry `before` if
    /// given: pass the last id of one page to get the next.
    pub async fn entries(&self, before: Option<i64>, limit: u32) -> Result<Vec<Entry>, Refused> {
        let rows: Vec<Row> = sqlx::query_as(
            "SELECT id, at, actor, address, action, target, detail FROM audit_log \
             WHERE id < ? ORDER BY id DESC LIMIT ?",
        )
        .bind(before.unwrap_or(i64::MAX))
        .bind(i64::from(limit.clamp(1, MAX_PAGE)))
        .fetch_all(&self.pool)
        .await
        .map_err(internal)?;
        Ok(rows
            .into_iter()
            .map(|(id, at, actor, address, action, target, detail)| Entry {
                id,
                at,
                actor,
                address,
                action,
                target,
                detail,
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn entries_come_back_newest_first_a_page_at_a_time() {
        let audit = Audit::new(crate::db::in_memory().await);
        for n in 0..5 {
            audit
                .record(Event {
                    actor: Some("ada"),
                    address: Some("192.0.2.1".parse().expect("ip")),
                    action: "user.create",
                    target: Some(&format!("user{n}")),
                    detail: None,
                })
                .await;
        }
        let first = audit.entries(None, 2).await.expect("page");
        let targets: Vec<_> = first.iter().map(|e| e.target.as_deref()).collect();
        assert_eq!(targets, [Some("user4"), Some("user3")]);
        assert_eq!(first[0].address.as_deref(), Some("192.0.2.1"));
        let next = audit
            .entries(Some(first[1].id), 10)
            .await
            .expect("next page");
        assert_eq!(next.len(), 3);
        assert_eq!(next[0].target.as_deref(), Some("user2"));
    }

    #[tokio::test]
    async fn the_server_itself_can_be_the_actor() {
        let audit = Audit::new(crate::db::in_memory().await);
        audit
            .record(Event {
                action: "device.enroll",
                target: Some("PC-1"),
                ..Event::default()
            })
            .await;
        let entries = audit.entries(None, 10).await.expect("entries");
        assert_eq!(entries[0].actor, None);
        assert_eq!(entries[0].action, "device.enroll");
    }
}
