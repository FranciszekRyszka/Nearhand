//! The web console: one page and its script and style, built into the
//! binary. It is a client of the REST API like any script (`console/`), so
//! it adds no endpoints of its own and no way in that the API lacks.
//!
//! Everything it loads comes from here: the Content-Security-Policy allows
//! this server's own script, style and API, and its WebTransport address for
//! the web viewer, and nothing else — no inline script, no other origin, no
//! framing.

use std::sync::Arc;

use axum::Router;
use axum::http::HeaderValue;
use axum::http::header::{
    CACHE_CONTROL, CONTENT_SECURITY_POLICY, CONTENT_TYPE, REFERRER_POLICY, X_CONTENT_TYPE_OPTIONS,
    X_FRAME_OPTIONS,
};
use axum::response::{IntoResponse, Response};
use axum::routing::get;

const INDEX: &str = include_str!("../console/index.html");
const SCRIPT: &str = include_str!("../console/console.js");
const STYLE: &str = include_str!("../console/console.css");

/// The policy for pages served from here, which may also open WebTransport
/// sessions to `webtransport` (`host:port` of the QUIC side).
pub fn policy(webtransport: &str) -> String {
    format!(
        "default-src 'none'; script-src 'self'; style-src 'self'; \
         connect-src 'self' https://{webtransport}; img-src 'self'; form-action 'self'; \
         base-uri 'none'; frame-ancestors 'none'"
    )
}

pub fn router<S: Clone + Send + Sync + 'static>(webtransport: &str) -> Router<S> {
    let policy: Arc<HeaderValue> = Arc::new(
        HeaderValue::from_str(&policy(webtransport))
            .unwrap_or_else(|_| HeaderValue::from_static("default-src 'none'")),
    );
    let serve = move |content_type: &'static str, body: &'static str| {
        let policy = policy.clone();
        move || {
            let policy = (*policy).clone();
            async move { page(content_type, body, policy) }
        }
    };
    Router::new()
        .route("/", get(serve("text/html; charset=utf-8", INDEX)))
        .route(
            "/console.js",
            get(serve("text/javascript; charset=utf-8", SCRIPT)),
        )
        .route("/console.css", get(serve("text/css; charset=utf-8", STYLE)))
}

fn page(content_type: &'static str, body: &'static str, policy: HeaderValue) -> Response {
    (
        [
            (CONTENT_TYPE, HeaderValue::from_static(content_type)),
            (CONTENT_SECURITY_POLICY, policy),
            (X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff")),
            (X_FRAME_OPTIONS, HeaderValue::from_static("DENY")),
            (REFERRER_POLICY, HeaderValue::from_static("no-referrer")),
            // A new server version brings a new console at once.
            (CACHE_CONTROL, HeaderValue::from_static("no-cache")),
        ],
        body,
    )
        .into_response()
}
