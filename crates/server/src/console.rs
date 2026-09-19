//! The web console: one page and its script and style, built into the
//! binary. It is a client of the REST API like any script (`console/`), so
//! it adds no endpoints of its own and no way in that the API lacks.
//!
//! Everything it loads comes from here: the Content-Security-Policy allows
//! this server's own script, style and API and nothing else — no inline
//! script, no other origin, no framing.

use axum::Router;
use axum::http::header::{
    CACHE_CONTROL, CONTENT_SECURITY_POLICY, CONTENT_TYPE, REFERRER_POLICY, X_CONTENT_TYPE_OPTIONS,
    X_FRAME_OPTIONS,
};
use axum::response::IntoResponse;
use axum::routing::get;

const INDEX: &str = include_str!("../console/index.html");
const SCRIPT: &str = include_str!("../console/console.js");
const STYLE: &str = include_str!("../console/console.css");

pub const POLICY: &str = "default-src 'none'; script-src 'self'; style-src 'self'; \
    connect-src 'self'; img-src 'self'; form-action 'self'; base-uri 'none'; \
    frame-ancestors 'none'";

pub fn router<S: Clone + Send + Sync + 'static>() -> Router<S> {
    Router::new()
        .route(
            "/",
            get(|| async { page("text/html; charset=utf-8", INDEX) }),
        )
        .route(
            "/console.js",
            get(|| async { page("text/javascript; charset=utf-8", SCRIPT) }),
        )
        .route(
            "/console.css",
            get(|| async { page("text/css; charset=utf-8", STYLE) }),
        )
}

fn page(content_type: &'static str, body: &'static str) -> impl IntoResponse {
    (
        [
            (CONTENT_TYPE, content_type),
            (CONTENT_SECURITY_POLICY, POLICY),
            (X_CONTENT_TYPE_OPTIONS, "nosniff"),
            (X_FRAME_OPTIONS, "DENY"),
            (REFERRER_POLICY, "no-referrer"),
            // A new server version brings a new console at once.
            (CACHE_CONTROL, "no-cache"),
        ],
        body,
    )
}
