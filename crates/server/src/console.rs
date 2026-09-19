//! The web console and the web viewer: pages, scripts and styles built into
//! the binary. Both are clients of the REST API like any script
//! (`console/`, `web/`), so they add no endpoints of their own and no way in
//! that the API lacks.
//!
//! Everything they load comes from here: the Content-Security-Policy allows
//! this server's own script, style and API, and its WebTransport address for
//! the web viewer, and nothing else — no inline script, no other origin, no
//! framing. The viewer page may also compile WebAssembly
//! (`'wasm-unsafe-eval'`, which permits nothing for JavaScript); the
//! console may not.

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
const VIEW: &str = include_str!("../web/view.html");
const VIEW_SCRIPT: &str = include_str!("../web/view.js");
const VIEW_STYLE: &str = include_str!("../web/view.css");

#[cfg(web_viewer)]
const WASM_GLUE: &str = include_str!("../web/pkg/nearhand_web.js");
#[cfg(web_viewer)]
const WASM: &[u8] = include_bytes!("../web/pkg/nearhand_web_bg.wasm");
/// What the viewer's script gets in place of the WebAssembly when the
/// server was built without it: a module that says so.
#[cfg(not(web_viewer))]
const WASM_GLUE: &str = "export default async function () {\n\
    throw new Error(\"This server was built without the web viewer: run \
    packaging/web/build.ps1 (or build.sh) and build the server again.\");\n}\n\
    export class Viewer {}\nexport function introduction_request() {}\n\
    export function introduction_answer() {}\n";
#[cfg(not(web_viewer))]
const WASM: &[u8] = b"";

/// The policy for pages served from here, which may also open WebTransport
/// sessions to `webtransport` (`host:port` of the QUIC side), and, with
/// `wasm`, compile WebAssembly.
pub fn policy(webtransport: &str, wasm: bool) -> String {
    let script = if wasm {
        "'self' 'wasm-unsafe-eval'"
    } else {
        "'self'"
    };
    format!(
        "default-src 'none'; script-src {script}; style-src 'self'; \
         connect-src 'self' https://{webtransport}; img-src 'self'; form-action 'self'; \
         base-uri 'none'; frame-ancestors 'none'"
    )
}

pub fn router<S: Clone + Send + Sync + 'static>(webtransport: &str) -> Router<S> {
    let header = |wasm| {
        Arc::new(
            HeaderValue::from_str(&policy(webtransport, wasm))
                .unwrap_or_else(|_| HeaderValue::from_static("default-src 'none'")),
        )
    };
    let console: Arc<HeaderValue> = header(false);
    let viewer: Arc<HeaderValue> = header(true);
    let serve =
        move |policy: &Arc<HeaderValue>, content_type: &'static str, body: &'static [u8]| {
            let policy = policy.clone();
            move || {
                let policy = (*policy).clone();
                async move { page(content_type, body, policy) }
            }
        };
    let html = "text/html; charset=utf-8";
    let js = "text/javascript; charset=utf-8";
    let css = "text/css; charset=utf-8";
    Router::new()
        .route("/", get(serve(&console, html, INDEX.as_bytes())))
        .route("/console.js", get(serve(&console, js, SCRIPT.as_bytes())))
        .route("/console.css", get(serve(&console, css, STYLE.as_bytes())))
        .route("/view", get(serve(&viewer, html, VIEW.as_bytes())))
        .route("/view.js", get(serve(&viewer, js, VIEW_SCRIPT.as_bytes())))
        .route("/view.css", get(serve(&viewer, css, VIEW_STYLE.as_bytes())))
        .route(
            "/pkg/nearhand_web.js",
            get(serve(&viewer, js, WASM_GLUE.as_bytes())),
        )
        .route(
            "/pkg/nearhand_web_bg.wasm",
            get(serve(&viewer, "application/wasm", WASM)),
        )
}

fn page(content_type: &'static str, body: &'static [u8], policy: HeaderValue) -> Response {
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
