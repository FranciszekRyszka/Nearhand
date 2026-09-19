//! Embed the web viewer if it has been built (`packaging/web/build.*`):
//! `cfg(web_viewer)` when `web/pkg` holds it. Without it the server still
//! builds, and its /view page says what is missing.

use std::path::Path;

fn main() {
    println!("cargo::rustc-check-cfg=cfg(web_viewer)");
    println!("cargo::rerun-if-changed=web/pkg");
    let pkg = Path::new(env!("CARGO_MANIFEST_DIR")).join("web/pkg");
    if pkg.join("nearhand_web_bg.wasm").exists() && pkg.join("nearhand_web.js").exists() {
        println!("cargo::rerun-if-changed=web/pkg/nearhand_web_bg.wasm");
        println!("cargo::rerun-if-changed=web/pkg/nearhand_web.js");
        println!("cargo::rustc-cfg=web_viewer");
    }
}
