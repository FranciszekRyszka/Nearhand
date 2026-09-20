//! Small things the server's tests share.

use nearhand_transport::rendezvous::Running;

/// What a test's stand-in agent says it is running.
pub(crate) fn testing() -> Running {
    Running::new(env!("CARGO_PKG_VERSION"))
}
