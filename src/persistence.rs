//! Persistence capability for sandboxes: named sessions that survive across commands.
//!
//! Sandboxes that use ephemeral containers (e.g. `docker run --rm`) lose state between runs.
//! The `PersistentSandbox` trait allows backends to support named sessions so that
//! installed packages and other state persist.

use std::io;
use std::process::Command;

use crate::sandbox::Sandbox;

/// Error indicating persistence is not supported by this sandbox backend.
pub fn unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "Persistent sessions are not supported by this sandbox backend",
    )
}

/// Capability: persistent sandbox sessions.
///
/// Only some sandbox backends (e.g. Docker) can support this. Others should return
/// `Err(io::ErrorKind::Unsupported)` from the session methods.
pub trait PersistentSandbox: Sandbox {
    /// Create or resume a named persistent session (e.g. `docker create --name {id}`).
    fn create_session(&self, session_id: &str) -> io::Result<()>;

    /// Execute a command inside an existing persistent session (e.g. `docker exec`).
    fn exec_in_session(&self, session_id: &str, cmd: &mut Command) -> io::Result<()>;

    /// Destroy a persistent session (e.g. `docker rm -f {id}`).
    fn destroy_session(&self, session_id: &str) -> io::Result<()>;

    /// List active persistent sessions (e.g. `docker ps -a --filter label=secure-shell`).
    fn list_sessions(&self) -> io::Result<Vec<String>>;

    /// Check if a session exists.
    fn session_exists(&self, session_id: &str) -> bool {
        self.list_sessions()
            .map(|ids| ids.iter().any(|id| id == session_id))
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_returns_correct_error_kind() {
        let err = unsupported();
        assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
        assert!(err.to_string().contains("not supported"));
    }
}
