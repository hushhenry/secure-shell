//! Pluggable sandbox backends for OS-level isolation.

mod detect;
#[cfg(target_os = "linux")]
mod firejail;
#[cfg(feature = "sandbox-landlock")]
mod landlock;
#[cfg(feature = "sandbox-bubblewrap")]
mod bubblewrap;
mod docker;
#[cfg(target_os = "macos")]
mod seatbelt;

pub use docker::DockerSandbox;
#[cfg(target_os = "linux")]
pub use firejail::FirejailSandbox;
#[cfg(feature = "sandbox-landlock")]
pub use landlock::LandlockSandbox;
#[cfg(feature = "sandbox-bubblewrap")]
pub use bubblewrap::BubblewrapSandbox;
#[cfg(target_os = "macos")]
pub use seatbelt::SeatbeltSandbox;

use std::process::Command;
use std::sync::Arc;

use crate::config::SecurityConfig;

/// Sandbox backend for OS-level isolation.
pub trait Sandbox: Send + Sync {
    /// Wrap a command with sandbox protection.
    fn wrap_command(&self, cmd: &mut Command) -> std::io::Result<()>;

    /// Check if this sandbox backend is available on the current platform.
    fn is_available(&self) -> bool;

    /// Human-readable name of this sandbox backend.
    fn name(&self) -> &str;

    /// Description of what this sandbox provides.
    fn description(&self) -> &str;
}

/// No-op sandbox (always available, provides no additional isolation).
#[derive(Debug, Clone, Default)]
pub struct NoopSandbox;

impl Sandbox for NoopSandbox {
    fn wrap_command(&self, _cmd: &mut Command) -> std::io::Result<()> {
        Ok(())
    }

    fn is_available(&self) -> bool {
        true
    }

    fn name(&self) -> &str {
        "none"
    }

    fn description(&self) -> &str {
        "No sandboxing (application-layer security only)"
    }
}

/// Create a sandbox from config. When `persistent` is true, prefers backends that implement `PersistentSandbox` (e.g. Docker).
pub fn create_sandbox(config: &SecurityConfig, persistent: bool) -> Arc<dyn Sandbox> {
    detect::create_sandbox_impl(config, persistent)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noop_sandbox_name() {
        assert_eq!(NoopSandbox.name(), "none");
    }

    #[test]
    fn noop_sandbox_is_always_available() {
        assert!(NoopSandbox.is_available());
    }

    #[test]
    fn noop_sandbox_wrap_command_is_noop() {
        let mut cmd = Command::new("echo");
        cmd.arg("test");
        let sandbox = NoopSandbox;
        assert!(sandbox.wrap_command(&mut cmd).is_ok());
        assert_eq!(cmd.get_program().to_string_lossy(), "echo");
    }
}
