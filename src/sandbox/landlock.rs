//! Landlock sandbox (Linux kernel 5.13+ LSM).
//!
//! Landlock provides unprivileged sandboxing through the Linux kernel.
//! Uses the pure-Rust `landlock` crate for filesystem access control.

#[cfg(all(feature = "sandbox-landlock", target_os = "linux"))]
use landlock::{AccessFS, Ruleset};
#[cfg(all(feature = "sandbox-landlock", target_os = "linux"))]
use std::path::Path;

use crate::sandbox::Sandbox;

/// Landlock sandbox backend for Linux.
#[cfg(all(feature = "sandbox-landlock", target_os = "linux"))]
#[derive(Debug)]
pub struct LandlockSandbox {
    workspace_dir: Option<std::path::PathBuf>,
}

#[cfg(all(feature = "sandbox-landlock", target_os = "linux"))]
impl LandlockSandbox {
    /// Create a new Landlock sandbox.
    pub fn new() -> std::io::Result<Self> {
        Self::with_workspace(None)
    }

    /// Create a Landlock sandbox with a specific workspace directory.
    pub fn with_workspace(workspace_dir: Option<std::path::PathBuf>) -> std::io::Result<Self> {
        let test_ruleset = Ruleset::new().set_access_fs(AccessFS::read_file | AccessFS::write_file);
        match test_ruleset.create() {
            Ok(_) => Ok(Self { workspace_dir }),
            Err(e) => {
                tracing::debug!("Landlock not available: {}", e);
                Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "Landlock not available",
                ))
            }
        }
    }

    /// Probe if Landlock is available (for auto-detection).
    pub fn probe() -> std::io::Result<Self> {
        Self::new()
    }

    fn apply_restrictions(&self) -> std::io::Result<()> {
        let mut ruleset = Ruleset::new().set_access_fs(
            AccessFS::read_file
                | AccessFS::write_file
                | AccessFS::read_dir
                | AccessFS::remove_dir
                | AccessFS::remove_file
                | AccessFS::make_char
                | AccessFS::make_sock
                | AccessFS::make_fifo
                | AccessFS::make_block
                | AccessFS::make_reg
                | AccessFS::make_sym,
        );

        if let Some(ref workspace) = self.workspace_dir {
            if workspace.exists() {
                ruleset = ruleset.add_path(
                    workspace,
                    AccessFS::read_file | AccessFS::write_file | AccessFS::read_dir,
                )?;
            }
        }

        ruleset = ruleset.add_path(
            Path::new("/tmp"),
            AccessFS::read_file | AccessFS::write_file,
        )?;
        ruleset = ruleset.add_path(Path::new("/usr"), AccessFS::read_file | AccessFS::read_dir)?;
        ruleset = ruleset.add_path(Path::new("/bin"), AccessFS::read_file | AccessFS::read_dir)?;

        match ruleset.create() {
            Ok(_) => {
                tracing::debug!("Landlock restrictions applied successfully");
                Ok(())
            }
            Err(e) => {
                tracing::warn!("Failed to apply Landlock restrictions: {}", e);
                Err(std::io::Error::new(std::io::ErrorKind::Other, e))
            }
        }
    }
}

#[cfg(all(feature = "sandbox-landlock", target_os = "linux"))]
impl Sandbox for LandlockSandbox {
    fn wrap_command(&self, _cmd: &mut std::process::Command) -> std::io::Result<()> {
        self.apply_restrictions()
    }

    fn is_available(&self) -> bool {
        Ruleset::new()
            .set_access_fs(AccessFS::read_file)
            .create()
            .is_ok()
    }

    fn name(&self) -> &str {
        "landlock"
    }

    fn description(&self) -> &str {
        "Linux kernel LSM sandboxing (filesystem access control)"
    }
}

// Stub when feature disabled or not Linux
#[cfg(not(all(feature = "sandbox-landlock", target_os = "linux")))]
#[derive(Debug, Default)]
pub struct LandlockSandbox;

#[cfg(not(all(feature = "sandbox-landlock", target_os = "linux")))]
impl LandlockSandbox {
    pub fn new() -> std::io::Result<Self> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "Landlock is only supported on Linux with the sandbox-landlock feature",
        ))
    }

    pub fn with_workspace(_workspace_dir: Option<std::path::PathBuf>) -> std::io::Result<Self> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "Landlock is only supported on Linux",
        ))
    }

    pub fn probe() -> std::io::Result<Self> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "Landlock is only supported on Linux",
        ))
    }
}

#[cfg(not(all(feature = "sandbox-landlock", target_os = "linux")))]
impl Sandbox for LandlockSandbox {
    fn wrap_command(&self, _cmd: &mut std::process::Command) -> std::io::Result<()> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "Landlock is only supported on Linux",
        ))
    }

    fn is_available(&self) -> bool {
        false
    }

    fn name(&self) -> &str {
        "landlock"
    }

    fn description(&self) -> &str {
        "Linux kernel LSM sandboxing (not available on this platform)"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn landlock_sandbox_name() {
        #[cfg(all(feature = "sandbox-landlock", target_os = "linux"))]
        {
            if let Ok(sandbox) = LandlockSandbox::new() {
                assert_eq!(sandbox.name(), "landlock");
            }
        }
        #[cfg(not(all(feature = "sandbox-landlock", target_os = "linux")))]
        {
            assert_eq!(LandlockSandbox::default().name(), "landlock");
        }
    }

    #[test]
    fn landlock_with_none_workspace() {
        let result = LandlockSandbox::with_workspace(None);
        match result {
            Ok(sandbox) => assert!(sandbox.is_available()),
            Err(_) => {}
        }
    }
}
