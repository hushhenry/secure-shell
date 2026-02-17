//! Landlock sandbox (Linux kernel 5.13+ LSM).
//!
//! Landlock provides unprivileged sandboxing through the Linux kernel.
//! Uses the pure-Rust `landlock` crate for filesystem access control.

#[cfg(all(feature = "sandbox-landlock", target_os = "linux"))]
use landlock::{
    Access, AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr, ABI,
};
#[cfg(all(feature = "sandbox-landlock", target_os = "linux"))]
use std::os::unix::process::CommandExt;
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
        let abi = ABI::V1;
        let access = AccessFs::from_read(abi) | AccessFs::from_write(abi);
        let _ = Ruleset::default()
            .handle_access(access)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Unsupported, e))?
            .create()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Unsupported, e))?;
        Ok(Self { workspace_dir })
    }

    /// Probe if Landlock is available (for auto-detection).
    pub fn probe() -> std::io::Result<Self> {
        Self::new()
    }

    fn apply_restrictions(&self) -> std::io::Result<()> {
        let abi = ABI::V1;
        let access_all = AccessFs::from_all(abi);
        let access_rw = AccessFs::from_read(abi) | AccessFs::from_write(abi);
        let access_ro = AccessFs::from_read(abi);

        let mut created = Ruleset::default()
            .handle_access(access_all)
            .map_err(std::io::Error::other)?
            .create()
            .map_err(std::io::Error::other)?;

        if let Some(ref workspace) = self.workspace_dir {
            if workspace.exists() {
                let fd = PathFd::new(workspace.as_path()).map_err(std::io::Error::other)?;
                created = created
                    .add_rule(PathBeneath::new(fd, access_rw))
                    .map_err(std::io::Error::other)?;
            }
        }

        for (path, access) in [
            (Path::new("/tmp"), access_rw),
            (Path::new("/usr"), access_ro),
            (Path::new("/bin"), access_ro),
        ] {
            if path.exists() {
                let fd = PathFd::new(path).map_err(std::io::Error::other)?;
                created = created
                    .add_rule(PathBeneath::new(fd, access))
                    .map_err(std::io::Error::other)?;
            }
        }

        created.restrict_self().map_err(std::io::Error::other)?;
        tracing::debug!("Landlock restrictions applied successfully");
        Ok(())
    }
}

#[cfg(all(feature = "sandbox-landlock", target_os = "linux"))]
impl Sandbox for LandlockSandbox {
    fn wrap_command(&self, cmd: &mut std::process::Command) -> std::io::Result<()> {
        let workspace_dir = self.workspace_dir.clone();
        unsafe {
            cmd.pre_exec(move || {
                let sandbox = LandlockSandbox {
                    workspace_dir: workspace_dir.clone(),
                };
                sandbox.apply_restrictions()
            });
        }
        Ok(())
    }

    fn is_available(&self) -> bool {
        let abi = ABI::V1;
        let access = AccessFs::from_read(abi);
        Ruleset::default()
            .handle_access(access)
            .and_then(|r: Ruleset| r.create())
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

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn landlock_non_linux_unavailable() {
        let sandbox = LandlockSandbox::default();
        assert!(!sandbox.is_available());
        assert_eq!(sandbox.name(), "landlock");
    }
}
