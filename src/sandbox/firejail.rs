//! Firejail sandbox (Linux user-space sandboxing).
//!
//! Firejail is a SUID sandbox program that Linux applications use to sandbox themselves.

use std::process::Command;

use crate::sandbox::Sandbox;

/// Firejail sandbox backend for Linux.
#[derive(Debug, Clone, Default)]
pub struct FirejailSandbox;

impl FirejailSandbox {
    /// Create a new Firejail sandbox.
    pub fn new() -> std::io::Result<Self> {
        if Self::is_installed() {
            Ok(Self)
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Firejail not found. Install with: sudo apt install firejail",
            ))
        }
    }

    /// Probe if Firejail is available (for auto-detection).
    pub fn probe() -> std::io::Result<Self> {
        Self::new()
    }

    fn is_installed() -> bool {
        Command::new("firejail")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
}

impl Sandbox for FirejailSandbox {
    fn wrap_command(&self, cmd: &mut Command) -> std::io::Result<()> {
        let program = cmd.get_program().to_string_lossy().to_string();
        let args: Vec<String> = cmd
            .get_args()
            .map(|s| s.to_string_lossy().to_string())
            .collect();

        let mut firejail_cmd = Command::new("firejail");
        firejail_cmd.args([
            "--private=home",
            "--private-dev",
            "--nosound",
            "--no3d",
            "--novideo",
            "--nowheel",
            "--notv",
            "--noprofile",
            "--quiet",
        ]);
        firejail_cmd.arg(&program);
        firejail_cmd.args(&args);

        *cmd = firejail_cmd;
        Ok(())
    }

    fn is_available(&self) -> bool {
        Self::is_installed()
    }

    fn name(&self) -> &str {
        "firejail"
    }

    fn description(&self) -> &str {
        "Linux user-space sandbox (requires firejail to be installed)"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    #[test]
    fn firejail_sandbox_name() {
        assert_eq!(FirejailSandbox.name(), "firejail");
    }

    #[test]
    fn firejail_description_mentions_dependency() {
        let desc = FirejailSandbox.description();
        assert!(desc.contains("firejail"));
    }

    #[test]
    fn firejail_wrap_command_prepends_with_security_flags() {
        if let Ok(sandbox) = FirejailSandbox::new() {
            let mut cmd = Command::new("ls");
            cmd.arg("-la");
            sandbox.wrap_command(&mut cmd).unwrap();
            assert_eq!(cmd.get_program().to_string_lossy(), "firejail");
            let args: Vec<String> = cmd.get_args().map(|s| s.to_string_lossy().into()).collect();
            assert!(args.contains(&"--private=home".to_string()));
            assert!(args.contains(&"--private-dev".to_string()));
            assert!(args.contains(&"--nosound".to_string()));
            assert!(args.contains(&"--noprofile".to_string()));
            assert!(args.contains(&"--quiet".to_string()));
            assert!(args.contains(&"ls".to_string()));
            assert!(args.contains(&"-la".to_string()));
        }
    }

    #[test]
    fn firejail_is_available_matches_is_installed() {
        let sandbox = FirejailSandbox;
        assert_eq!(sandbox.is_available(), FirejailSandbox::is_installed());
    }
}
