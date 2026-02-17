//! macOS sandbox-exec (Seatbelt) backend.
//!
//! Generates a Scheme (`.sb`) policy file and runs commands via `sandbox-exec -f <policy.sb> <cmd>`.
//! Only compiled on macOS.

#![cfg(target_os = "macos")]

use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

use crate::policy::AllowedPath;
use crate::sandbox::Sandbox;

/// Seatbelt (sandbox-exec) sandbox backend for macOS.
#[derive(Debug)]
pub struct SeatbeltSandbox {
    /// Allow network access when true.
    allow_network: bool,
}

impl Default for SeatbeltSandbox {
    fn default() -> Self {
        Self {
            allow_network: false,
        }
    }
}

impl SeatbeltSandbox {
    /// Create a new Seatbelt sandbox with default settings (no network).
    pub fn new() -> std::io::Result<Self> {
        if Self::probe().is_ok() {
            Ok(Self::default())
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "sandbox-exec not available",
            ))
        }
    }

    /// Create with optional network allow and policy for path rules.
    pub fn with_policy(
        allow_network: bool,
        _allowed_paths: &[AllowedPath],
        _forbidden_paths: &[String],
    ) -> std::io::Result<Self> {
        if !Self::is_sandbox_exec_available() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "sandbox-exec not available",
            ));
        }
        Ok(Self { allow_network })
    }

    /// Probe if sandbox-exec is available (for auto-detection).
    pub fn probe() -> std::io::Result<Self> {
        if Self::is_sandbox_exec_available() {
            Ok(Self::default())
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "sandbox-exec not available",
            ))
        }
    }

    fn is_sandbox_exec_available() -> bool {
        Command::new("sandbox-exec")
            .arg("-h")
            .output()
            .map(|o| o.status.success() || !o.stderr.is_empty())
            .unwrap_or(false)
    }

    /// Generate a Scheme policy file content. Deny by default; allow process-fork/exec, file-read/write for allowed subpaths, /tmp, and optional network.
    pub(crate) fn generate_sb_content(
        &self,
        allowed_paths: &[AllowedPath],
        _forbidden_paths: &[String],
    ) -> String {
        let mut lines = vec![
            "(deny default)".to_string(),
            "(allow process-fork)".to_string(),
        ];

        // Allow execute for common binary paths
        lines.push("(allow process-exec (subpath \"/usr/bin\"))".to_string());
        lines.push("(allow process-exec (subpath \"/bin\"))".to_string());
        lines.push("(allow process-exec (subpath \"/usr/sbin\"))".to_string());

        // Allowed paths: read and optionally write
        for ap in allowed_paths {
            let subpath = ap.path.to_string_lossy();
            let subpath = subpath.trim_end_matches('/');
            if subpath.is_empty() {
                continue;
            }
            lines.push(format!("(allow file-read* (subpath \"{}\"))", subpath));
            if ap.writable {
                lines.push(format!("(allow file-write* (subpath \"{}\"))", subpath));
            }
        }

        // /tmp read+write
        lines.push("(allow file-read* file-write* (subpath \"/tmp\"))".to_string());
        lines.push("(allow file-read* (subpath \"/usr\"))".to_string());
        lines.push("(allow file-read* (subpath \"/lib\"))".to_string());

        if self.allow_network {
            lines.push("(allow network*)".to_string());
        }

        lines.join("\n")
    }

    /// Write policy to a temp file and return path.
    fn write_policy_file(
        &self,
        allowed_paths: &[AllowedPath],
        forbidden_paths: &[String],
    ) -> std::io::Result<PathBuf> {
        let content = self.generate_sb_content(allowed_paths, forbidden_paths);
        let tmp = std::env::temp_dir().join(format!("secure_shell_{}.sb", uuid::Uuid::new_v4()));
        let mut f = File::create(&tmp)?;
        f.write_all(content.as_bytes())?;
        f.sync_all()?;
        Ok(tmp)
    }
}

impl Sandbox for SeatbeltSandbox {
    fn wrap_command(&self, cmd: &mut Command) -> std::io::Result<()> {
        // Default allowed paths for when we don't have a policy: cwd and /tmp
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let allowed_paths = vec![
            AllowedPath {
                path: cwd,
                writable: true,
            },
            AllowedPath {
                path: PathBuf::from("/tmp"),
                writable: true,
            },
        ];
        let forbidden_paths: Vec<String> = vec![];

        let policy_path = self.write_policy_file(&allowed_paths, &forbidden_paths)?;
        let program = cmd.get_program().to_string_lossy().to_string();
        let args: Vec<String> = cmd
            .get_args()
            .map(|s| s.to_string_lossy().to_string())
            .collect();

        let mut sandbox_cmd = Command::new("sandbox-exec");
        sandbox_cmd.arg("-f");
        sandbox_cmd.arg(&policy_path);
        sandbox_cmd.arg(&program);
        sandbox_cmd.args(&args);
        *cmd = sandbox_cmd;
        Ok(())
    }

    fn is_available(&self) -> bool {
        Self::is_sandbox_exec_available()
    }

    fn name(&self) -> &str {
        "seatbelt"
    }

    fn description(&self) -> &str {
        "macOS sandbox-exec (Seatbelt) sandbox"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    #[test]
    fn seatbelt_sandbox_name() {
        if let Ok(sandbox) = SeatbeltSandbox::new() {
            assert_eq!(sandbox.name(), "seatbelt");
        }
    }

    #[test]
    fn seatbelt_probe() {
        let _ = SeatbeltSandbox::probe();
    }

    #[test]
    fn seatbelt_policy_includes_deny_default() {
        let sandbox = SeatbeltSandbox::default();
        let allowed = vec![AllowedPath {
            path: std::path::PathBuf::from("/tmp/ws"),
            writable: true,
        }];
        let forbidden: Vec<String> = vec![];
        let content = sandbox.generate_sb_content(&allowed, &forbidden);
        assert!(content.contains("(deny default)"));
    }

    #[test]
    fn seatbelt_policy_includes_allowed_read_and_write_paths() {
        let sandbox = SeatbeltSandbox::default();
        let allowed = vec![AllowedPath {
            path: std::path::PathBuf::from("/tmp/workspace"),
            writable: true,
        }];
        let forbidden: Vec<String> = vec![];
        let content = sandbox.generate_sb_content(&allowed, &forbidden);
        assert!(content.contains("file-read*"));
        assert!(content.contains("file-write*"));
        assert!(content.contains("/tmp/workspace"));
    }

    #[test]
    fn seatbelt_wrap_command_rewrites_to_sandbox_exec() {
        if let Ok(sandbox) = SeatbeltSandbox::new() {
            let mut cmd = Command::new("echo");
            cmd.arg("hi");
            sandbox.wrap_command(&mut cmd).unwrap();
            assert_eq!(cmd.get_program().to_string_lossy(), "sandbox-exec");
            let args: Vec<String> = cmd.get_args().map(|s| s.to_string_lossy().into()).collect();
            assert_eq!(args[0], "-f");
            assert!(args[1].ends_with(".sb"));
            assert_eq!(args[2], "echo");
            assert_eq!(args[3], "hi");
        }
    }
}
