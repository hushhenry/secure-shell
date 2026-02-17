//! Docker sandbox (container isolation).
//!
//! Supports both ephemeral `docker run --rm` and persistent sessions via `PersistentSandbox`.

use std::process::Command;

use crate::persistence::PersistentSandbox;
use crate::sandbox::Sandbox;

/// Label applied to all Docker containers created by this sandbox (for filtering).
pub const SECURE_SHELL_LABEL: &str = "secure-shell=true";

/// Docker sandbox backend.
#[derive(Debug, Clone)]
pub struct DockerSandbox {
    image: String,
}

impl Default for DockerSandbox {
    fn default() -> Self {
        Self {
            image: "alpine:latest".to_string(),
        }
    }
}

impl DockerSandbox {
    /// Create a new Docker sandbox with default image.
    pub fn new() -> std::io::Result<Self> {
        if Self::is_installed() {
            Ok(Self::default())
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Docker not available (CLI missing or daemon not running)",
            ))
        }
    }

    /// Create a Docker sandbox with a custom image.
    pub fn with_image(image: String) -> std::io::Result<Self> {
        if Self::is_installed() {
            Ok(Self { image })
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Docker not available (CLI missing or daemon not running)",
            ))
        }
    }

    /// Probe if Docker is available (for auto-detection).
    pub fn probe() -> std::io::Result<Self> {
        Self::new()
    }

    /// Check if Docker CLI is present.
    #[allow(dead_code)]
    fn is_cli_present() -> bool {
        Command::new("docker")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Check if Docker daemon is reachable (CLI present + daemon running).
    fn is_installed() -> bool {
        Command::new("docker")
            .arg("info")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    /// Base docker args for run/create: memory, cpus, network, label.
    fn base_docker_args() -> Vec<&'static str> {
        vec![
            "--memory",
            "512m",
            "--cpus",
            "1.0",
            "--network",
            "none",
            "--label",
            SECURE_SHELL_LABEL,
        ]
    }
}

impl Sandbox for DockerSandbox {
    fn wrap_command(&self, cmd: &mut Command) -> std::io::Result<()> {
        let program = cmd.get_program().to_string_lossy().to_string();
        let args: Vec<String> = cmd
            .get_args()
            .map(|s| s.to_string_lossy().to_string())
            .collect();

        let mut docker_cmd = Command::new("docker");
        docker_cmd.arg("run");
        docker_cmd.arg("--rm");
        for arg in Self::base_docker_args() {
            docker_cmd.arg(arg);
        }
        docker_cmd.arg(&self.image);
        docker_cmd.arg(&program);
        docker_cmd.args(&args);

        *cmd = docker_cmd;
        Ok(())
    }

    fn is_available(&self) -> bool {
        Self::is_installed()
    }

    fn name(&self) -> &str {
        "docker"
    }

    fn description(&self) -> &str {
        "Docker container isolation (requires docker)"
    }
}

impl PersistentSandbox for DockerSandbox {
    fn create_session(&self, session_id: &str) -> std::io::Result<()> {
        let out = Command::new("docker")
            .args([
                "create",
                "--name",
                session_id,
                "--label",
                SECURE_SHELL_LABEL,
                "--memory",
                "512m",
                "--cpus",
                "1.0",
                "--network",
                "none",
                &self.image,
                "sleep",
                "infinity",
            ])
            .output()?;
        if out.status.success() {
            Ok(())
        } else {
            let err = String::from_utf8_lossy(&out.stderr);
            Err(std::io::Error::other(format!(
                "docker create failed: {}",
                err
            )))
        }
    }

    fn exec_in_session(&self, session_id: &str, cmd: &mut Command) -> std::io::Result<()> {
        // Ensure daemon is reachable before rewriting the command
        if !Self::is_installed() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Docker daemon not available",
            ));
        }

        let program = cmd.get_program().to_string_lossy().to_string();
        let args: Vec<String> = cmd
            .get_args()
            .map(|s| s.to_string_lossy().to_string())
            .collect();

        // Start container if stopped
        let start_out = Command::new("docker")
            .arg("start")
            .arg(session_id)
            .output()?;
        if !start_out.status.success() {
            let err = String::from_utf8_lossy(&start_out.stderr);
            return Err(std::io::Error::other(format!("docker start failed: {err}")));
        }

        let mut docker_cmd = Command::new("docker");
        docker_cmd.arg("exec");
        docker_cmd.arg(session_id);
        docker_cmd.arg(&program);
        docker_cmd.args(&args);
        *cmd = docker_cmd;
        Ok(())
    }

    fn destroy_session(&self, session_id: &str) -> std::io::Result<()> {
        let out = Command::new("docker")
            .args(["rm", "-f", session_id])
            .output()?;
        if out.status.success() {
            Ok(())
        } else {
            let err = String::from_utf8_lossy(&out.stderr);
            Err(std::io::Error::other(format!("docker rm failed: {}", err)))
        }
    }

    fn list_sessions(&self) -> std::io::Result<Vec<String>> {
        let out = Command::new("docker")
            .args([
                "ps",
                "-a",
                "--filter",
                &format!("label={}", SECURE_SHELL_LABEL),
                "--format",
                "{{.Names}}",
            ])
            .output()?;
        if !out.status.success() {
            return Err(std::io::Error::other("docker ps failed"));
        }
        let list = String::from_utf8_lossy(&out.stdout);
        let ids: Vec<String> = list
            .lines()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        Ok(ids)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    #[test]
    fn docker_sandbox_name() {
        let sandbox = DockerSandbox::default();
        assert_eq!(sandbox.name(), "docker");
    }

    #[test]
    fn docker_sandbox_default_image() {
        let sandbox = DockerSandbox::default();
        assert_eq!(sandbox.image, "alpine:latest");
    }

    #[test]
    fn docker_with_custom_image() {
        let result = DockerSandbox::with_image("ubuntu:latest".to_string());
        match result {
            Ok(sandbox) => assert_eq!(sandbox.image, "ubuntu:latest"),
            Err(_) => assert!(!DockerSandbox::is_installed()),
        }
    }

    #[test]
    fn docker_wrap_command_rewrites_to_docker_run() {
        let sandbox = DockerSandbox::default();
        let mut cmd = Command::new("echo");
        cmd.arg("hello");
        sandbox.wrap_command(&mut cmd).unwrap();
        let program = cmd.get_program().to_string_lossy();
        assert_eq!(program, "docker");
        let args: Vec<String> = cmd.get_args().map(|s| s.to_string_lossy().into()).collect();
        assert_eq!(args[0], "run");
        assert_eq!(args[1], "--rm");
        assert!(args.contains(&"--memory".to_string()));
        assert!(args.contains(&"--cpus".to_string()));
        assert!(args.contains(&"--network".to_string()));
        assert!(args.contains(&"none".to_string()));
        assert!(args.contains(&SECURE_SHELL_LABEL.to_string()));
        assert!(args.contains(&"echo".to_string()));
        assert!(args.contains(&"hello".to_string()));
    }

    #[test]
    fn docker_persistent_sandbox_errors_when_daemon_not_running() {
        // Skip if Docker daemon IS running — this test is for the "no daemon" case.
        if DockerSandbox::is_installed() {
            return;
        }
        let sandbox = DockerSandbox::default();
        // create_session should fail because `docker create` can't reach daemon
        assert!(sandbox.create_session("test-no-daemon").is_err());
        // exec_in_session should fail
        let mut cmd = Command::new("true");
        assert!(sandbox.exec_in_session("test-no-daemon", &mut cmd).is_err());
        // destroy_session should fail
        assert!(sandbox.destroy_session("test-no-daemon").is_err());
        // list_sessions should fail
        assert!(sandbox.list_sessions().is_err());
    }

    #[test]
    fn docker_session_exists_returns_false_when_no_daemon() {
        if DockerSandbox::is_installed() {
            return;
        }
        let sandbox = DockerSandbox::default();
        assert!(!sandbox.session_exists("nonexistent"));
    }

    #[test]
    fn secure_shell_label_constant() {
        assert_eq!(SECURE_SHELL_LABEL, "secure-shell=true");
    }
}
