use super::RuntimeAdapter;
use crate::config::DockerRuntimeConfig;
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

/// Docker runtime with lightweight container isolation.
#[derive(Debug, Clone)]
pub struct DockerRuntime {
    config: DockerRuntimeConfig,
}

impl DockerRuntime {
    /// Create a new Docker runtime
    pub fn new(config: DockerRuntimeConfig) -> Self {
        Self { config }
    }

    /// Validate and resolve workspace path for mounting (exposed for tests).
    pub fn workspace_mount_path(&self, workspace_dir: &Path) -> Result<PathBuf> {
        let resolved = workspace_dir
            .canonicalize()
            .unwrap_or_else(|_| workspace_dir.to_path_buf());

        if !resolved.is_absolute() {
            anyhow::bail!(
                "Docker runtime requires an absolute workspace path, got: {}",
                resolved.display()
            );
        }

        if resolved == Path::new("/") {
            anyhow::bail!("Refusing to mount filesystem root (/) into docker runtime");
        }

        if self.config.allowed_workspace_roots.is_empty() {
            return Ok(resolved);
        }

        let allowed = self.config.allowed_workspace_roots.iter().any(|root| {
            let root_path = Path::new(root)
                .canonicalize()
                .unwrap_or_else(|_| PathBuf::from(root));
            resolved.starts_with(root_path)
        });

        if !allowed {
            anyhow::bail!(
                "Workspace path {} is not in runtime.docker.allowed_workspace_roots",
                resolved.display()
            );
        }

        Ok(resolved)
    }
}

impl RuntimeAdapter for DockerRuntime {
    fn name(&self) -> &str {
        "docker"
    }

    fn has_shell_access(&self) -> bool {
        true
    }

    fn has_filesystem_access(&self) -> bool {
        self.config.mount_workspace
    }

    fn supports_long_running(&self) -> bool {
        false
    }

    fn memory_budget(&self) -> u64 {
        self.config
            .memory_limit_mb
            .map_or(0, |mb| mb.saturating_mul(1024 * 1024))
    }

    fn build_shell_command(
        &self,
        command: &str,
        workspace_dir: &Path,
    ) -> anyhow::Result<tokio::process::Command> {
        let mut process = tokio::process::Command::new("docker");
        process
            .arg("run")
            .arg("--rm")
            .arg("--init")
            .arg("--interactive");

        let network = self.config.network.trim();
        if !network.is_empty() {
            process.arg("--network").arg(network);
        }

        if let Some(memory_limit_mb) = self.config.memory_limit_mb.filter(|mb| *mb > 0) {
            process.arg("--memory").arg(format!("{memory_limit_mb}m"));
        }

        if let Some(cpu_limit) = self.config.cpu_limit.filter(|cpus| *cpus > 0.0) {
            process.arg("--cpus").arg(cpu_limit.to_string());
        }

        if self.config.read_only_rootfs {
            process.arg("--read-only");
        }

        if self.config.mount_workspace {
            let host_workspace = self.workspace_mount_path(workspace_dir).with_context(|| {
                format!(
                    "Failed to validate workspace mount path {}",
                    workspace_dir.display()
                )
            })?;

            process
                .arg("--volume")
                .arg(format!("{}:/workspace:rw", host_workspace.display()))
                .arg("--workdir")
                .arg("/workspace");
        }

        process
            .arg(self.config.image.trim())
            .arg("sh")
            .arg("-c")
            .arg(command);

        Ok(process)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn docker_runtime_name() {
        let runtime = DockerRuntime::new(DockerRuntimeConfig::default());
        assert_eq!(runtime.name(), "docker");
    }

    #[test]
    fn docker_runtime_has_shell_access() {
        let runtime = DockerRuntime::new(DockerRuntimeConfig::default());
        assert!(runtime.has_shell_access());
    }

    #[test]
    fn docker_runtime_memory_budget() {
        let mut cfg = DockerRuntimeConfig::default();
        cfg.memory_limit_mb = Some(256);
        let runtime = DockerRuntime::new(cfg);
        assert_eq!(runtime.memory_budget(), 256 * 1024 * 1024);
    }

    #[test]
    fn docker_runtime_build_shell_command_includes_docker_args() {
        let runtime = DockerRuntime::new(DockerRuntimeConfig::default());
        let cwd = std::env::temp_dir();
        let cmd = runtime.build_shell_command("echo hello", &cwd).unwrap();
        let debug = format!("{cmd:?}");
        assert!(debug.contains("docker"));
        assert!(debug.contains("run"));
        assert!(debug.contains("echo hello"));
    }

    #[test]
    fn docker_workspace_mount_path_rejects_root() {
        let runtime = DockerRuntime::new(DockerRuntimeConfig::default());
        let err = runtime.workspace_mount_path(Path::new("/"));
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("Refusing to mount"));
    }

    #[test]
    fn docker_workspace_mount_path_validates_allowed_roots() {
        let mut config = DockerRuntimeConfig::default();
        config.allowed_workspace_roots = vec!["/allowed".to_string()];
        let runtime = DockerRuntime::new(config);
        let err = runtime.workspace_mount_path(Path::new("/other/workspace"));
        assert!(err.is_err());
        assert!(err
            .unwrap_err()
            .to_string()
            .contains("allowed_workspace_roots"));
    }
}
