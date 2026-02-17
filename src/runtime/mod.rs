//! Runtime adapters: native shell vs Docker.

mod docker;
mod native;

pub use docker::DockerRuntime;
pub use native::NativeRuntime;

use std::path::{Path, PathBuf};

use crate::config::RuntimeConfig;

/// Runtime adapter — abstracts where commands run (native host vs Docker, etc.).
pub trait RuntimeAdapter: Send + Sync {
    /// Human-readable runtime name.
    fn name(&self) -> &str;

    /// Whether this runtime supports shell access.
    fn has_shell_access(&self) -> bool;

    /// Whether this runtime supports filesystem access.
    fn has_filesystem_access(&self) -> bool;

    /// Base storage path for this runtime.
    fn storage_path(&self) -> PathBuf;

    /// Whether long-running processes are supported.
    fn supports_long_running(&self) -> bool;

    /// Maximum memory budget in bytes (0 = unlimited).
    fn memory_budget(&self) -> u64 {
        0
    }

    /// Build a shell command process for this runtime.
    fn build_shell_command(
        &self,
        command: &str,
        workspace_dir: &Path,
    ) -> anyhow::Result<tokio::process::Command>;
}

/// Create the appropriate runtime from config.
pub fn create_runtime(config: &RuntimeConfig) -> anyhow::Result<Box<dyn RuntimeAdapter>> {
    match config.kind.as_str() {
        "native" => Ok(Box::new(NativeRuntime::new())),
        "docker" => Ok(Box::new(DockerRuntime::new(config.docker.clone()))),
        other if other.trim().is_empty() => {
            anyhow::bail!("runtime.kind cannot be empty. Supported values: native, docker")
        }
        other => anyhow::bail!(
            "Unknown runtime kind '{}'. Supported values: native, docker",
            other
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn factory_native() {
        let cfg = RuntimeConfig {
            kind: "native".into(),
            ..RuntimeConfig::default()
        };
        let rt = create_runtime(&cfg).unwrap();
        assert_eq!(rt.name(), "native");
        assert!(rt.has_shell_access());
    }

    #[test]
    fn factory_docker() {
        let cfg = RuntimeConfig {
            kind: "docker".into(),
            ..RuntimeConfig::default()
        };
        let rt = create_runtime(&cfg).unwrap();
        assert_eq!(rt.name(), "docker");
        assert!(rt.has_shell_access());
    }

    #[test]
    fn factory_unknown_errors() {
        let cfg = RuntimeConfig {
            kind: "wasm".into(),
            ..RuntimeConfig::default()
        };
        assert!(create_runtime(&cfg).is_err());
    }

    #[test]
    fn factory_empty_errors() {
        let cfg = RuntimeConfig {
            kind: String::new(),
            ..RuntimeConfig::default()
        };
        assert!(create_runtime(&cfg).is_err());
    }
}
