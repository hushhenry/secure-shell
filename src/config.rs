//! Configuration types for security, sandbox, runtime, and audit.
//!
//! Extracted from zeroclaw config/schema for use by secure-shell only.

use serde::{Deserialize, Serialize};

/// How much autonomy the agent has. Re-exported from policy for API convenience.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AutonomyLevel {
    /// Read-only: can observe but not act.
    ReadOnly,
    /// Supervised: acts but requires approval for risky operations.
    #[default]
    Supervised,
    /// Full: autonomous execution within policy bounds.
    Full,
}
use std::path::PathBuf;

// ── Autonomy / Security ──────────────────────────────────────────

/// Autonomy and security policy configuration (from config file or API).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutonomyConfig {
    /// Autonomy level (readonly, supervised, full).
    pub level: AutonomyLevel,
    /// When true, only paths under the configured workspace are allowed (legacy).
    pub workspace_only: bool,
    /// Workspace directory used when workspace_only is true (legacy; builds allowed_paths).
    pub workspace_dir: Option<PathBuf>,
    /// Command allowlist (e.g. git, cargo, ls).
    pub allowed_commands: Vec<String>,
    /// Path prefixes that are always denied.
    pub forbidden_paths: Vec<String>,
    /// Max actions per hour for rate limiting.
    pub max_actions_per_hour: u32,
    /// Max cost per day (cents) for budget enforcement.
    pub max_cost_per_day_cents: u32,
    /// Require explicit approval for medium-risk shell commands.
    #[serde(default = "default_true")]
    pub require_approval_for_medium_risk: bool,
    /// Block high-risk shell commands even if allowlisted.
    #[serde(default = "default_true")]
    pub block_high_risk_commands: bool,
}

fn default_true() -> bool {
    true
}

impl Default for AutonomyConfig {
    fn default() -> Self {
        Self {
            level: AutonomyLevel::Supervised,
            workspace_only: true,
            workspace_dir: None,
            allowed_commands: vec![
                "git".into(),
                "npm".into(),
                "cargo".into(),
                "ls".into(),
                "cat".into(),
                "grep".into(),
                "find".into(),
                "echo".into(),
                "pwd".into(),
                "wc".into(),
                "head".into(),
                "tail".into(),
            ],
            forbidden_paths: vec![
                "/etc".into(),
                "/root".into(),
                "/home".into(),
                "/usr".into(),
                "/bin".into(),
                "/sbin".into(),
                "/lib".into(),
                "/opt".into(),
                "/boot".into(),
                "/dev".into(),
                "/proc".into(),
                "/sys".into(),
                "/var".into(),
                "/tmp".into(),
                "~/.ssh".into(),
                "~/.gnupg".into(),
                "~/.aws".into(),
                "~/.config".into(),
            ],
            max_actions_per_hour: 20,
            max_cost_per_day_cents: 500,
            require_approval_for_medium_risk: true,
            block_high_risk_commands: true,
        }
    }
}

// ── Security (sandbox + audit) ─────────────────────────────────────

/// Top-level security configuration (sandbox + resources + audit).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SecurityConfig {
    #[serde(default)]
    pub sandbox: SandboxConfig,
    #[serde(default)]
    pub resources: ResourceLimitsConfig,
    #[serde(default)]
    pub audit: AuditConfig,
}

/// Sandbox backend and options.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxConfig {
    /// Enable sandboxing (None = auto-detect).
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub backend: SandboxBackend,
    /// Custom Firejail arguments when backend = firejail.
    #[serde(default)]
    pub firejail_args: Vec<String>,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            enabled: None,
            backend: SandboxBackend::Auto,
            firejail_args: Vec::new(),
        }
    }
}

/// Sandbox backend selection.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum SandboxBackend {
    #[default]
    Auto,
    Landlock,
    Firejail,
    Bubblewrap,
    Docker,
    #[cfg(target_os = "macos")]
    Seatbelt,
    None,
}

/// Resource limits for command execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimitsConfig {
    #[serde(default = "default_max_memory_mb")]
    pub max_memory_mb: u32,
    #[serde(default = "default_max_cpu_time_seconds")]
    pub max_cpu_time_seconds: u64,
    #[serde(default = "default_max_subprocesses")]
    pub max_subprocesses: u32,
    #[serde(default = "default_memory_monitoring_enabled")]
    pub memory_monitoring: bool,
}

fn default_max_memory_mb() -> u32 {
    512
}
fn default_max_cpu_time_seconds() -> u64 {
    60
}
fn default_max_subprocesses() -> u32 {
    10
}
fn default_memory_monitoring_enabled() -> bool {
    true
}

impl Default for ResourceLimitsConfig {
    fn default() -> Self {
        Self {
            max_memory_mb: default_max_memory_mb(),
            max_cpu_time_seconds: default_max_cpu_time_seconds(),
            max_subprocesses: default_max_subprocesses(),
            memory_monitoring: default_memory_monitoring_enabled(),
        }
    }
}

/// Audit logging configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    #[serde(default = "default_audit_enabled")]
    pub enabled: bool,
    #[serde(default = "default_audit_log_path")]
    pub log_path: String,
    #[serde(default = "default_audit_max_size_mb")]
    pub max_size_mb: u32,
    #[serde(default)]
    pub sign_events: bool,
}

fn default_audit_enabled() -> bool {
    true
}
fn default_audit_log_path() -> String {
    "audit.log".into()
}
fn default_audit_max_size_mb() -> u32 {
    100
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: default_audit_enabled(),
            log_path: default_audit_log_path(),
            max_size_mb: default_audit_max_size_mb(),
            sign_events: false,
        }
    }
}

// ── Runtime ────────────────────────────────────────────────────────

/// Runtime kind and options.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeConfig {
    #[serde(default = "default_runtime_kind")]
    pub kind: String,
    #[serde(default)]
    pub docker: DockerRuntimeConfig,
}

fn default_runtime_kind() -> String {
    "native".into()
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            kind: default_runtime_kind(),
            docker: DockerRuntimeConfig::default(),
        }
    }
}

/// Docker runtime options (when kind = docker).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DockerRuntimeConfig {
    #[serde(default = "default_docker_image")]
    pub image: String,
    #[serde(default = "default_docker_network")]
    pub network: String,
    #[serde(default)]
    pub memory_limit_mb: Option<u64>,
    #[serde(default)]
    pub cpu_limit: Option<f64>,
    #[serde(default = "default_true")]
    pub read_only_rootfs: bool,
    #[serde(default = "default_true")]
    pub mount_workspace: bool,
    #[serde(default)]
    pub allowed_workspace_roots: Vec<String>,
}

fn default_docker_image() -> String {
    "alpine:3.20".into()
}
fn default_docker_network() -> String {
    "none".into()
}

impl Default for DockerRuntimeConfig {
    fn default() -> Self {
        Self {
            image: default_docker_image(),
            network: default_docker_network(),
            memory_limit_mb: Some(512),
            cpu_limit: Some(1.0),
            read_only_rootfs: true,
            mount_workspace: true,
            allowed_workspace_roots: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn autonomy_config_default() {
        let a = AutonomyConfig::default();
        assert_eq!(a.level, AutonomyLevel::Supervised);
        assert!(a.workspace_only);
        assert!(a.allowed_commands.contains(&"git".to_string()));
        assert!(a.forbidden_paths.contains(&"/etc".to_string()));
    }

    #[test]
    fn runtime_config_default() {
        let r = RuntimeConfig::default();
        assert_eq!(r.kind, "native");
        assert_eq!(r.docker.image, "alpine:3.20");
        assert_eq!(r.docker.network, "none");
    }

    #[test]
    fn audit_config_default() {
        let a = AuditConfig::default();
        assert!(a.enabled);
        assert_eq!(a.log_path, "audit.log");
    }
}
