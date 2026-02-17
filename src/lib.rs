//! secure-shell — Secure shell execution with pluggable sandbox backends, policy enforcement, and audit logging.
//!
//! Re-exports configuration, policy, audit, sandbox, runtime, and persistence.

pub mod audit;
pub mod config;
pub mod persistence;
pub mod policy;
pub mod runtime;
pub mod sandbox;

pub use config::{
    AuditConfig, AutonomyConfig, AutonomyLevel, DockerRuntimeConfig, ResourceLimitsConfig,
    RuntimeConfig, SandboxBackend, SandboxConfig, SecurityConfig,
};
pub use policy::{AllowedPath, CommandRiskLevel, SecurityPolicy};
pub use audit::{AuditEvent, AuditEventType, AuditLogger, CommandExecutionLog};
pub use persistence::PersistentSandbox;
pub use runtime::{create_runtime, DockerRuntime, NativeRuntime, RuntimeAdapter};
pub use sandbox::{create_sandbox, NoopSandbox, Sandbox};
