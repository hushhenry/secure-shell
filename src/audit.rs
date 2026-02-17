//! Audit logging for security events.
//!
//! Extracted from zeroclaw security/audit for use by secure-shell.

use crate::config::AuditConfig;
use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;
use uuid::Uuid;

/// Audit event types.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventType {
    /// Shell command execution.
    CommandExecution,
    /// File access.
    FileAccess,
    /// Configuration change.
    ConfigChange,
    /// Authentication success.
    AuthSuccess,
    /// Authentication failure.
    AuthFailure,
    /// Policy violation.
    PolicyViolation,
    /// Generic security event.
    SecurityEvent,
}

/// Actor information (who performed the action).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Actor {
    /// Channel or source (e.g. telegram, cli).
    pub channel: String,
    /// Optional user identifier.
    pub user_id: Option<String>,
    /// Optional username.
    pub username: Option<String>,
}

/// Action information (what was done).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Action {
    /// Command string if applicable.
    pub command: Option<String>,
    /// Risk level (low, medium, high).
    pub risk_level: Option<String>,
    /// Whether the action was explicitly approved.
    pub approved: bool,
    /// Whether the action was allowed by policy.
    pub allowed: bool,
}

/// Execution result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionResult {
    /// Whether execution succeeded.
    pub success: bool,
    /// Process exit code if available.
    pub exit_code: Option<i32>,
    /// Duration in milliseconds.
    pub duration_ms: Option<u64>,
    /// Error message if any.
    pub error: Option<String>,
}

/// Security context attached to audit events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityContext {
    /// Whether a policy violation occurred.
    pub policy_violation: bool,
    /// Remaining rate limit if applicable.
    pub rate_limit_remaining: Option<u32>,
    /// Sandbox backend name if used.
    pub sandbox_backend: Option<String>,
}

/// Complete audit event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Event timestamp (UTC).
    pub timestamp: DateTime<Utc>,
    /// Unique event ID.
    pub event_id: String,
    /// Event type.
    pub event_type: AuditEventType,
    /// Optional actor.
    pub actor: Option<Actor>,
    /// Optional action details.
    pub action: Option<Action>,
    /// Optional execution result.
    pub result: Option<ExecutionResult>,
    /// Security context.
    pub security: SecurityContext,
}

impl AuditEvent {
    /// Create a new audit event.
    pub fn new(event_type: AuditEventType) -> Self {
        Self {
            timestamp: Utc::now(),
            event_id: Uuid::new_v4().to_string(),
            event_type,
            actor: None,
            action: None,
            result: None,
            security: SecurityContext {
                policy_violation: false,
                rate_limit_remaining: None,
                sandbox_backend: None,
            },
        }
    }

    /// Set the actor.
    pub fn with_actor(
        mut self,
        channel: String,
        user_id: Option<String>,
        username: Option<String>,
    ) -> Self {
        self.actor = Some(Actor {
            channel,
            user_id,
            username,
        });
        self
    }

    /// Set the action.
    pub fn with_action(
        mut self,
        command: String,
        risk_level: String,
        approved: bool,
        allowed: bool,
    ) -> Self {
        self.action = Some(Action {
            command: Some(command),
            risk_level: Some(risk_level),
            approved,
            allowed,
        });
        self
    }

    /// Set the result.
    pub fn with_result(
        mut self,
        success: bool,
        exit_code: Option<i32>,
        duration_ms: u64,
        error: Option<String>,
    ) -> Self {
        self.result = Some(ExecutionResult {
            success,
            exit_code,
            duration_ms: Some(duration_ms),
            error,
        });
        self
    }

    /// Set security context (e.g. sandbox backend).
    pub fn with_security(mut self, sandbox_backend: Option<String>) -> Self {
        self.security.sandbox_backend = sandbox_backend;
        self
    }
}

/// Audit logger for writing events to a log file.
pub struct AuditLogger {
    log_path: PathBuf,
    config: AuditConfig,
    #[allow(dead_code)]
    buffer: Mutex<Vec<AuditEvent>>,
}

/// Structured command execution details for audit logging.
#[derive(Debug, Clone)]
pub struct CommandExecutionLog<'a> {
    /// Channel or source.
    pub channel: &'a str,
    /// Command string.
    pub command: &'a str,
    /// Risk level (low, medium, high).
    pub risk_level: &'a str,
    /// Whether approved.
    pub approved: bool,
    /// Whether allowed by policy.
    pub allowed: bool,
    /// Whether execution succeeded.
    pub success: bool,
    /// Duration in milliseconds.
    pub duration_ms: u64,
}

impl AuditLogger {
    /// Create a new audit logger. `base_dir` is the directory in which `config.log_path` is resolved.
    pub fn new(config: AuditConfig, base_dir: PathBuf) -> Result<Self> {
        let log_path = base_dir.join(&config.log_path);
        Ok(Self {
            log_path,
            config,
            buffer: Mutex::new(Vec::new()),
        })
    }

    /// Log an event.
    pub fn log(&self, event: &AuditEvent) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }

        self.rotate_if_needed()?;

        let line = serde_json::to_string(event)?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)?;

        writeln!(file, "{}", line)?;
        file.sync_all()?;

        Ok(())
    }

    /// Log a command execution event.
    pub fn log_command_event(&self, entry: CommandExecutionLog<'_>) -> Result<()> {
        let event = AuditEvent::new(AuditEventType::CommandExecution)
            .with_actor(entry.channel.to_string(), None, None)
            .with_action(
                entry.command.to_string(),
                entry.risk_level.to_string(),
                entry.approved,
                entry.allowed,
            )
            .with_result(entry.success, None, entry.duration_ms, None);

        self.log(&event)
    }

    /// Backward-compatible helper to log a command execution event.
    #[allow(clippy::too_many_arguments)]
    pub fn log_command(
        &self,
        channel: &str,
        command: &str,
        risk_level: &str,
        approved: bool,
        allowed: bool,
        success: bool,
        duration_ms: u64,
    ) -> Result<()> {
        self.log_command_event(CommandExecutionLog {
            channel,
            command,
            risk_level,
            approved,
            allowed,
            success,
            duration_ms,
        })
    }

    /// Rotate log if it exceeds max size.
    fn rotate_if_needed(&self) -> Result<()> {
        if let Ok(metadata) = std::fs::metadata(&self.log_path) {
            let current_size_mb = metadata.len() / (1024 * 1024);
            if current_size_mb >= u64::from(self.config.max_size_mb) {
                self.rotate()?;
            }
        }
        Ok(())
    }

    fn rotate(&self) -> Result<()> {
        for i in (1..10).rev() {
            let old_name = format!("{}.{}.log", self.log_path.display(), i);
            let new_name = format!("{}.{}.log", self.log_path.display(), i + 1);
            let _ = std::fs::rename(&old_name, &new_name);
        }

        let rotated = format!("{}.1.log", self.log_path.display());
        std::fs::rename(&self.log_path, &rotated)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn audit_event_new_creates_unique_id() {
        let event1 = AuditEvent::new(AuditEventType::CommandExecution);
        let event2 = AuditEvent::new(AuditEventType::CommandExecution);
        assert_ne!(event1.event_id, event2.event_id);
    }

    #[test]
    fn audit_event_with_actor() {
        let event = AuditEvent::new(AuditEventType::CommandExecution).with_actor(
            "telegram".to_string(),
            Some("123".to_string()),
            Some("@alice".to_string()),
        );

        assert!(event.actor.is_some());
        let actor = event.actor.as_ref().unwrap();
        assert_eq!(actor.channel, "telegram");
        assert_eq!(actor.user_id, Some("123".to_string()));
        assert_eq!(actor.username, Some("@alice".to_string()));
    }

    #[test]
    fn audit_event_serializes_to_json() {
        let event = AuditEvent::new(AuditEventType::CommandExecution)
            .with_actor("telegram".to_string(), None, None)
            .with_action("ls".to_string(), "low".to_string(), false, true)
            .with_result(true, Some(0), 15, None);

        let json = serde_json::to_string(&event);
        assert!(json.is_ok());
        let json = json.expect("serialize");
        let parsed: AuditEvent = serde_json::from_str(json.as_str()).expect("parse");
        assert!(parsed.actor.is_some());
        assert!(parsed.action.is_some());
        assert!(parsed.result.is_some());
    }

    #[test]
    fn audit_logger_disabled_does_not_create_file() -> Result<()> {
        let tmp = TempDir::new()?;
        let config = AuditConfig {
            enabled: false,
            ..Default::default()
        };
        let logger = AuditLogger::new(config, tmp.path().to_path_buf())?;
        let event = AuditEvent::new(AuditEventType::CommandExecution);

        logger.log(&event)?;

        assert!(!tmp.path().join("audit.log").exists());
        Ok(())
    }

    #[test]
    fn audit_event_builder_with_action_result_security() {
        let event = AuditEvent::new(AuditEventType::CommandExecution)
            .with_action("git push".to_string(), "medium".to_string(), true, true)
            .with_result(false, Some(1), 100, Some("failed".to_string()))
            .with_security(Some("docker".to_string()));
        assert!(event.action.is_some());
        assert_eq!(
            event.action.as_ref().unwrap().command,
            Some("git push".to_string())
        );
        assert!(event.result.is_some());
        assert_eq!(event.result.as_ref().unwrap().exit_code, Some(1));
        assert_eq!(event.security.sandbox_backend, Some("docker".to_string()));
    }

    #[test]
    fn audit_event_serde_roundtrip() {
        let event = AuditEvent::new(AuditEventType::SecurityEvent)
            .with_actor("cli".to_string(), None, Some("user".to_string()))
            .with_action("ls".to_string(), "low".to_string(), false, true);
        let json = serde_json::to_string(&event).expect("serialize");
        let parsed: AuditEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.event_id, event.event_id);
        assert_eq!(parsed.event_type, event.event_type);
        assert_eq!(parsed.actor.as_ref().unwrap().channel, "cli");
        assert_eq!(
            parsed.action.as_ref().unwrap().risk_level,
            Some("low".to_string())
        );
    }

    #[test]
    fn audit_logger_log_writes_when_enabled() -> Result<()> {
        let tmp = TempDir::new()?;
        let config = AuditConfig {
            enabled: true,
            log_path: "audit.log".to_string(),
            ..Default::default()
        };
        let logger = AuditLogger::new(config, tmp.path().to_path_buf())?;
        let event = AuditEvent::new(AuditEventType::CommandExecution).with_action(
            "ls".to_string(),
            "low".to_string(),
            false,
            true,
        );
        logger.log(&event)?;
        let log_file = tmp.path().join("audit.log");
        assert!(log_file.exists());
        let content = std::fs::read_to_string(&log_file)?;
        assert!(content.contains("command_execution")); // serde snake_case
        assert!(content.contains("ls"));
        Ok(())
    }

    #[test]
    fn audit_logger_log_rotation_when_exceeds_max_size() -> Result<()> {
        let tmp = TempDir::new()?;
        let log_path = tmp.path().join("audit.log");
        let config = AuditConfig {
            enabled: true,
            log_path: log_path.file_name().unwrap().to_string_lossy().to_string(),
            max_size_mb: 0, // 0 MB → rotate on first write after initial
            ..Default::default()
        };
        let logger = AuditLogger::new(config, tmp.path().to_path_buf())?;
        // Fill file to trigger rotation (max_size_mb 0 means any existing size could trigger; actually 0 MB means current_size_mb >= 0 is true after we write once)
        // So after first log we have 1 line. Then rotate_if_needed: current_size_mb = 0, so 0 >= 0 triggers rotate. So we need to log once, then log again - second time might rotate.
        let event = AuditEvent::new(AuditEventType::CommandExecution);
        logger.log(&event)?;
        logger.log(&event)?;
        // Rotation renames audit.log to audit.log.1.log and creates new audit.log
        let rotated = tmp.path().join("audit.log.1.log");
        let main_log = tmp.path().join("audit.log");
        assert!(main_log.exists() || rotated.exists());
        Ok(())
    }

    #[test]
    fn audit_logger_log_command_convenience() -> Result<()> {
        let tmp = TempDir::new()?;
        let config = AuditConfig {
            enabled: true,
            log_path: "cmd.log".to_string(),
            ..Default::default()
        };
        let logger = AuditLogger::new(config, tmp.path().to_path_buf())?;
        logger.log_command("test", "cargo build", "low", false, true, true, 50)?;
        let content = std::fs::read_to_string(tmp.path().join("cmd.log"))?;
        assert!(content.contains("cargo build"));
        Ok(())
    }
}
