//! Security policy: autonomy level, command allowlist, path allow/forbid, rate limiting, risk classification.

use crate::config::{AutonomyConfig, AutonomyLevel};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Instant;

/// A path that is allowed for access, with optional write permission.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllowedPath {
    /// Directory (or file) path that is allowed.
    pub path: PathBuf,
    /// If true, path is read-write; if false, read-only.
    pub writable: bool,
}

/// Risk level for shell command execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandRiskLevel {
    Low,
    Medium,
    High,
}

/// Sliding-window action tracker for rate limiting.
#[derive(Debug)]
pub struct ActionTracker {
    actions: Mutex<Vec<Instant>>,
}

impl Default for ActionTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl ActionTracker {
    /// Create a new tracker.
    pub fn new() -> Self {
        Self {
            actions: Mutex::new(Vec::new()),
        }
    }

    /// Record an action and return the current count within the window.
    pub fn record(&self) -> usize {
        let mut actions = self.actions.lock();
        let cutoff = Instant::now()
            .checked_sub(std::time::Duration::from_secs(3600))
            .unwrap_or_else(Instant::now);
        actions.retain(|t| *t > cutoff);
        actions.push(Instant::now());
        actions.len()
    }

    /// Count of actions in the current window without recording.
    pub fn count(&self) -> usize {
        let mut actions = self.actions.lock();
        let cutoff = Instant::now()
            .checked_sub(std::time::Duration::from_secs(3600))
            .unwrap_or_else(Instant::now);
        actions.retain(|t| *t > cutoff);
        actions.len()
    }
}

impl Clone for ActionTracker {
    fn clone(&self) -> Self {
        let actions = self.actions.lock();
        Self {
            actions: Mutex::new(actions.clone()),
        }
    }
}

/// Security policy enforced on all tool executions.
#[derive(Debug, Clone)]
pub struct SecurityPolicy {
    /// Autonomy level.
    pub autonomy: AutonomyLevel,
    /// Allowed path entries (replaces single workspace_dir). Takes precedence over forbidden_paths.
    pub allowed_paths: Vec<AllowedPath>,
    /// Forbidden path prefixes (denied even if under an allowed parent unless path is under allowed_paths).
    pub forbidden_paths: Vec<String>,
    /// Command allowlist (base names only).
    pub allowed_commands: Vec<String>,
    /// Max actions per hour.
    pub max_actions_per_hour: u32,
    /// Max cost per day (cents).
    pub max_cost_per_day_cents: u32,
    /// Require approval for medium-risk commands in supervised mode.
    pub require_approval_for_medium_risk: bool,
    /// Block high-risk commands.
    pub block_high_risk_commands: bool,
    /// Rate limit tracker.
    pub tracker: ActionTracker,
}

impl Default for SecurityPolicy {
    fn default() -> Self {
        Self {
            autonomy: AutonomyLevel::Supervised,
            allowed_paths: vec![AllowedPath {
                path: PathBuf::from("."),
                writable: true,
            }],
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
            max_actions_per_hour: 20,
            max_cost_per_day_cents: 500,
            require_approval_for_medium_risk: true,
            block_high_risk_commands: true,
            tracker: ActionTracker::new(),
        }
    }
}

/// Skip leading environment variable assignments (e.g. `FOO=bar cmd args`).
fn skip_env_assignments(s: &str) -> &str {
    let mut rest = s;
    loop {
        let Some(word) = rest.split_whitespace().next() else {
            return rest;
        };
        if word.contains('=')
            && word
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        {
            rest = rest[word.len()..].trim_start();
        } else {
            return rest;
        }
    }
}

/// Detect a single `&` (background); `&&` is allowed.
fn contains_single_ampersand(s: &str) -> bool {
    let bytes = s.as_bytes();
    for (i, b) in bytes.iter().enumerate() {
        if *b != b'&' {
            continue;
        }
        let prev_is_amp = i > 0 && bytes[i - 1] == b'&';
        let next_is_amp = i + 1 < bytes.len() && bytes[i + 1] == b'&';
        if !prev_is_amp && !next_is_amp {
            return true;
        }
    }
    false
}

/// Expand `~` in a path string using `$HOME`.
fn expand_tilde(path: &str) -> PathBuf {
    if let Some(stripped) = path.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home).join(stripped);
        }
    }
    PathBuf::from(path)
}

impl SecurityPolicy {
    /// Create a policy with a single writable workspace directory (backward compatible).
    pub fn from_workspace_dir(dir: PathBuf) -> Self {
        Self {
            allowed_paths: vec![AllowedPath {
                path: dir,
                writable: true,
            }],
            ..Self::default()
        }
    }

    /// Primary workspace: first writable allowed path (for runtime cwd / backward compat).
    pub fn primary_workspace(&self) -> Option<&Path> {
        self.allowed_paths
            .iter()
            .find(|a| a.writable)
            .map(|a| a.path.as_path())
    }

    /// Build from config. Uses workspace_dir from config or provided path to build allowed_paths.
    pub fn from_config(autonomy: &AutonomyConfig, workspace_dir: &Path) -> Self {
        let allowed_paths = if let Some(ref wd) = autonomy.workspace_dir {
            vec![AllowedPath {
                path: wd.clone(),
                writable: true,
            }]
        } else {
            vec![AllowedPath {
                path: workspace_dir.to_path_buf(),
                writable: true,
            }]
        };

        Self {
            autonomy: autonomy.level,
            allowed_paths,
            forbidden_paths: autonomy.forbidden_paths.clone(),
            allowed_commands: autonomy.allowed_commands.clone(),
            max_actions_per_hour: autonomy.max_actions_per_hour,
            max_cost_per_day_cents: autonomy.max_cost_per_day_cents,
            require_approval_for_medium_risk: autonomy.require_approval_for_medium_risk,
            block_high_risk_commands: autonomy.block_high_risk_commands,
            tracker: ActionTracker::new(),
        }
    }

    /// Classify command risk.
    pub fn command_risk_level(&self, command: &str) -> CommandRiskLevel {
        let mut normalized = command.to_string();
        for sep in ["&&", "||"] {
            normalized = normalized.replace(sep, "\x00");
        }
        for sep in ['\n', ';', '|', '&'] {
            normalized = normalized.replace(sep, "\x00");
        }

        let mut saw_medium = false;

        for segment in normalized.split('\x00') {
            let segment = segment.trim();
            if segment.is_empty() {
                continue;
            }

            let cmd_part = skip_env_assignments(segment);
            let mut words = cmd_part.split_whitespace();
            let Some(base_raw) = words.next() else {
                continue;
            };

            let base = base_raw.rsplit('/').next().unwrap_or("").to_lowercase();
            let args: Vec<String> = words.map(|w| w.to_lowercase()).collect();
            let joined_segment = cmd_part.to_lowercase();

            if matches!(
                base.as_str(),
                "rm" | "mkfs"
                    | "dd"
                    | "shutdown"
                    | "reboot"
                    | "halt"
                    | "poweroff"
                    | "sudo"
                    | "su"
                    | "chown"
                    | "chmod"
                    | "useradd"
                    | "userdel"
                    | "usermod"
                    | "passwd"
                    | "mount"
                    | "umount"
                    | "iptables"
                    | "ufw"
                    | "firewall-cmd"
                    | "curl"
                    | "wget"
                    | "nc"
                    | "ncat"
                    | "netcat"
                    | "scp"
                    | "ssh"
                    | "ftp"
                    | "telnet"
            ) {
                return CommandRiskLevel::High;
            }

            if joined_segment.contains("rm -rf /")
                || joined_segment.contains("rm -fr /")
                || joined_segment.contains(":(){:|:&};:")
            {
                return CommandRiskLevel::High;
            }

            let medium = match base.as_str() {
                "git" => args.first().is_some_and(|verb| {
                    matches!(
                        verb.as_str(),
                        "commit"
                            | "push"
                            | "reset"
                            | "clean"
                            | "rebase"
                            | "merge"
                            | "cherry-pick"
                            | "revert"
                            | "branch"
                            | "checkout"
                            | "switch"
                            | "tag"
                    )
                }),
                "npm" | "pnpm" | "yarn" => args.first().is_some_and(|verb| {
                    matches!(
                        verb.as_str(),
                        "install" | "add" | "remove" | "uninstall" | "update" | "publish"
                    )
                }),
                "cargo" => args.first().is_some_and(|verb| {
                    matches!(
                        verb.as_str(),
                        "add" | "remove" | "install" | "clean" | "publish"
                    )
                }),
                "touch" | "mkdir" | "mv" | "cp" | "ln" => true,
                _ => false,
            };

            saw_medium |= medium;
        }

        if saw_medium {
            CommandRiskLevel::Medium
        } else {
            CommandRiskLevel::Low
        }
    }

    /// Validate full command execution (allowlist + risk gate).
    pub fn validate_command_execution(
        &self,
        command: &str,
        approved: bool,
    ) -> Result<CommandRiskLevel, String> {
        if !self.is_command_allowed(command) {
            return Err(format!("Command not allowed by security policy: {command}"));
        }

        let risk = self.command_risk_level(command);

        if risk == CommandRiskLevel::High {
            if self.block_high_risk_commands {
                return Err("Command blocked: high-risk command is disallowed by policy".into());
            }
            if self.autonomy == AutonomyLevel::Supervised && !approved {
                return Err(
                    "Command requires explicit approval (approved=true): high-risk operation"
                        .into(),
                );
            }
        }

        if risk == CommandRiskLevel::Medium
            && self.autonomy == AutonomyLevel::Supervised
            && self.require_approval_for_medium_risk
            && !approved
        {
            return Err(
                "Command requires explicit approval (approved=true): medium-risk operation".into(),
            );
        }

        Ok(risk)
    }

    /// Check if a shell command is allowed (entire command string validated).
    pub fn is_command_allowed(&self, command: &str) -> bool {
        if self.autonomy == AutonomyLevel::ReadOnly {
            return false;
        }
        if command.contains('`') || command.contains("$(") || command.contains("${") {
            return false;
        }
        if command.contains('>') {
            return false;
        }
        if contains_single_ampersand(command) {
            return false;
        }

        let mut normalized = command.to_string();
        for sep in ["&&", "||"] {
            normalized = normalized.replace(sep, "\x00");
        }
        for sep in ['\n', ';', '|'] {
            normalized = normalized.replace(sep, "\x00");
        }

        for segment in normalized.split('\x00') {
            let segment = segment.trim();
            if segment.is_empty() {
                continue;
            }
            let cmd_part = skip_env_assignments(segment);
            let base_cmd = cmd_part
                .split_whitespace()
                .next()
                .unwrap_or("")
                .rsplit('/')
                .next()
                .unwrap_or("");

            if base_cmd.is_empty() {
                continue;
            }
            if !self.allowed_commands.iter().any(|a| a == base_cmd) {
                return false;
            }
        }

        let has_cmd = normalized.split('\x00').any(|s| {
            let s = skip_env_assignments(s.trim());
            s.split_whitespace().next().is_some_and(|w| !w.is_empty())
        });
        has_cmd
    }

    /// Check if a file path is allowed.
    /// Rules: 1) normalize/canonicalize; 2) if under any allowed_path → ALLOW;
    /// 3) if under any forbidden_path → DENY; 4) else DENY. After canonicalize, re-verify resolved path is still under allowed_paths (symlink check).
    pub fn is_path_allowed(&self, path: &str) -> bool {
        if path.contains('\0') {
            return false;
        }
        if Path::new(path)
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return false;
        }
        let lower = path.to_lowercase();
        if lower.contains("..%2f") || lower.contains("%2f..") {
            return false;
        }

        let expanded = expand_tilde(path);

        // Build normalized forbidden paths for comparison
        let forbidden_normalized: Vec<PathBuf> = self
            .forbidden_paths
            .iter()
            .map(|p| expand_tilde(p))
            .collect();

        // 1) Check allowed_paths first (takes precedence). Path must be under at least one allowed path.
        let mut under_allowed = false;
        for allowed in &self.allowed_paths {
            let allowed_canon = allowed
                .path
                .canonicalize()
                .unwrap_or_else(|_| allowed.path.clone());
            let path_canon = match Path::new(&expanded).canonicalize() {
                Ok(p) => p,
                Err(_) => continue,
            };
            if path_canon.starts_with(&allowed_canon) {
                under_allowed = true;
                break;
            }
        }

        if under_allowed {
            // Re-verify resolved path is still within an allowed path (symlink escape check).
            let path_canon = match Path::new(&expanded).canonicalize() {
                Ok(p) => p,
                Err(_) => return false,
            };
            for allowed in &self.allowed_paths {
                let allowed_canon = allowed
                    .path
                    .canonicalize()
                    .unwrap_or_else(|_| allowed.path.clone());
                if path_canon.starts_with(&allowed_canon) {
                    return true;
                }
            }
            return false;
        }

        // 2) If not under any allowed path, check forbidden (for absolute paths that might be explicitly forbidden).
        for forbidden in &forbidden_normalized {
            if expanded.starts_with(forbidden) {
                return false;
            }
        }

        // 3) Default deny: not under any allowed path.
        false
    }

    /// Validate that a resolved path is still inside an allowed path (e.g. after joining + canonicalize). Prevents symlink escapes.
    pub fn is_resolved_path_allowed(&self, resolved: &Path) -> bool {
        for allowed in &self.allowed_paths {
            let root = allowed
                .path
                .canonicalize()
                .unwrap_or_else(|_| allowed.path.clone());
            if resolved.starts_with(&root) {
                return true;
            }
        }
        false
    }

    /// Whether autonomy level permits any action.
    pub fn can_act(&self) -> bool {
        self.autonomy != AutonomyLevel::ReadOnly
    }

    /// Record an action and check rate limit. Returns true if allowed.
    pub fn record_action(&self) -> bool {
        let count = self.tracker.record();
        count <= self.max_actions_per_hour as usize
    }

    /// Check if rate limit would be exceeded without recording.
    pub fn is_rate_limited(&self) -> bool {
        self.tracker.count() >= self.max_actions_per_hour as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_policy() -> SecurityPolicy {
        SecurityPolicy::default()
    }

    fn readonly_policy() -> SecurityPolicy {
        SecurityPolicy {
            autonomy: AutonomyLevel::ReadOnly,
            ..SecurityPolicy::default()
        }
    }

    #[test]
    fn autonomy_default_is_supervised() {
        assert_eq!(AutonomyLevel::default(), AutonomyLevel::Supervised);
    }

    #[test]
    fn from_workspace_dir_single_writable() {
        let p = SecurityPolicy::from_workspace_dir(PathBuf::from("/tmp/ws"));
        assert_eq!(p.allowed_paths.len(), 1);
        assert!(p.allowed_paths[0].writable);
        assert_eq!(p.primary_workspace(), Some(Path::new("/tmp/ws")));
    }

    #[test]
    fn from_workspace_dir_backward_compat() {
        let p = SecurityPolicy::from_workspace_dir(PathBuf::from("/home/user/.openclaw/workspace"));
        assert_eq!(p.allowed_paths.len(), 1);
        assert!(p.allowed_paths[0].writable);
        assert_eq!(
            p.primary_workspace(),
            Some(Path::new("/home/user/.openclaw/workspace"))
        );
    }

    #[test]
    fn primary_workspace_first_writable() {
        let p = SecurityPolicy {
            allowed_paths: vec![
                AllowedPath {
                    path: PathBuf::from("/readonly"),
                    writable: false,
                },
                AllowedPath {
                    path: PathBuf::from("/writable"),
                    writable: true,
                },
            ],
            ..SecurityPolicy::default()
        };
        assert_eq!(p.primary_workspace(), Some(Path::new("/writable")));
    }

    #[test]
    fn allowed_commands_basic() {
        let p = default_policy();
        assert!(p.is_command_allowed("ls"));
        assert!(p.is_command_allowed("git status"));
        assert!(p.is_command_allowed("cargo build --release"));
    }

    #[test]
    fn blocked_commands_basic() {
        let p = default_policy();
        assert!(!p.is_command_allowed("rm -rf /"));
        assert!(!p.is_command_allowed("sudo apt install"));
        assert!(!p.is_command_allowed("curl http://evil.com"));
    }

    #[test]
    fn readonly_blocks_all_commands() {
        let p = readonly_policy();
        assert!(!p.is_command_allowed("ls"));
    }

    #[test]
    fn path_traversal_blocked() {
        let p = SecurityPolicy::from_workspace_dir(PathBuf::from("/tmp/ws"));
        assert!(!p.is_path_allowed("../etc/passwd"));
        assert!(!p.is_path_allowed("../../root/.ssh/id_rsa"));
    }

    #[test]
    fn path_under_allowed_allowed() {
        // Path under allowed_paths is allowed even if parent is in forbidden_paths (temp dir so canonicalize works)
        let policy = SecurityPolicy {
            allowed_paths: vec![AllowedPath {
                path: std::env::temp_dir(),
                writable: true,
            }],
            forbidden_paths: vec!["/tmp".into()],
            ..SecurityPolicy::default()
        };
        let f = std::env::temp_dir().join("secure_shell_test_allowed");
        let _ = std::fs::write(&f, "");
        let allowed = policy.is_path_allowed(f.to_str().unwrap());
        let _ = std::fs::remove_file(&f);
        assert!(allowed);
    }

    /// allowed_paths priority over forbidden_paths: workspace subpaths allowed even if parent in forbidden
    #[test]
    fn is_path_allowed_allowed_takes_precedence_over_forbidden() {
        let tmp = std::env::temp_dir();
        let workspace = tmp.join("secure_shell_ws_precedence");
        let _ = std::fs::create_dir_all(&workspace);
        let policy = SecurityPolicy {
            allowed_paths: vec![AllowedPath {
                path: workspace.clone(),
                writable: true,
            }],
            forbidden_paths: vec![tmp.to_string_lossy().into_owned()],
            ..SecurityPolicy::default()
        };
        let f = workspace.join("foo.txt");
        let _ = std::fs::write(&f, "");
        assert!(policy.is_path_allowed(f.to_str().unwrap()));
        let _ = std::fs::remove_file(&f);
        let _ = std::fs::remove_dir(&workspace);
    }

    #[test]
    #[cfg(unix)]
    fn is_path_allowed_symlink_escape_blocked() {
        let tmp = std::env::temp_dir();
        let workspace = tmp.join("secure_shell_ws_symlink");
        let _ = std::fs::create_dir_all(&workspace);
        let link_path = workspace.join("escape");
        #[allow(unused_must_use)]
        {
            std::os::unix::fs::symlink("/etc/passwd", &link_path);
        }
        let policy = SecurityPolicy {
            allowed_paths: vec![AllowedPath {
                path: workspace.clone(),
                writable: true,
            }],
            forbidden_paths: vec![],
            ..SecurityPolicy::default()
        };
        // Resolving link_path goes to /etc/passwd, outside allowed → denied
        assert!(!policy.is_path_allowed(link_path.to_str().unwrap()));
        let _ = std::fs::remove_file(&link_path);
        let _ = std::fs::remove_dir(&workspace);
    }

    #[test]
    fn path_null_byte_blocked() {
        let p = default_policy();
        assert!(!p.is_path_allowed("file\0.txt"));
    }

    #[test]
    fn is_path_allowed_url_encoded_traversal_blocked() {
        let p = default_policy();
        assert!(!p.is_path_allowed("..%2fetc%2fpasswd"));
        assert!(!p.is_path_allowed("foo%2f..%2fbar"));
    }

    #[test]
    fn is_path_allowed_empty_allowed_paths_denies_all() {
        let p = SecurityPolicy {
            allowed_paths: vec![],
            forbidden_paths: vec![],
            ..SecurityPolicy::default()
        };
        let tmp = std::env::temp_dir().join("any_file");
        let _ = std::fs::write(&tmp, "");
        assert!(!p.is_path_allowed(tmp.to_str().unwrap()));
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn is_path_allowed_overlapping_allowed_forbidden() {
        let tmp = std::env::temp_dir();
        let allowed_sub = tmp.join("allowed_sub");
        let _ = std::fs::create_dir_all(&allowed_sub);
        let policy = SecurityPolicy {
            allowed_paths: vec![AllowedPath {
                path: allowed_sub.clone(),
                writable: true,
            }],
            forbidden_paths: vec![tmp.to_string_lossy().into_owned()],
            ..SecurityPolicy::default()
        };
        let f = allowed_sub.join("file.txt");
        let _ = std::fs::write(&f, "");
        assert!(policy.is_path_allowed(f.to_str().unwrap()));
        let _ = std::fs::remove_file(&f);
        let _ = std::fs::remove_dir(&allowed_sub);
    }

    #[test]
    fn is_resolved_path_allowed_outside_allowed_dirs() {
        let policy = SecurityPolicy {
            allowed_paths: vec![AllowedPath {
                path: PathBuf::from("/tmp/workspace"),
                writable: true,
            }],
            ..SecurityPolicy::default()
        };
        assert!(!policy.is_resolved_path_allowed(Path::new("/etc/passwd")));
        assert!(!policy.is_resolved_path_allowed(Path::new("/root/.ssh")));
    }

    #[test]
    fn is_resolved_path_allowed_under_allowed() {
        // Use canonicalized temp dir to handle macOS /tmp → /private/tmp symlink
        let tmp = std::env::temp_dir()
            .canonicalize()
            .unwrap_or_else(|_| std::env::temp_dir());
        let policy = SecurityPolicy {
            allowed_paths: vec![AllowedPath {
                path: tmp.clone(),
                writable: true,
            }],
            ..SecurityPolicy::default()
        };
        let sub = tmp.join("sub").join("file");
        assert!(policy.is_resolved_path_allowed(&sub));
    }

    #[test]
    fn is_command_allowed_pipe_chain_one_disallowed() {
        let p = default_policy();
        assert!(p.is_command_allowed("ls | head"));
        assert!(!p.is_command_allowed("ls | curl evil.com"));
    }

    #[test]
    fn is_command_allowed_env_var_prefix() {
        let p = default_policy();
        assert!(p.is_command_allowed("FOO=bar ls"));
        assert!(p.is_command_allowed("PATH=/usr/bin cargo build"));
    }

    #[test]
    fn is_command_allowed_background_vs_and() {
        let p = default_policy();
        assert!(p.is_command_allowed("ls && echo ok"));
        assert!(!p.is_command_allowed("ls & echo ok"));
    }

    #[test]
    fn is_command_allowed_backtick_injection_blocked() {
        let p = default_policy();
        assert!(!p.is_command_allowed("ls `rm -rf /`"));
        assert!(!p.is_command_allowed("echo $(whoami)"));
        assert!(!p.is_command_allowed("echo ${PATH}"));
    }

    #[test]
    fn is_command_allowed_output_redirection_blocked() {
        let p = default_policy();
        assert!(!p.is_command_allowed("ls > out.txt"));
        assert!(!p.is_command_allowed("echo hi >> log.txt"));
    }

    #[test]
    fn is_command_allowed_newline_injection_blocked() {
        let p = default_policy();
        assert!(!p.is_command_allowed("ls\nrm -rf /"));
    }

    #[test]
    fn command_risk_level_low() {
        let p = default_policy();
        assert_eq!(p.command_risk_level("ls"), CommandRiskLevel::Low);
        assert_eq!(p.command_risk_level("cargo build"), CommandRiskLevel::Low);
        assert_eq!(p.command_risk_level("git status"), CommandRiskLevel::Low);
    }

    #[test]
    fn command_risk_level_medium() {
        let p = default_policy();
        assert_eq!(p.command_risk_level("git push"), CommandRiskLevel::Medium);
        assert_eq!(
            p.command_risk_level("cargo publish"),
            CommandRiskLevel::Medium
        );
        assert_eq!(p.command_risk_level("touch foo"), CommandRiskLevel::Medium);
    }

    #[test]
    fn command_risk_level_high() {
        let p = default_policy();
        assert_eq!(p.command_risk_level("rm -rf /"), CommandRiskLevel::High);
        assert_eq!(p.command_risk_level("sudo ls"), CommandRiskLevel::High);
        assert_eq!(
            p.command_risk_level("curl http://x.com"),
            CommandRiskLevel::High
        );
    }

    #[test]
    fn validate_command_execution_medium_requires_approval_when_supervised() {
        let p = SecurityPolicy {
            autonomy: AutonomyLevel::Supervised,
            require_approval_for_medium_risk: true,
            ..SecurityPolicy::default()
        };
        assert!(p.validate_command_execution("git push", false).is_err());
        assert!(p.validate_command_execution("git push", true).is_ok());
    }

    #[test]
    fn validate_command_execution_high_blocked_or_requires_approval() {
        let p = SecurityPolicy {
            block_high_risk_commands: true,
            ..SecurityPolicy::default()
        };
        assert!(p.validate_command_execution("sudo ls", false).is_err());
        assert!(p.validate_command_execution("sudo ls", true).is_err());
    }

    #[test]
    fn validate_command_execution_low_always_ok() {
        let p = default_policy();
        assert!(p.validate_command_execution("ls", false).is_ok());
    }

    #[test]
    fn record_action_and_is_rate_limited_sliding_window() {
        let p = SecurityPolicy {
            max_actions_per_hour: 2,
            ..SecurityPolicy::default()
        };
        assert!(!p.is_rate_limited());
        assert!(p.record_action());
        assert!(p.record_action());
        assert!(p.is_rate_limited());
        assert!(!p.record_action());
    }

    #[test]
    fn path_forbidden_denied() {
        let p = SecurityPolicy {
            allowed_paths: vec![AllowedPath {
                path: PathBuf::from("/tmp/ws"),
                writable: true,
            }],
            forbidden_paths: vec!["/etc".into(), "/root".into()],
            ..SecurityPolicy::default()
        };
        assert!(!p.is_path_allowed("/etc/passwd"));
        assert!(!p.is_path_allowed("/root/.bashrc"));
    }

    #[test]
    fn action_tracker_and_rate_limit() {
        let p = SecurityPolicy {
            max_actions_per_hour: 2,
            ..SecurityPolicy::default()
        };
        assert!(p.record_action());
        assert!(p.record_action());
        assert!(!p.record_action());
    }

    #[test]
    fn from_config_maps_fields() {
        let autonomy = AutonomyConfig {
            level: AutonomyLevel::Full,
            workspace_only: false,
            workspace_dir: Some(PathBuf::from("/tmp/test-workspace")),
            allowed_commands: vec!["docker".into()],
            forbidden_paths: vec!["/secret".into()],
            max_actions_per_hour: 100,
            max_cost_per_day_cents: 1000,
            require_approval_for_medium_risk: false,
            block_high_risk_commands: false,
        };
        let policy = SecurityPolicy::from_config(&autonomy, Path::new("/fallback"));
        assert_eq!(policy.autonomy, AutonomyLevel::Full);
        assert_eq!(policy.allowed_commands, vec!["docker"]);
        assert_eq!(policy.allowed_paths.len(), 1);
        assert_eq!(
            policy.allowed_paths[0].path,
            PathBuf::from("/tmp/test-workspace")
        );
    }
}
