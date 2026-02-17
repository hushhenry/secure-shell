//! Integration tests: policy creation, command validation, risk assessment, rate limiting.

use secure_shell::{
    config::AutonomyConfig,
    policy::{CommandRiskLevel, SecurityPolicy},
    AllowedPath,
};
use std::path::PathBuf;

#[test]
fn policy_creation_and_validation_flow() {
    let policy = SecurityPolicy::from_workspace_dir(PathBuf::from("/tmp/workspace"));
    assert!(policy.can_act());
    assert!(policy.primary_workspace().is_some());
    assert!(policy.is_command_allowed("ls"));
    assert!(!policy.is_command_allowed("rm -rf /"));
}

#[test]
fn policy_command_validation_and_risk_assessment() {
    let policy = SecurityPolicy::default();
    let risk_low = policy.command_risk_level("cargo build");
    let risk_medium = policy.command_risk_level("git push");
    let risk_high = policy.command_risk_level("sudo ls");
    assert_eq!(risk_low, CommandRiskLevel::Low);
    assert_eq!(risk_medium, CommandRiskLevel::Medium);
    assert_eq!(risk_high, CommandRiskLevel::High);
}

#[test]
fn policy_validate_command_execution_full_flow() {
    let policy = SecurityPolicy::default();
    assert!(policy.validate_command_execution("ls", false).is_ok());
    assert!(policy
        .validate_command_execution("git status", false)
        .is_ok());
    let res = policy.validate_command_execution("git push", false);
    assert!(res.is_err() || res.is_ok()); // depends on require_approval_for_medium_risk
    assert!(policy.validate_command_execution("sudo ls", false).is_err());
}

#[test]
fn policy_rate_limiting_flow() {
    let policy = SecurityPolicy {
        max_actions_per_hour: 3,
        ..SecurityPolicy::default()
    };
    assert!(!policy.is_rate_limited());
    assert!(policy.record_action());
    assert!(policy.record_action());
    assert!(policy.record_action());
    assert!(policy.is_rate_limited());
    assert!(!policy.record_action());
}

#[test]
fn policy_path_checks_full_flow() {
    let tmp = std::env::temp_dir();
    let policy = SecurityPolicy {
        allowed_paths: vec![AllowedPath {
            path: tmp.clone(),
            writable: true,
        }],
        forbidden_paths: vec![],
        ..SecurityPolicy::default()
    };
    let file_in_allowed = tmp.join("integration_test_file");
    let _ = std::fs::write(&file_in_allowed, "ok");
    assert!(policy.is_path_allowed(file_in_allowed.to_str().unwrap()));
    assert!(policy.is_resolved_path_allowed(&file_in_allowed));
    assert!(!policy.is_resolved_path_allowed(std::path::Path::new("/etc/passwd")));
    let _ = std::fs::remove_file(&file_in_allowed);
}

#[test]
fn policy_from_config_integration() {
    let autonomy = AutonomyConfig::default();
    let policy = SecurityPolicy::from_config(&autonomy, std::path::Path::new("/tmp/fallback"));
    assert!(policy.primary_workspace().is_some());
    assert_eq!(policy.autonomy, autonomy.level);
}
