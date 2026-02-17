//! Integration tests: create_sandbox with various configs, NoopSandbox behavior, platform-specific backends.

use secure_shell::config::{SandboxBackend, SandboxConfig, SecurityConfig};
use secure_shell::sandbox::{create_sandbox, NoopSandbox, Sandbox};
use std::process::Command;

#[test]
fn create_sandbox_none_returns_noop() {
    let config = SecurityConfig {
        sandbox: SandboxConfig {
            enabled: None,
            backend: SandboxBackend::None,
            firejail_args: vec![],
        },
        ..Default::default()
    };
    let sandbox = create_sandbox(&config, false);
    assert_eq!(sandbox.name(), "none");
}

#[test]
fn create_sandbox_auto_returns_available_backend() {
    let config = SecurityConfig::default();
    let sandbox = create_sandbox(&config, false);
    assert!(sandbox.is_available());
}

#[test]
fn noop_sandbox_allows_commands_through() {
    let mut cmd = Command::new("echo");
    cmd.arg("hello");
    let noop = NoopSandbox;
    noop.wrap_command(&mut cmd).unwrap();
    assert_eq!(cmd.get_program().to_string_lossy(), "echo");
    let args: Vec<String> = cmd.get_args().map(|s| s.to_string_lossy().into()).collect();
    assert_eq!(args, vec!["hello"]);
}

#[test]
fn create_sandbox_persistent_false() {
    let config = SecurityConfig::default();
    let sandbox = create_sandbox(&config, false);
    assert!(sandbox.is_available());
}

#[test]
fn create_sandbox_persistent_true() {
    let config = SecurityConfig::default();
    let sandbox = create_sandbox(&config, true);
    assert!(sandbox.is_available());
}

#[cfg(target_os = "linux")]
#[test]
fn create_sandbox_firejail_if_available() {
    let config = SecurityConfig {
        sandbox: SandboxConfig {
            enabled: Some(true),
            backend: SandboxBackend::Firejail,
            firejail_args: vec![],
        },
        ..Default::default()
    };
    let sandbox = create_sandbox(&config, false);
    if sandbox.name() == "firejail" {
        let mut cmd = Command::new("true");
        assert!(sandbox.wrap_command(&mut cmd).is_ok());
        assert_eq!(cmd.get_program().to_string_lossy(), "firejail");
    }
    assert!(sandbox.is_available());
}

#[cfg(target_os = "macos")]
#[test]
fn create_sandbox_seatbelt_if_available() {
    let config = SecurityConfig {
        sandbox: SandboxConfig {
            enabled: Some(true),
            backend: SandboxBackend::Seatbelt,
            firejail_args: vec![],
        },
        ..Default::default()
    };
    let sandbox = create_sandbox(&config, false);
    assert!(sandbox.is_available());
}
