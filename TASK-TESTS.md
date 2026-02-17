# TASK: Add Comprehensive Tests, CI, and Documentation

## Overview
The secure-shell project needs comprehensive testing, cross-platform CI, and documentation for sandbox backend dependencies.

## Task 1: Unit Tests

Add thorough unit tests to every module. Each test module should cover happy paths, edge cases, and error conditions.

### src/policy.rs — Add tests for:
- `is_path_allowed`: allowed_paths priority over forbidden_paths (e.g., allowed=/home/user/workspace, forbidden=/home → workspace subpaths should be allowed)
- `is_path_allowed`: symlink escape detection (create a symlink inside allowed dir pointing outside, verify it's blocked after canonicalization)
- `is_path_allowed`: null bytes in paths
- `is_path_allowed`: URL-encoded traversal (`..%2f`)
- `is_path_allowed`: empty allowed_paths (should deny everything)
- `is_path_allowed`: overlapping allowed and forbidden paths
- `is_resolved_path_allowed`: paths outside all allowed dirs
- `is_command_allowed`: pipe chains where one segment is disallowed
- `is_command_allowed`: commands with env var prefixes (e.g., `FOO=bar ls`)
- `is_command_allowed`: background operator `&` vs `&&`
- `is_command_allowed`: backtick injection, `$()` injection, `${}` injection
- `is_command_allowed`: output redirection `>`, `>>`
- `is_command_allowed`: newline injection
- `command_risk_level`: verify Low/Medium/High classification for various commands
- `validate_command_execution`: approval flows for medium and high risk
- `record_action` / `is_rate_limited`: sliding window behavior
- `from_workspace_dir`: backward compatibility constructor

### src/audit.rs — Add tests for:
- `AuditEvent::new` generates unique IDs
- `AuditEvent` builder pattern (with_actor, with_action, with_result, with_security)
- `AuditEvent` serde roundtrip (serialize then deserialize)
- `AuditLogger::log` writes to file when enabled
- `AuditLogger::log` does NOT write when disabled
- `AuditLogger` log rotation when file exceeds max size
- `log_command` convenience method

### src/sandbox/mod.rs — Add tests for:
- `NoopSandbox` wrap_command is identity
- `create_sandbox` with backend=None returns Noop
- `create_sandbox` with backend=Auto returns something available

### src/sandbox/docker.rs — Add tests for:
- `DockerSandbox::wrap_command` rewrites command correctly (program becomes "docker", original cmd is arg)
- `DockerSandbox::wrap_command` includes --rm, --memory, --cpus, --network none
- `PersistentSandbox` methods return correct errors when Docker is not installed
- Verify SECURE_SHELL_LABEL is applied

### src/sandbox/firejail.rs — Add tests for:
- `wrap_command` prepends firejail with all security flags
- Verify `--private=home`, `--private-dev`, `--nosound`, etc. are present
- `is_available` returns false when firejail is not installed

### src/sandbox/bubblewrap.rs — Add tests for:
- `wrap_command` prepends bwrap with correct flags
- Verify `--ro-bind /usr /usr`, `--unshare-all`, `--die-with-parent`

### src/sandbox/seatbelt.rs — Add tests for:
- Policy generation includes `(deny default)`
- Policy includes allowed read paths
- Policy includes allowed write paths
- `wrap_command` rewrites to `sandbox-exec -f <profile> <cmd>`

### src/sandbox/landlock.rs — Add tests for:
- Sandbox name is "landlock"
- Non-Linux platforms return unavailable

### src/sandbox/detect.rs — Add tests for:
- `create_sandbox_impl` with each backend variant
- Auto-detection returns at least NoopSandbox
- Persistent flag preference

### src/persistence.rs — Add tests for:
- `unsupported()` returns correct error kind

### src/runtime/mod.rs — Add tests for:
- `create_runtime("native")` works
- `create_runtime("docker")` works  
- `create_runtime("unknown")` errors
- `create_runtime("")` errors

### src/runtime/native.rs — Add tests for:
- name, has_shell_access, has_filesystem_access, supports_long_running
- memory_budget is 0
- storage_path contains "zeroclaw"
- build_shell_command produces valid command

### src/runtime/docker.rs — Add tests for:
- name, has_shell_access, storage_path
- memory_budget calculation
- build_shell_command includes docker args
- workspace_mount_path rejects root "/"
- workspace_mount_path validates allowed roots

### src/config.rs — Add tests for:
- Default values for all config types
- Serde roundtrip for SecurityConfig, SandboxConfig, etc.

## Task 2: Integration / Functional Tests

Create `tests/` directory with integration tests:

### tests/policy_integration.rs
- End-to-end test: create policy, validate commands, check paths
- Test the full flow: policy creation → command validation → risk assessment → rate limiting

### tests/sandbox_integration.rs
- Test `create_sandbox` with various configs
- Test that NoopSandbox actually allows commands through
- On Linux: test Firejail wrapping if available
- Platform-conditional tests with `#[cfg(target_os = "...")]`

## Task 3: GitHub Actions CI

Create `.github/workflows/ci.yml`:

```yaml
name: CI

on:
  push:
    branches: [master, main]
  pull_request:

env:
  CARGO_TERM_COLOR: always

jobs:
  test-linux:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - name: Install sandbox dependencies
        run: |
          sudo apt-get update
          sudo apt-get install -y firejail bubblewrap
      - name: Build
        run: cargo build --all-features
      - name: Test
        run: cargo test --all-features -- --nocapture
      - name: Test without optional features
        run: cargo test

  test-macos:
    runs-on: macos-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - name: Build
        run: cargo build
      - name: Test
        run: cargo test -- --nocapture

  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: clippy, rustfmt
      - name: Format check
        run: cargo fmt -- --check
      - name: Clippy
        run: cargo clippy --all-features -- -D warnings
```

## Task 4: Documentation — Sandbox Backend Dependencies

Update README.md to add a section "## Sandbox Backend Dependencies" with:

### Linux
- **Landlock**: No installation needed. Requires Linux kernel 5.13+. Check with `uname -r`.
- **Firejail**: `sudo apt install firejail` (Debian/Ubuntu), `sudo dnf install firejail` (Fedora), `sudo pacman -S firejail` (Arch)
- **Bubblewrap**: `sudo apt install bubblewrap` (Debian/Ubuntu), `sudo dnf install bubblewrap` (Fedora), `sudo pacman -S bubblewrap` (Arch)
- **Docker**: Follow [Docker Engine install guide](https://docs.docker.com/engine/install/)

### macOS
- **Seatbelt (sandbox-exec)**: Built into macOS, no installation needed. Available on macOS 10.5+.
- **Docker**: Install [Docker Desktop](https://www.docker.com/products/docker-desktop/), [OrbStack](https://orbstack.dev/), or [Colima](https://github.com/abiosoft/colima) (`brew install colima docker`)

### Feature Flags
- `sandbox-landlock`: Enable Landlock support (Linux only, requires `landlock` crate)
- `sandbox-bubblewrap`: Enable Bubblewrap support

## Important Notes
- Use `#[cfg(target_os = "linux")]` and `#[cfg(target_os = "macos")]` for platform-specific tests
- Tests that require external tools (firejail, docker) should check availability first and skip gracefully
- Run `cargo fmt` and `cargo clippy` before finishing
- Make sure `cargo test` passes on the current platform
- Make sure `cargo check` passes with and without features
