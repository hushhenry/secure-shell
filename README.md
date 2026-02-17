# secure-shell

Secure shell execution library with pluggable sandbox backends, path-based access control, policy enforcement, and audit logging. Extracted from zeroclaw for use in agent runtimes.

## Features

- **Security policy**: Autonomy levels, command allowlist, path allow/forbid lists, rate limiting, risk classification.
- **Sandbox backends**: No-op, Landlock (Linux), Firejail (Linux), Bubblewrap, Docker, sandbox-exec/Seatbelt (macOS).
- **Path access control**: `allowed_paths` (read-only or writable) and `forbidden_paths` with symlink-safe checks.
- **Persistence**: Optional persistent Docker sessions so installed packages survive across runs.
- **Runtime adapters**: Native shell and Docker runtime for building and running commands.
- **Audit logging**: JSONL audit events with rotation.

## Usage

```rust
use secure_shell::{
    SecurityPolicy,
    sandbox::{create_sandbox, Sandbox},
    runtime::{create_runtime, RuntimeAdapter},
    config::SecurityConfig,
};

// Policy from a single workspace directory (backward compatible)
let policy = SecurityPolicy::from_workspace_dir(std::path::PathBuf::from("/path/to/workspace"));

// Or with explicit allowed paths
let policy = SecurityPolicy {
    allowed_paths: vec![
        AllowedPath { path: "/workspace".into(), writable: true },
        AllowedPath { path: "/usr".into(), writable: false },
    ],
    ..Default::default()
};

let config = SecurityConfig::default();
let sandbox = create_sandbox(&config.sandbox, false);
let runtime = create_runtime(&config.runtime).unwrap();

// Build command and apply sandbox
let workspace_dir = policy.primary_workspace().unwrap_or(std::path::Path::new("/tmp"));
let mut cmd = runtime.build_shell_command("cargo build", workspace_dir).unwrap();
sandbox.wrap_command(&mut cmd).unwrap();
```

## Cargo features

- `sandbox-landlock`: Enable Landlock LSM backend (Linux only).
- `sandbox-bubblewrap`: Enable Bubblewrap backend.

## License

Apache-2.0. See LICENSE.
