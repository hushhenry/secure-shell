# AGENTS.md — secure-shell

## Project Overview
Extract the `security` and `runtime` modules from zeroclaw (located at `/home/hush/.openclaw/workspace/zeroclaw/src/`) into an independent Rust library crate called `secure-shell`.

**Reference source code**: `/home/hush/.openclaw/workspace/zeroclaw/src/`
- Key source directories: `security/`, `runtime/`, `tools/shell.rs`, `tools/traits.rs`, `config/schema.rs`

## Task Checklist

### 1. Project Structure
Create a complete Rust library project:
```
secure-shell/
├── Cargo.toml
├── LICENSE            # Apache 2.0, author: hushhenry
├── README.md          # Project description, usage examples
├── .gitignore         # Standard Rust .gitignore
├── src/
│   ├── lib.rs         # Re-exports
│   ├── config.rs      # Configuration types (extracted from zeroclaw config/schema.rs)
│   ├── policy.rs      # SecurityPolicy (from zeroclaw security/policy.rs)
│   ├── audit.rs       # AuditLogger (from zeroclaw security/audit.rs)
│   ├── sandbox/
│   │   ├── mod.rs     # Sandbox trait + NoopSandbox + create_sandbox()
│   │   ├── detect.rs  # Auto-detection logic
│   │   ├── landlock.rs
│   │   ├── firejail.rs
│   │   ├── bubblewrap.rs
│   │   ├── docker.rs
│   │   └── seatbelt.rs  # NEW: macOS sandbox-exec (Seatbelt)
│   ├── runtime/
│   │   ├── mod.rs     # RuntimeAdapter trait
│   │   ├── native.rs
│   │   └── docker.rs
│   └── persistence.rs # NEW: Persistence capability trait + Docker implementation
```

### 2. Add macOS `sandbox-exec` (Seatbelt) Backend
Create `src/sandbox/seatbelt.rs`:
- Implement `Sandbox` trait for macOS `sandbox-exec`.
- Generate a `.sb` (Scheme) policy file dynamically based on `allowed_paths` and `forbidden_paths`.
- The policy should:
  - `(deny default)` — deny everything by default
  - `(allow process-fork)` and `(allow process-exec ...)` for allowed binary paths
  - `(allow file-read* (subpath ...))` for allowed read paths (e.g., `/usr/lib`, `/nix/store`)
  - `(allow file-write* (subpath ...))` for workspace/allowed write paths
  - `(allow file-read* file-write* (subpath "/tmp"))` for temp
  - Network control: configurable allow/deny
- `wrap_command` should rewrite the command as: `sandbox-exec -f /path/to/generated.sb <original_command>`
- Only compile on `#[cfg(target_os = "macos")]`
- Add `probe()` that checks if `sandbox-exec` binary exists (it's built into macOS)

### 3. Persistence Capability
**Problem**: Current sandboxes use `docker run --rm`, so installed packages are lost every time.

**Solution**: Design persistence as a **capability trait**:
```rust
/// Capability: persistent sandbox sessions
pub trait PersistentSandbox: Sandbox {
    /// Create or resume a named persistent session
    fn create_session(&self, session_id: &str) -> std::io::Result<()>;
    
    /// Execute a command inside an existing persistent session
    fn exec_in_session(&self, session_id: &str, cmd: &mut Command) -> std::io::Result<()>;
    
    /// Destroy a persistent session
    fn destroy_session(&self, session_id: &str) -> std::io::Result<()>;
    
    /// List active persistent sessions
    fn list_sessions(&self) -> std::io::Result<Vec<String>>;
    
    /// Check if a session exists
    fn session_exists(&self, session_id: &str) -> bool;
}
```

**Docker implementation**:
- `create_session`: `docker create --name {session_id} ...` (without `--rm`)
- `exec_in_session`: `docker start {session_id}` (if stopped) then `docker exec {session_id} ...`
- `destroy_session`: `docker rm -f {session_id}`
- `list_sessions`: `docker ps -a --filter label=secure-shell`
- Add a `--label secure-shell=true` to all created containers for easy filtering

**Other sandboxes**: Return `Err(Unsupported)` for now. Do NOT implement PersistentSandbox for them.

Update `create_sandbox()` to accept an optional `persistent: bool` parameter. When `persistent=true`, prefer backends that implement `PersistentSandbox`.

### 4. Redesign Path Access Control
**Current problem**: `workspace_dir` is a single directory; `workspace_only=true` blocks all absolute paths.

**New design**:
Replace `workspace_dir: PathBuf` and `workspace_only: bool` with:
```rust
pub struct SecurityPolicy {
    pub allowed_paths: Vec<AllowedPath>,  // NEW: replaces workspace_dir
    pub forbidden_paths: Vec<String>,
    // ... other fields remain
}

pub struct AllowedPath {
    pub path: PathBuf,
    pub writable: bool,  // read-only or read-write
}
```

**Path validation rules** (`is_path_allowed`):
1. Normalize and canonicalize the path.
2. Check if the path is under ANY `allowed_paths` entry → if yes, ALLOW (even if a parent is in `forbidden_paths`).
3. Check if the path is under ANY `forbidden_paths` entry → if yes, DENY.
4. If not matched by either list → DENY (default deny).
5. **Symlink check**: After canonicalization, re-verify that the resolved path is still within `allowed_paths`. This prevents symlink escapes.

**Priority rule**: `allowed_paths` takes precedence over `forbidden_paths`. 
Example: `allowed_paths=[/home/user/.openclaw/workspace]`, `forbidden_paths=[/home]` → access to `/home/user/.openclaw/workspace/foo.txt` is ALLOWED, but `/home/user/other/` is DENIED.

**Absolute paths**: Always allowed as long as they pass the above checks. Remove the old `workspace_only` absolute-path blocking logic.

**Keep backward compatibility**: Add a `from_workspace_dir(dir: PathBuf)` constructor that creates an `allowed_paths` with a single writable entry for the given dir.

### 5. Code Quality
- All public types must have doc comments.
- Include unit tests for all major functions (copy relevant tests from zeroclaw and adapt them).
- Use `#[cfg(test)]` modules.
- Ensure `cargo build` and `cargo test` pass.
- Use feature flags: `sandbox-landlock`, `sandbox-bubblewrap` (matching zeroclaw's approach).
- Minimize external dependencies. Required: `serde`, `serde_json`, `tokio`, `async-trait`, `anyhow`, `tracing`, `chrono`, `uuid`, `parking_lot`.
- For Landlock: use `landlock` crate behind feature flag.

### 6. Important Notes
- Do NOT copy zeroclaw code verbatim for non-security/runtime modules. Only extract what's needed.
- Strip all zeroclaw-specific imports (like `crate::config::*`). Re-define necessary config types in `src/config.rs`.
- The `SecurityPolicy::from_config()` method should accept the new config types defined in this crate.
- Make sure the crate compiles on both Linux and macOS (use `#[cfg]` appropriately).
- Run `cargo check` frequently to ensure compilation.
