//! Auto-detection of available sandbox backends.

use std::sync::Arc;

use crate::config::{SandboxBackend, SecurityConfig};
use crate::sandbox::Sandbox;

use super::NoopSandbox;
#[cfg(all(feature = "sandbox-landlock", target_os = "linux"))]
use super::LandlockSandbox;
#[cfg(target_os = "linux")]
use super::FirejailSandbox;
#[cfg(feature = "sandbox-bubblewrap")]
use super::BubblewrapSandbox;
use super::DockerSandbox;
#[cfg(target_os = "macos")]
use super::SeatbeltSandbox;

/// Create a sandbox based on config and optional persistent preference.
pub(super) fn create_sandbox_impl(config: &SecurityConfig, persistent: bool) -> Arc<dyn Sandbox> {
    let backend = &config.sandbox.backend;

    if matches!(backend, SandboxBackend::None) || config.sandbox.enabled == Some(false) {
        return Arc::new(NoopSandbox);
    }

    match backend {
        SandboxBackend::Landlock => {
            #[cfg(all(feature = "sandbox-landlock", target_os = "linux"))]
            {
                if let Ok(sandbox) = LandlockSandbox::new() {
                    return Arc::new(sandbox);
                }
            }
            tracing::warn!(
                "Landlock requested but not available, falling back to application-layer"
            );
            Arc::new(NoopSandbox)
        }
        SandboxBackend::Firejail => {
            #[cfg(target_os = "linux")]
            {
                if let Ok(sandbox) = FirejailSandbox::new() {
                    return Arc::new(sandbox);
                }
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = config;
            }
            tracing::warn!(
                "Firejail requested but not available, falling back to application-layer"
            );
            Arc::new(NoopSandbox)
        }
        SandboxBackend::Bubblewrap => {
            #[cfg(feature = "sandbox-bubblewrap")]
            {
                if let Ok(sandbox) = BubblewrapSandbox::new() {
                    return Arc::new(sandbox);
                }
            }
            tracing::warn!(
                "Bubblewrap requested but not available, falling back to application-layer"
            );
            Arc::new(NoopSandbox)
        }
        SandboxBackend::Docker => {
            if let Ok(sandbox) = DockerSandbox::new() {
                return Arc::new(sandbox);
            }
            tracing::warn!("Docker requested but not available, falling back to application-layer");
            Arc::new(NoopSandbox)
        }
        #[cfg(target_os = "macos")]
        SandboxBackend::Seatbelt => {
            if let Ok(sandbox) = SeatbeltSandbox::new() {
                return Arc::new(sandbox);
            }
            tracing::warn!(
                "Seatbelt requested but not available, falling back to application-layer"
            );
            Arc::new(NoopSandbox)
        }
        SandboxBackend::Auto | SandboxBackend::None => detect_best_sandbox(persistent),
    }
}

fn detect_best_sandbox(persistent: bool) -> Arc<dyn Sandbox> {
    // When persistent=true, prefer Docker (implements PersistentSandbox)
    if persistent {
        if let Ok(sandbox) = DockerSandbox::probe() {
            tracing::info!("Docker sandbox enabled (persistent sessions supported)");
            return Arc::new(sandbox);
        }
    }

    #[cfg(target_os = "linux")]
    {
        #[cfg(feature = "sandbox-landlock")]
        {
            if let Ok(sandbox) = LandlockSandbox::probe() {
                tracing::info!("Landlock sandbox enabled (Linux kernel 5.13+)");
                return Arc::new(sandbox);
            }
        }

        if let Ok(sandbox) = FirejailSandbox::probe() {
            tracing::info!("Firejail sandbox enabled");
            return Arc::new(sandbox);
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Ok(sandbox) = SeatbeltSandbox::probe() {
            tracing::info!("Seatbelt (sandbox-exec) sandbox enabled");
            return Arc::new(sandbox);
        }
        #[cfg(feature = "sandbox-bubblewrap")]
        {
            if let Ok(sandbox) = BubblewrapSandbox::probe() {
                tracing::info!("Bubblewrap sandbox enabled");
                return Arc::new(sandbox);
            }
        }
    }

    if let Ok(sandbox) = DockerSandbox::probe() {
        tracing::info!("Docker sandbox enabled");
        return Arc::new(sandbox);
    }

    tracing::info!("No sandbox backend available, using application-layer security");
    Arc::new(NoopSandbox)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{SandboxConfig, SecurityConfig};

    #[test]
    fn detect_best_sandbox_returns_something() {
        let sandbox = detect_best_sandbox(false);
        assert!(sandbox.is_available());
    }

    #[test]
    fn explicit_none_returns_noop() {
        let config = SecurityConfig {
            sandbox: SandboxConfig {
                enabled: Some(false),
                backend: SandboxBackend::None,
                firejail_args: Vec::new(),
            },
            ..Default::default()
        };
        let sandbox = create_sandbox_impl(&config, false);
        assert_eq!(sandbox.name(), "none");
    }

    #[test]
    fn auto_mode_detects_something() {
        let config = SecurityConfig {
            sandbox: SandboxConfig {
                enabled: None,
                backend: SandboxBackend::Auto,
                firejail_args: Vec::new(),
            },
            ..Default::default()
        };
        let sandbox = create_sandbox_impl(&config, false);
        assert!(sandbox.is_available());
    }
}
