//! Memory hardening utilities for the vault agent.

use anyhow::Result;

/// Apply memory hardening to the current process.
/// - Disable core dumps via prctl(PR_SET_DUMPABLE, 0)
/// - Set umask to 077
pub fn harden_process() -> Result<()> {
    // Disable core dumps
    #[cfg(target_os = "linux")]
    {
        use nix::sys::prctl;
        prctl::set_dumpable(false)
            .map_err(|e| anyhow::anyhow!("failed to set PR_SET_DUMPABLE: {}", e))?;
    }

    // Set restrictive umask
    nix::sys::stat::umask(nix::sys::stat::Mode::from_bits_truncate(0o077));

    Ok(())
}
