//! Level 1: Passphrase authentication.

use anyhow::Result;

/// Passphrase strength level.
#[derive(Debug, PartialEq)]
pub enum PassphraseStrength {
    Weak,
    Fair,
    Strong,
}

impl std::fmt::Display for PassphraseStrength {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PassphraseStrength::Weak => write!(f, "Weak"),
            PassphraseStrength::Fair => write!(f, "Fair"),
            PassphraseStrength::Strong => write!(f, "Strong"),
        }
    }
}

/// Evaluate passphrase strength based on length and character variety.
pub fn evaluate_strength(passphrase: &[u8]) -> PassphraseStrength {
    let s = String::from_utf8_lossy(passphrase);
    let len = s.len();

    let has_lower = s.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = s.chars().any(|c| c.is_ascii_uppercase());
    let has_digit = s.chars().any(|c| c.is_ascii_digit());
    let has_special = s.chars().any(|c| !c.is_alphanumeric());

    let variety = [has_lower, has_upper, has_digit, has_special]
        .iter()
        .filter(|&&v| v)
        .count();

    if (len >= 16 && variety >= 3) || (len >= 12 && variety >= 2) {
        PassphraseStrength::Strong
    } else if len >= 12 || (len >= 8 && variety >= 2) {
        PassphraseStrength::Fair
    } else {
        PassphraseStrength::Weak
    }
}

/// Validate passphrase and show strength indicator.
/// Returns Ok(()) if passphrase meets minimum requirements.
pub fn validate_passphrase(passphrase: &[u8]) -> Result<()> {
    if passphrase.is_empty() {
        anyhow::bail!("passphrase cannot be empty");
    }

    let len = String::from_utf8_lossy(passphrase).len();

    if len < 8 {
        anyhow::bail!("passphrase must be at least 8 characters (got {})", len);
    }

    let strength = evaluate_strength(passphrase);
    eprintln!("  Passphrase strength: {}", strength);

    if len < 12 {
        eprintln!("  ⚠ Consider using a passphrase of 12+ characters for better security");
    }

    Ok(())
}

/// Prompt the user for a passphrase (with confirmation for init).
pub fn prompt_passphrase(confirm: bool) -> Result<Vec<u8>> {
    #[cfg(unix)]
    {
        if !nix::unistd::isatty(0).unwrap_or(false) {
            anyhow::bail!("terminal required for passphrase input (use --stdin for non-interactive mode)");
        }
    }
    let pass = rpassword::prompt_password("Enter vault passphrase: ")
        .map_err(|e| anyhow::anyhow!("failed to read passphrase: {}", e))?;

    if pass.is_empty() {
        anyhow::bail!("passphrase cannot be empty");
    }

    if confirm {
        // Validate strength on init
        validate_passphrase(pass.as_bytes())?;

        let pass2 = rpassword::prompt_password("Confirm vault passphrase: ")
            .map_err(|e| anyhow::anyhow!("failed to read passphrase: {}", e))?;

        if pass != pass2 {
            anyhow::bail!("passphrases do not match");
        }
    }

    Ok(pass.into_bytes())
}

/// Prompt for an export passphrase (separate from vault passphrase).
#[allow(dead_code)]
pub fn prompt_export_passphrase(confirm: bool) -> Result<Vec<u8>> {
    #[cfg(unix)]
    {
        if !nix::unistd::isatty(0).unwrap_or(false) {
            anyhow::bail!("terminal required for passphrase input (use --stdin for non-interactive mode)");
        }
    }
    let pass = rpassword::prompt_password("Enter export passphrase: ")
        .map_err(|e| anyhow::anyhow!("failed to read export passphrase: {}", e))?;

    if pass.is_empty() {
        anyhow::bail!("export passphrase cannot be empty");
    }

    if confirm {
        validate_passphrase(pass.as_bytes())?;

        let pass2 = rpassword::prompt_password("Confirm export passphrase: ")
            .map_err(|e| anyhow::anyhow!("failed to read export passphrase: {}", e))?;

        if pass != pass2 {
            anyhow::bail!("export passphrases do not match");
        }
    }

    Ok(pass.into_bytes())
}
