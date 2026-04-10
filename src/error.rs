use thiserror::Error;

#[derive(Error, Debug)]
pub enum VaultError {
    #[error("vault is not initialized")]
    NotInitialized,
    #[error("vault is already initialized")]
    AlreadyInitialized,
    #[error("secret not found: {0}")]
    SecretNotFound(String),
    #[error("secret name too long (max {max} bytes)")]
    NameTooLong { max: usize },
    #[error("secret value too large (max {max} bytes)")]
    ValueTooLarge { max: usize },
    #[error("invalid secret name: {0}")]
    InvalidName(String),
    #[error("authentication failed")]
    AuthFailed,
    #[error("no suitable auth slot found; is the vault initialized?")]
    NoAuthSlot,
    #[error("incorrect passphrase")]
    BadPassphrase,
    #[error("agent not running")]
    AgentNotRunning,
    #[error("agent vault ID mismatch")]
    AgentVaultMismatch,
    #[error("import error: {0}")]
    Import(String),
    #[error("export error: {0}")]
    Export(String),
    #[error("cannot remove last auth slot")]
    LastSlot,
    #[error("platform not supported: {0}")]
    PlatformUnsupported(String),
    #[error("trust-local unavailable: {0}")]
    TrustLocalUnavailable(String),
    #[error("validation error: {0}")]
    Validation(String),
    #[error("{0}")]
    Other(String),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("encryption failed")]
    EncryptionFailed,
    #[error("decryption failed")]
    DecryptionFailed,
    #[error("key derivation failed: {0}")]
    KeyDerivation(String),
    #[error("invalid key length")]
    InvalidKeyLength,
}

#[derive(Error, Debug)]
pub enum StoreError {
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("schema error: {0}")]
    Schema(String),
}

/// Unified result type for the vault library.
pub type Result<T> = std::result::Result<T, VaultError>;
