pub mod passphrase;
pub mod slot;
#[cfg(target_os = "linux")]
pub mod trustlocal;

#[cfg(target_os = "linux")]
pub mod tpm;

#[cfg(target_os = "macos")]
pub mod keychain;

#[cfg(target_os = "windows")]
pub mod dpapi;
