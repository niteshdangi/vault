//! Windows DPAPI auth backend.
//!
//! Uses `CryptProtectData` / `CryptUnprotectData` to encrypt the VKEK
//! tied to the current Windows user account.  The protected blob is stored
//! in the auth_slots table and can only be decrypted by the same user on
//! the same machine.

#![cfg(target_os = "windows")]

use anyhow::{Context, Result};
use zeroize::Zeroizing;

use crate::crypto::keys::Vkek;
use crate::store::sqlite;

fn dpapi_protect(plaintext: &[u8]) -> Result<Vec<u8>> {
    use std::ptr;
    use windows::Win32::Security::Cryptography::{CryptProtectData, CRYPT_INTEGER_BLOB};

    let mut input_blob = CRYPT_INTEGER_BLOB {
        cbData: plaintext.len() as u32,
        pbData: plaintext.as_ptr() as *mut u8,
    };
    let mut output_blob = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: ptr::null_mut(),
    };

    unsafe {
        CryptProtectData(&mut input_blob, None, None, None, None, 0, &mut output_blob)
            .context("CryptProtectData failed")?;

        let protected =
            std::slice::from_raw_parts(output_blob.pbData, output_blob.cbData as usize).to_vec();
        // HLOCAL implements Drop in windows 0.58+, auto-freeing the buffer
        drop(windows::Win32::Foundation::HLOCAL(output_blob.pbData as _));
        Ok(protected)
    }
}

fn dpapi_unprotect(protected: &[u8]) -> Result<Vec<u8>> {
    use std::ptr;
    use windows::Win32::Security::Cryptography::{CryptUnprotectData, CRYPT_INTEGER_BLOB};

    let mut input_blob = CRYPT_INTEGER_BLOB {
        cbData: protected.len() as u32,
        pbData: protected.as_ptr() as *mut u8,
    };
    let mut output_blob = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: ptr::null_mut(),
    };

    unsafe {
        CryptUnprotectData(&mut input_blob, None, None, None, None, 0, &mut output_blob)
            .context("CryptUnprotectData failed")?;

        let plaintext =
            std::slice::from_raw_parts(output_blob.pbData, output_blob.cbData as usize).to_vec();
        // HLOCAL implements Drop in windows 0.58+, auto-freeing the buffer
        drop(windows::Win32::Foundation::HLOCAL(output_blob.pbData as _));
        Ok(plaintext)
    }
}

pub fn create_dpapi_slot(conn: &rusqlite::Connection, vkek: &Vkek) -> Result<i64> {
    let protected = dpapi_protect(vkek.as_bytes()).context("failed to protect VKEK with DPAPI")?;
    let slot_id = sqlite::insert_auth_slot(
        conn,
        sqlite::SlotKind::Dpapi,
        &protected,
        None,
        Some(r#"{"method":"windows-dpapi"}"#),
    )?;
    Ok(slot_id)
}

pub fn unwrap_dpapi_slot(slot: &sqlite::AuthSlotRow) -> Result<Vkek> {
    let plaintext = Zeroizing::new(
        dpapi_unprotect(&slot.wrapped_vkek).context("failed to unprotect VKEK with DPAPI")?,
    );

    if plaintext.len() != 32 {
        anyhow::bail!(
            "DPAPI-decrypted VKEK has invalid length ({}, expected 32)",
            plaintext.len()
        );
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(plaintext.as_slice());
    Ok(Vkek::from_bytes(key))
}
