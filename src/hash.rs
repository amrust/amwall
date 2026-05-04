// amwall — file hashing for the use_hashes parity feature.
// Copyright (C) 2026  amwall contributors. Licensed GPL-3.0-or-later.
//
// SHA-256 hex digest of an exe on disk. Wraps `BCryptHash` (one-
// shot CNG hash) using the `BCRYPT_SHA256_ALG_HANDLE` pseudo-
// handle — no `BCryptOpenAlgorithmProvider` round-trip needed
// since SHA-256 is one of the built-in algorithm handles Windows
// 10+ exposes directly.
//
// Mirrors upstream simplewall's `_r_crypt_getfilehash` shape
// (helper.c:1759) — same algorithm (BCRYPT_SHA256_ALGORITHM),
// same lowercase-hex output format that goes into profile.xml's
// `<item hash="..."/>` attribute.
//
// Returns `None` for paths the file system can't open (typical
// reasons: missing file, no read permission, NT-form path the
// user-mode shell can't resolve). Callers treat `None` as
// "skip this app, don't try to drift-check".

#![cfg(windows)]

use std::path::Path;

#[cfg(windows)]
use windows::Win32::Security::Cryptography::{BCRYPT_SHA256_ALG_HANDLE, BCryptHash};

const SHA256_LEN: usize = 32;

/// Compute the SHA-256 of the file at `path` and return the
/// lowercase-hex form (64 chars). Returns `None` if the file
/// can't be opened or read.
///
/// Reads the whole file into memory then hands it to `BCryptHash`
/// in one shot. For typical exe sizes (a few MB) that's well
/// within budget; for very large files (an installer staging an
/// uncompressed video, etc.) a streaming approach with
/// `BCryptHashData` would be better, but no app amwall would
/// per-app-permit is in that range.
pub fn sha256_file(path: &Path) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    sha256_bytes(&bytes)
}

/// Hash a slice directly. Pulled out so unit tests can pin the
/// output against a known input without touching the disk.
pub fn sha256_bytes(input: &[u8]) -> Option<String> {
    let mut digest = [0u8; SHA256_LEN];
    let status =
        unsafe { BCryptHash(BCRYPT_SHA256_ALG_HANDLE, None, input, &mut digest) };
    // NTSTATUS 0 == STATUS_SUCCESS; non-zero == failure.
    if status.0 != 0 {
        return None;
    }
    Some(hex_lower(&digest))
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Empty input has a stable, well-known SHA-256.
    #[test]
    fn sha256_empty_string() {
        let h = sha256_bytes(b"").expect("empty hash");
        assert_eq!(
            h,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    /// "abc" is the canonical SHA-256 test vector from FIPS 180-2.
    #[test]
    fn sha256_abc_test_vector() {
        let h = sha256_bytes(b"abc").expect("abc hash");
        assert_eq!(
            h,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn sha256_file_returns_none_for_missing() {
        let p = std::path::PathBuf::from(
            r"Z:\amwall_definitely_does_not_exist_5d9aa.bin",
        );
        assert!(sha256_file(&p).is_none());
    }
}
