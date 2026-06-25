//! Fuzz `SecureStore::from_bytes` — the binary parser for the encrypted
//! key-value store blob (header + HMAC-hashed key IDs + AES-GCM records).
//!
//! The parser handles two magic prefixes (`SVMSTORE03`, `SVMSTORE04`), a
//! 32-byte salt, a u32 record count, and variable-length ciphertext records.
//! All field-length fields are u32/u16 LE and any out-of-bounds value must
//! produce `Err`, never a panic or an unbounded allocation.

#![no_main]

use libfuzzer_sys::fuzz_target;
use secure_android_vm::SecureStore;

fuzz_target!(|data: &[u8]| {
    let _ = SecureStore::from_bytes(data);
});
