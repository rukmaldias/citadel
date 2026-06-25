//! Fuzz `FirmwareLicense::from_bytes` — the binary parser for the decrypted
//! license payload (magic + fields). This is reached in production after
//! AES-GCM decryption; here we hand arbitrary bytes directly to the parser
//! so the fuzzer can explore all field-boundary and truncation paths without
//! needing valid crypto material.
//!
//! Goal: confirm no panic, use-after-free, integer overflow, or OOM occurs
//! on any input. Every error path must return `Err`, never panic.

#![no_main]

use libfuzzer_sys::fuzz_target;
use secure_android_vm::FirmwareLicense;

fuzz_target!(|data: &[u8]| {
    // The return value is intentionally discarded — we only care that parsing
    // does not panic. Errors (InvalidLicense, etc.) are expected and valid.
    let _ = FirmwareLicense::from_bytes(data);
});
