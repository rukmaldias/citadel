//! Self-integrity checks: SHA-256 (keyless, early) and HMAC-SHA-256 (key-bound, late).
//!
//! ## Two-layer model
//!
//! The .so contains two magic-prefixed 40-byte slots compiled into `.rodata`:
//!
//! ```text
//! SVM_HASH_SLOT  = b"SVMHASH\x00" + [32 bytes: SHA-256,   patched post-build]
//! SVM_HMAC_SLOT  = b"SVMHMAC\x00" + [32 bytes: HMAC-SHA-256, patched post-build]
//! ```
//!
//! ### SHA-256 slot — early, keyless
//!
//! Checked at startup before any Argon2id work. Catches casual patchers who
//! modify the binary without understanding the slot format. An informed attacker
//! who knows the magic can zero the slot, recompute SHA-256, and re-patch it —
//! the check is **not** cryptographically binding.
//!
//! ### HMAC-SHA-256 slot — late, key-bound to `firmware_secret`
//!
//! Checked inside `decrypt_program_and_customer_key`, **after** the license is
//! decrypted and `firmware_secret` is available. The HMAC key is derived from
//! `firmware_secret` (a 256-bit secret inside the encrypted license). An attacker
//! who patches the .so cannot forge this MAC without `firmware_secret`, which
//! requires decrypting the license, which requires the app's signing certificate.
//! This check **is** cryptographically binding to the distribution chain.
//!
//! ## Neutralization rule
//!
//! Both patch tools and both runtime checks zero **both** slots before computing
//! their respective digest. Each digest therefore covers the same "neutral" file
//! state, and the two checks are completely independent of each other.
//!
//! ## Post-build workflow
//!
//! After `cargo build --release --target aarch64-linux-android --features jni`:
//!
//! ```text
//! cargo run --bin patch_so -- \
//!     target/aarch64-linux-android/release/libsecure_android_vm.so \
//!     <firmware_secret_as_64_hex_chars>
//! ```
//!
//! `patch_so` zeros both slots, then computes SHA-256 and HMAC over the same
//! neutral RX segment in a single pass, writing both values back to the file.

/// 8-byte magic that identifies the SHA-256 hash slot inside the .so.
#[cfg(target_os = "android")]
const HASH_SLOT_MAGIC: &[u8; 8] = b"SVMHASH\x00";

/// 8-byte magic that identifies the HMAC-SHA-256 slot inside the .so.
#[cfg(target_os = "android")]
const HMAC_SLOT_MAGIC: &[u8; 8] = b"SVMHMAC\x00";

/// Byte length of each integrity-slot payload (SHA-256 or HMAC-SHA-256 output).
const SLOT_PAYLOAD_LEN: usize = 32;

/// Combined magic marker and 32-byte SHA-256 placeholder.
///
/// Bytes 0–7 are `SVMHASH\x00`. Bytes 8–39 hold the expected SHA-256 of the
/// .so with **both** integrity slots zeroed, filled in by `patch_so`.
///
/// `#[used]` prevents the linker from discarding this symbol. `strip = true`
/// removes the symbol name but not the `.rodata` bytes, so the magic scan
/// still locates the slot at runtime.
#[used]
static SVM_HASH_SLOT: [u8; 40] = [
    b'S', b'V', b'M', b'H', b'A', b'S', b'H', 0x00, // magic (8 bytes)
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,   // SHA-256 (32 bytes,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,   // patched post-build)
];

/// Combined magic marker and 32-byte HMAC-SHA-256 placeholder.
///
/// Bytes 0–7 are `SVMHMAC\x00`. Bytes 8–39 hold `HMAC-SHA-256(key, .so)` where
/// `key` is derived from the license's `firmware_secret`, filled in by
/// `patch_so`. An attacker who patches the .so cannot recompute this value
/// without `firmware_secret`.
#[used]
static SVM_HMAC_SLOT: [u8; 40] = [
    b'S', b'V', b'M', b'H', b'M', b'A', b'C', 0x00, // magic (8 bytes)
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,   // HMAC-SHA-256 (32 bytes,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,   // patched post-build)
];

/// Returns `true` if the running .so matches the embedded SHA-256.
///
/// This is the **early** check — called before any Argon2id work in
/// `start_with_verified_assets`. It catches casual binary patchers. For a
/// cryptographically binding check see [`verify_so_hmac`].
///
/// On non-Android targets always returns `true`. An all-zero hash slot (not
/// yet patched) returns `true` in dev builds and `false` when the
/// `enforce_patch` feature is enabled, ensuring release builds fail loudly
/// if `patch_so` was not run.
pub fn check_so_integrity() -> bool {
    #[cfg(target_os = "android")]
    {
        hash_check_impl().unwrap_or(false)
    }
    #[cfg(not(target_os = "android"))]
    {
        true
    }
}

/// Returns `true` if the running .so passes an HMAC-SHA-256 check keyed from
/// `firmware_secret`.
///
/// This is the **late**, cryptographically binding check — called after the
/// license has been decrypted. An attacker who patches the .so cannot forge the
/// HMAC without `firmware_secret`, which lives inside the AES-GCM–encrypted
/// license. The license is encrypted with a key derived from the app's signing
/// certificate, closing the forgery path.
///
/// On non-Android targets always returns `true`. An all-zero HMAC slot (not
/// yet patched) returns `true` in dev builds and `false` with `enforce_patch`.
pub(crate) fn verify_so_hmac(firmware_secret: &[u8; SLOT_PAYLOAD_LEN]) -> bool {
    #[cfg(target_os = "android")]
    {
        hmac_check_impl(firmware_secret).unwrap_or(false)
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = firmware_secret;
        true
    }
}

// ── Android-only implementation ───────────────────────────────────────────────

#[cfg(target_os = "android")]
fn hash_check_impl() -> Option<bool> {
    use sha2::{Digest, Sha256};

    let so_path = find_so_path()?;
    let mut full = std::fs::read(&so_path).ok()?;

    // Extract the expected SHA-256 from the full file and zero the slot.
    // Zeroing in `full` before the segment copy means the slot is also zero
    // inside the segment bytes extracted below.
    let expected = neutralize_slot(&mut full, HASH_SLOT_MAGIC)?;

    if expected == [0u8; SLOT_PAYLOAD_LEN] {
        return Some(!cfg!(feature = "enforce_patch"));
    }

    // Hash only the RX (read+execute) ELF segment — the code and read-only data.
    // This skips the RW data segment, which the dynamic linker modifies via
    // position-independent relocations after the file is loaded; those changes
    // are linker-legal and should not invalidate the integrity check.
    let (seg_off, seg_size) = rx_segment_range(&full)?;
    // HASH slot is already zeroed in `full`, so it is also zero in this copy.
    let mut seg = full.get(seg_off..seg_off + seg_size)?.to_vec();
    // Zero the HMAC slot as well so the digest covers the same neutral state
    // that patch_so computed over.
    let _ = neutralize_slot(&mut seg, HMAC_SLOT_MAGIC);

    use subtle::ConstantTimeEq;
    let actual: [u8; SLOT_PAYLOAD_LEN] = Sha256::digest(&seg).into();
    Some(bool::from(actual.ct_eq(&expected)))
}

#[cfg(target_os = "android")]
fn hmac_check_impl(firmware_secret: &[u8; SLOT_PAYLOAD_LEN]) -> Option<bool> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;

    let so_path = find_so_path()?;
    let full = std::fs::read(&so_path).ok()?;

    // Work exclusively on the RX segment (same region as patch_so).
    let (seg_off, seg_size) = rx_segment_range(&full)?;
    let mut seg = full.get(seg_off..seg_off + seg_size)?.to_vec();

    // Zero both slots in the segment copy (matches the neutral state that
    // patch_so computed the HMAC over).
    let _ = neutralize_slot(&mut seg, HASH_SLOT_MAGIC);
    let expected = neutralize_slot(&mut seg, HMAC_SLOT_MAGIC)?;

    if expected == [0u8; SLOT_PAYLOAD_LEN] {
        return Some(!cfg!(feature = "enforce_patch"));
    }

    // Derive a domain-specific sub-key: HMAC-SHA-256(key=firmware_secret,
    // msg="SVM-SO-INTEGRITY-V1"). This separates the MAC key from the raw
    // firmware_secret and ensures this key cannot be confused with the
    // firmware decryption key or the customer-data key.
    let mac_key: [u8; SLOT_PAYLOAD_LEN] = {
        let mut m = HmacSha256::new_from_slice(firmware_secret)
            .expect("HMAC accepts any key length");
        m.update(b"SVM-SO-INTEGRITY-V1");
        m.finalize().into_bytes().into()
    };

    let mut m = HmacSha256::new_from_slice(&mac_key)
        .expect("HMAC accepts any key length");
    m.update(&seg);
    let actual: [u8; SLOT_PAYLOAD_LEN] = m.finalize().into_bytes().into();

    use subtle::ConstantTimeEq;
    Some(bool::from(actual.ct_eq(&expected)))
}

/// Locates `magic` in `bytes`, reads the 32-byte payload that follows, zeros
/// those bytes in-place, and returns the original payload value.
///
/// Returns `None` if `magic` is not found or the slot would extend past EOF.
/// This allows callers to silently skip an absent slot (for backward
/// compatibility with .so files built before `SVM_HMAC_SLOT` was added).
#[cfg(target_os = "android")]
fn neutralize_slot(bytes: &mut Vec<u8>, magic: &[u8; 8]) -> Option<[u8; SLOT_PAYLOAD_LEN]> {
    let pos = find_subsequence(bytes, magic)?;
    let start = pos + magic.len();
    if start + SLOT_PAYLOAD_LEN > bytes.len() {
        return None;
    }
    let mut value = [0u8; SLOT_PAYLOAD_LEN];
    value.copy_from_slice(&bytes[start..start + SLOT_PAYLOAD_LEN]);
    bytes[start..start + SLOT_PAYLOAD_LEN].fill(0);
    Some(value)
}

/// Cache for the .so filesystem path, derived from `/proc/self/maps` on first
/// call. Subsequent calls (e.g. the HMAC check after the SHA-256 check) reuse
/// the cached value and do not re-read the maps file.
#[cfg(target_os = "android")]
static SO_PATH: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();

/// Reads `/proc/self/maps` on the first invocation and returns the filesystem
/// path of our .so as a `'static` str. Returns `None` if the maps file cannot
/// be read or our library is not listed.
#[cfg(target_os = "android")]
fn find_so_path() -> Option<&'static str> {
    SO_PATH.get_or_init(|| {
        use obfstr::obfstr;
        let so_name = obfstr!("libsecure_android_vm.so").to_owned();
        let maps = std::fs::read_to_string("/proc/self/maps").ok()?;
        for line in maps.lines() {
            if line.contains(so_name.as_str()) {
                if let Some(path) = line.split_whitespace().last() {
                    if path.starts_with('/') {
                        return Some(path.to_owned());
                    }
                }
            }
        }
        None
    }).as_deref()
}

/// Returns the byte offset of the first occurrence of `needle` in `haystack`.
#[cfg(target_os = "android")]
fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

// ── ELF segment parsing ───────────────────────────────────────────────────────

/// Returns the `(file_offset, file_size)` of the first `PT_LOAD` segment that
/// is readable and executable but **not** writable (the RX segment containing
/// `.text` and `.rodata`).
///
/// Both ELF32 (ARMv7) and ELF64 (AArch64, x86_64) are handled. Returns `None`
/// if the file is not ELF, the class byte is unexpected, or no matching segment
/// is found.
///
/// Program headers are never stripped by `strip = true` (the OS loader requires
/// them), so this function works on stripped release `.so` files.
#[cfg(target_os = "android")]
fn rx_segment_range(bytes: &[u8]) -> Option<(usize, usize)> {
    if bytes.get(..4)? != b"\x7fELF" {
        return None;
    }
    match bytes.get(4).copied()? {
        1 => rx_elf32(bytes),
        2 => rx_elf64(bytes),
        _ => None,
    }
}

#[cfg(target_os = "android")]
fn rx_elf32(b: &[u8]) -> Option<(usize, usize)> {
    // ELF32 header: e_phoff at 28 (4 bytes), e_phentsize at 42 (2 bytes),
    // e_phnum at 44 (2 bytes).
    let phoff = u32::from_le_bytes(b.get(28..32)?.try_into().ok()?) as usize;
    let phentsize = u16::from_le_bytes(b.get(42..44)?.try_into().ok()?) as usize;
    let phnum = u16::from_le_bytes(b.get(44..46)?.try_into().ok()?) as usize;
    for i in 0..phnum {
        let off = phoff + i * phentsize;
        let ph = b.get(off..off + 32)?;
        // ELF32 PH: p_type@0, p_offset@4, p_filesz@16, p_flags@24
        let p_type   = u32::from_le_bytes(ph[0..4].try_into().ok()?);
        let p_offset = u32::from_le_bytes(ph[4..8].try_into().ok()?) as usize;
        let p_filesz = u32::from_le_bytes(ph[16..20].try_into().ok()?) as usize;
        let p_flags  = u32::from_le_bytes(ph[24..28].try_into().ok()?);
        // PT_LOAD=1, PF_R=4, PF_W=2, PF_X=1 — want RX, not W
        if p_type == 1 && (p_flags & 0x1) != 0 && (p_flags & 0x2) == 0 {
            return Some((p_offset, p_filesz));
        }
    }
    None
}

#[cfg(target_os = "android")]
fn rx_elf64(b: &[u8]) -> Option<(usize, usize)> {
    // ELF64 header: e_phoff at 32 (8 bytes), e_phentsize at 54 (2 bytes),
    // e_phnum at 56 (2 bytes).
    let phoff = u64::from_le_bytes(b.get(32..40)?.try_into().ok()?) as usize;
    let phentsize = u16::from_le_bytes(b.get(54..56)?.try_into().ok()?) as usize;
    let phnum = u16::from_le_bytes(b.get(56..58)?.try_into().ok()?) as usize;
    for i in 0..phnum {
        let off = phoff + i * phentsize;
        let ph = b.get(off..off + 56)?;
        // ELF64 PH: p_type@0, p_flags@4, p_offset@8, p_filesz@32
        let p_type   = u32::from_le_bytes(ph[0..4].try_into().ok()?);
        let p_flags  = u32::from_le_bytes(ph[4..8].try_into().ok()?);
        let p_offset = u64::from_le_bytes(ph[8..16].try_into().ok()?) as usize;
        let p_filesz = u64::from_le_bytes(ph[32..40].try_into().ok()?) as usize;
        // PT_LOAD=1, PF_R=4, PF_W=2, PF_X=1 — want RX, not W
        if p_type == 1 && (p_flags & 0x1) != 0 && (p_flags & 0x2) == 0 {
            return Some((p_offset, p_filesz));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// On non-Android targets the stub implementations must always return `true`
    /// so unit tests and CI builds pass without a real .so on disk.
    #[test]
    fn non_android_integrity_stubs_pass() {
        assert!(check_so_integrity(), "check_so_integrity() stub must return true");
        assert!(verify_so_hmac(&[0u8; 32]), "verify_so_hmac() stub must return true");
    }
}
