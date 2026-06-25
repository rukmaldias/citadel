//! Post-build tool: patches both integrity slots in a compiled .so in one pass.
//!
//! Run this after every release build before packaging the .so into the APK:
//!
//! ```text
//! cargo run --bin patch_so -- \
//!     target/aarch64-linux-android/release/libsecure_android_vm.so \
//!     <firmware_secret_as_64_hex_chars>
//! ```
//!
//! The `firmware_secret` is the 32-byte random value stored in the
//! `FirmwareLicense`. Print it with `hex::encode(license.firmware_secret())`
//! from your license-creation tool and pass it here as 64 hex characters.
//!
//! Keep `firmware_secret` out of CI logs. Pass it via an environment variable
//! or a secrets manager, not on a shell command line that ends up in history.
//!
//! ## What this tool does
//!
//! 1. Reads the .so file.
//! 2. Zeroes both the `SVMHASH\x00` slot (32 bytes) and the `SVMHMAC\x00`
//!    slot (32 bytes).
//! 3. Locates the ELF RX (read+execute) segment via the program header table.
//! 4. Computes SHA-256 over the neutralised RX segment → writes to `SVMHASH\x00`.
//! 5. Derives a MAC key: `HMAC-SHA-256(key=firmware_secret, "SVM-SO-INTEGRITY-V1")`.
//! 6. Computes HMAC-SHA-256(mac_key, neutralised RX segment) → writes to `SVMHMAC\x00`.
//! 7. Writes the patched file.
//!
//! Both digests are computed over the **same** neutral segment bytes (both slots
//! zeroed), so they are independent of each other and can be verified in any
//! order at runtime.
//!
//! Hashing only the RX segment (code + rodata) avoids false failures from
//! linker-legal changes to the RW data segment (GOT/PLT relocations applied
//! by the dynamic linker after load).

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::{env, fs, process};

type HmacSha256 = Hmac<Sha256>;

const HASH_MAGIC: &[u8; 8] = b"SVMHASH\x00";
const HMAC_MAGIC: &[u8; 8] = b"SVMHMAC\x00";
const SLOT_LEN: usize = 32;

fn main() {
    let mut args = env::args().skip(1);
    let path = args.next().unwrap_or_else(|| {
        eprintln!("usage: patch_so <path/to/libsecure_android_vm.so> <firmware_secret_hex>");
        process::exit(1);
    });
    let secret_hex = args.next().unwrap_or_else(|| {
        eprintln!("error: firmware_secret (64 hex chars) is required");
        process::exit(1);
    });
    let firmware_secret: [u8; 32] = decode_hex_secret(&secret_hex);

    let mut bytes = fs::read(&path).unwrap_or_else(|e| {
        eprintln!("error reading {path}: {e}");
        process::exit(1);
    });

    // Zero both slots so each digest covers the same neutral state.
    let hash_slot = find_and_zero(&mut bytes, HASH_MAGIC, &path);
    let hmac_slot = find_and_zero(&mut bytes, HMAC_MAGIC, &path);

    // Locate the ELF RX segment; both slots are already zeroed in `bytes` so
    // the segment slice inherits the neutral state automatically.
    let (seg_off, seg_size) = rx_segment_range(&bytes).unwrap_or_else(|| {
        eprintln!("error: could not locate ELF RX segment in {path}");
        eprintln!("       Is this a valid ELF .so file?");
        process::exit(1);
    });

    // Derive domain-specific HMAC key.
    let mac_key: [u8; 32] = {
        let mut m = HmacSha256::new_from_slice(&firmware_secret)
            .expect("HMAC accepts any key length");
        m.update(b"SVM-SO-INTEGRITY-V1");
        m.finalize().into_bytes().into()
    };

    // Compute both digests over the same neutral segment (borrow ends before
    // we mutate `bytes` to write the results).
    let (hash, mac) = {
        let seg = &bytes[seg_off..seg_off + seg_size];
        let hash: [u8; 32] = Sha256::digest(seg).into();
        let mut m = HmacSha256::new_from_slice(&mac_key)
            .expect("HMAC accepts any key length");
        m.update(seg);
        let mac: [u8; 32] = m.finalize().into_bytes().into();
        (hash, mac)
    };

    // Patch both slots in the full file.
    let p = hash_slot + HASH_MAGIC.len();
    bytes[p..p + SLOT_LEN].copy_from_slice(&hash);
    let p = hmac_slot + HMAC_MAGIC.len();
    bytes[p..p + SLOT_LEN].copy_from_slice(&mac);

    fs::write(&path, &bytes).unwrap_or_else(|e| {
        eprintln!("error writing {path}: {e}");
        process::exit(1);
    });

    println!("patched: {path}");
    println!("  sha256: {}", hex_str(&hash));
    println!("  hmac:   {}", hex_str(&mac));
    println!("  rx segment: offset={seg_off:#x} size={seg_size:#x}");
}

/// Finds `magic`, zeros the 32-byte payload, and returns the magic's byte
/// offset. Exits the process if the magic is not found or the slot is truncated.
fn find_and_zero(bytes: &mut [u8], magic: &[u8; 8], path: &str) -> usize {
    let pos = bytes
        .windows(magic.len())
        .position(|w| w == magic)
        .unwrap_or_else(|| {
            eprintln!(
                "error: magic {:?} not found in {path}",
                String::from_utf8_lossy(magic)
            );
            eprintln!("       Was the binary compiled from this source tree?");
            process::exit(1);
        });
    let slot = pos + magic.len();
    if slot + SLOT_LEN > bytes.len() {
        eprintln!("error: slot extends past end of file");
        process::exit(1);
    }
    bytes[slot..slot + SLOT_LEN].fill(0);
    pos
}

fn decode_hex_secret(s: &str) -> [u8; 32] {
    if s.len() != 64 {
        eprintln!(
            "error: firmware_secret must be exactly 64 hex chars (got {})",
            s.len()
        );
        process::exit(1);
    }
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let pair = std::str::from_utf8(chunk).unwrap_or_else(|_| {
            eprintln!("error: invalid UTF-8 in hex string");
            process::exit(1);
        });
        out[i] = u8::from_str_radix(pair, 16).unwrap_or_else(|_| {
            eprintln!("error: invalid hex byte '{pair}'");
            process::exit(1);
        });
    }
    out
}

fn hex_str(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

// ── ELF segment parsing ───────────────────────────────────────────────────────

fn rx_segment_range(b: &[u8]) -> Option<(usize, usize)> {
    if b.get(..4)? != b"\x7fELF" {
        return None;
    }
    match b.get(4).copied()? {
        1 => rx_elf32(b),
        2 => rx_elf64(b),
        _ => None,
    }
}

fn rx_elf32(b: &[u8]) -> Option<(usize, usize)> {
    let phoff = u32::from_le_bytes(b.get(28..32)?.try_into().ok()?) as usize;
    let phentsize = u16::from_le_bytes(b.get(42..44)?.try_into().ok()?) as usize;
    let phnum = u16::from_le_bytes(b.get(44..46)?.try_into().ok()?) as usize;
    for i in 0..phnum {
        let off = phoff + i * phentsize;
        let ph = b.get(off..off + 32)?;
        let p_type   = u32::from_le_bytes(ph[0..4].try_into().ok()?);
        let p_offset = u32::from_le_bytes(ph[4..8].try_into().ok()?) as usize;
        let p_filesz = u32::from_le_bytes(ph[16..20].try_into().ok()?) as usize;
        let p_flags  = u32::from_le_bytes(ph[24..28].try_into().ok()?);
        if p_type == 1 && (p_flags & 0x1) != 0 && (p_flags & 0x2) == 0 {
            return Some((p_offset, p_filesz));
        }
    }
    None
}

fn rx_elf64(b: &[u8]) -> Option<(usize, usize)> {
    let phoff = u64::from_le_bytes(b.get(32..40)?.try_into().ok()?) as usize;
    let phentsize = u16::from_le_bytes(b.get(54..56)?.try_into().ok()?) as usize;
    let phnum = u16::from_le_bytes(b.get(56..58)?.try_into().ok()?) as usize;
    for i in 0..phnum {
        let off = phoff + i * phentsize;
        let ph = b.get(off..off + 56)?;
        let p_type   = u32::from_le_bytes(ph[0..4].try_into().ok()?);
        let p_flags  = u32::from_le_bytes(ph[4..8].try_into().ok()?);
        let p_offset = u64::from_le_bytes(ph[8..16].try_into().ok()?) as usize;
        let p_filesz = u64::from_le_bytes(ph[32..40].try_into().ok()?) as usize;
        if p_type == 1 && (p_flags & 0x1) != 0 && (p_flags & 0x2) == 0 {
            return Some((p_offset, p_filesz));
        }
    }
    None
}
