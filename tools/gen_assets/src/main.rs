//! Asset generator for Secure Android VM.
//!
//! Reads `licensepack.json` from the current directory and produces three
//! binary asset files: `license.bin`, `firmware.bin`, `codesign.bin`.
//!
//! ## licensepack.json format
//!
//! ```json
//! {
//!   "key":              "<64 hex chars = 32 bytes>",
//!   "value":            "<64 hex chars = 32 bytes>",
//!   "cert":             "<hex bytes>",
//!   "id":               "com.example.app",
//!   "installer_policy": "required:com.android.vending",
//!   "valid_until":      1893456000,
//!   "firmware_flags":   0
//! }
//! ```
//!
//! ### `installer_policy` values
//!
//! | Value | Meaning |
//! |-------|---------|
//! `"required:com.android.vending"` | Only Play Store installs accepted (production) |
//! `"any"` | Any installer including sideload (development only) |
//!
//! ### `valid_until`
//!
//! Unix timestamp (seconds since epoch). `0` means the license never expires,
//! which is appropriate only for permanent entitlements. For time-limited
//! deployments set an explicit expiry — e.g. `date -d "2030-01-01" +%s`.
//!
//! ## Required environment variables
//!
//! | Variable               | Value                                            |
//! |------------------------|--------------------------------------------------|
//! | `CODESIGN_PRIVATE_KEY` | 64 hex chars — Ed25519 signing key (keep secret) |
//!
//! ## Usage
//!
//! ```bash
//! export CODESIGN_PRIVATE_KEY="<64-char hex>"
//! cargo run --manifest-path tools/gen_assets/Cargo.toml
//! # Writes: license.bin  firmware.bin  codesign.bin
//! # Prints to stderr: FIRMWARE_SECRET=<hex>  (needed by patch_so)
//! ```

use std::fs;

use ed25519_dalek::{Signer, SigningKey};
use rand::RngCore;
use secure_android_vm::{
    encrypt_firmware, encrypt_license_for_signing_certificate, sign_code_assets,
    CodeIdentity, FirmwareLicense, InstallerPolicy, Program,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};

// ── licensepack.json schema ───────────────────────────────────────────────────

#[derive(Deserialize)]
struct LicensePack {
    /// 32-byte firmware secret as 64 hex chars.
    /// Used by Argon2id to derive the AES-256 key that encrypts `firmware.bin`.
    /// Keep this value secret — store it in a secrets manager alongside the
    /// Ed25519 private key.
    key: String,

    /// 32-byte customer secret as 64 hex chars.
    /// Used by Argon2id to derive the session customer-data AES key.
    value: String,

    /// Identity anchor bytes as hex.
    /// SHA-256'd and used as the Argon2id salt. In a standard Android build
    /// this is the DER-encoded APK signing certificate.
    cert: String,

    /// Package / customer identifier string used as part of the Argon2id
    /// password. A license for `id="com.a"` cannot be decrypted by `id="com.b"`.
    id: String,

    /// Installer restriction for this license.
    ///
    /// Accepted values:
    /// - `"required:<installer_package>"` — only that installer is accepted at
    ///   runtime, e.g. `"required:com.android.vending"` for Google Play.
    /// - `"any"` — any installer including sideload (dev / test only).
    ///
    /// **Do not use `"any"` in production.** A cloned APK distributed outside
    /// your channel will still pass the installer check.
    installer_policy: String,

    /// License expiry as a Unix timestamp (seconds since epoch).
    ///
    /// `0` means the license never expires. For time-limited deployments,
    /// set an explicit value: `date -d "2030-01-01" +%s` → `1893456000`.
    ///
    /// A non-zero value that is in the past at VM startup will cause
    /// `start_with_verified_assets` to return `StartCode::LicenseFailed`.
    valid_until: u64,

    /// VM behaviour flags.
    ///
    /// | Bit | Meaning |
    /// |-----|---------|
    /// |  0  | VM debug mode: per-instruction trace to stderr/logcat |
    ///
    /// Set to `0` in production licenses.
    firmware_flags: u32,
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn hex_decode(label: &str, s: &str) -> Vec<u8> {
    hex::decode(s)
        .unwrap_or_else(|e| panic!("licensepack.json: field `{label}` is not valid hex: {e}"))
}

fn hex32(label: &str, s: &str) -> [u8; 32] {
    let v = hex_decode(label, s);
    v.try_into().unwrap_or_else(|v: Vec<u8>| {
        panic!(
            "licensepack.json: field `{label}` must be exactly 32 bytes (got {} bytes)",
            v.len()
        )
    })
}

fn parse_installer_policy(raw: &str) -> InstallerPolicy {
    let lower = raw.trim().to_lowercase();
    if lower == "any" {
        eprintln!(
            "WARNING: installer_policy is \"any\" — the license will accept sideloaded APKs.\n\
             Use \"required:com.android.vending\" for production builds.\n\
             KDF note: Any-policy licenses use an empty installer string in the\n\
             Argon2id KDF. A runtime installer value other than null/\"\" (e.g.\n\
             from the Google Play Store) will produce a key mismatch and fail\n\
             to decrypt. Any policy is intended for sideload / adb-install only."
        );
        InstallerPolicy::Any
    } else if let Some(pkg) = lower.strip_prefix("required:") {
        if pkg.is_empty() {
            panic!(
                "licensepack.json: installer_policy \"required:\" must include the installer \
                 package name, e.g. \"required:com.android.vending\""
            );
        }
        InstallerPolicy::Required(raw.trim()["required:".len()..].to_owned())
    } else {
        panic!(
            "licensepack.json: unrecognised installer_policy {:?}. \
             Use \"required:<package>\" or \"any\".",
            raw
        )
    }
}

fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

// ── Main ──────────────────────────────────────────────────────────────────────

fn main() {
    // ── 1. Load licensepack.json ──────────────────────────────────────────────
    let json = fs::read_to_string("licensepack.json")
        .expect("licensepack.json not found in current directory");
    let pack: LicensePack =
        serde_json::from_str(&json).expect("licensepack.json: invalid JSON or missing fields");

    let firmware_secret: [u8; 32] = hex32("key", &pack.key);
    let customer_secret: [u8; 32] = hex32("value", &pack.value);
    let cert_bytes: Vec<u8> = hex_decode("cert", &pack.cert);

    if cert_bytes.is_empty() {
        panic!("licensepack.json: `cert` must not be empty");
    }
    if pack.id.is_empty() {
        panic!("licensepack.json: `id` must not be empty");
    }

    let installer_policy = parse_installer_policy(&pack.installer_policy);

    if pack.valid_until == 0 {
        eprintln!(
            "WARNING: valid_until is 0 — this license never expires.\n\
             Set an explicit Unix timestamp for time-limited deployments."
        );
    }

    // ── 2. Load Ed25519 codesign key ──────────────────────────────────────────
    let private_key_hex = std::env::var("CODESIGN_PRIVATE_KEY").expect(
        "CODESIGN_PRIVATE_KEY environment variable not set.\n\
         Generate a key pair with `cargo run --bin keygen` and set the private key here.",
    );
    let key_bytes: [u8; 32] = hex_decode("CODESIGN_PRIVATE_KEY env var", &private_key_hex)
        .try_into()
        .expect("CODESIGN_PRIVATE_KEY must be exactly 32 bytes (64 hex chars)");
    let signing_key = SigningKey::from_bytes(&key_bytes);

    // ── 3. Build CodeIdentity from cert bytes ─────────────────────────────────
    // SHA-256(cert_bytes) becomes the Argon2id salt — same cryptographic role
    // as SHA-256(X.509 signing certificate) in a standard Android build.
    let installer_pkg = match &installer_policy {
        InstallerPolicy::Required(pkg) => Some(pkg.clone()),
        InstallerPolicy::Any => None,
    };
    let identity = CodeIdentity::from_certificate(&pack.id, &cert_bytes, installer_pkg)
        .expect("failed to build CodeIdentity");

    // ── 4. Generate opcode seed (fresh random per generation) ─────────────────
    // A non-zero opcode seed scrambles the bytecode so it is unreadable without
    // the matching license. Store it alongside firmware_secret if you ever need
    // to regenerate assets for the same firmware without changing the bytecode.
    let mut opcode_seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut opcode_seed);

    // ── 5. Build firmware ─────────────────────────────────────────────────────
    // Replace this stub with your real business-logic bytecode.
    let program = Program::new(vec![
        secure_android_vm::Instruction::PushI64(pack.firmware_flags as i64),
        secure_android_vm::Instruction::Halt,
    ])
    .expect("failed to build program");

    // Encode with the per-license opcode table.
    use secure_android_vm::OpcodeTable;
    let table = OpcodeTable::from_seed(&opcode_seed);
    let firmware_bytes = program.to_bytes_with_table(&table);
    let firmware_hash = sha256(&firmware_bytes);

    // ── 6. Assemble and encrypt the license ───────────────────────────────────
    let license = FirmwareLicense::new(
        pack.id.clone(),
        identity.signing_cert_sha256,
        installer_policy,
        firmware_hash,
        firmware_secret,
        customer_secret,
        opcode_seed,
        pack.valid_until,
        pack.firmware_flags,
    );

    let enc_firmware = encrypt_firmware(&firmware_bytes, &license.firmware_key().unwrap())
        .expect("firmware encryption failed");

    let license_bin = encrypt_license_for_signing_certificate(&license, &cert_bytes)
        .expect("license encryption failed");

    // ── 7. Sign ───────────────────────────────────────────────────────────────
    let codesign_bin = sign_code_assets(
        &identity,
        &license_bin,
        &enc_firmware,
        |payload| Ok(signing_key.sign(payload).to_bytes()),
    )
    .expect("code signing failed");

    // ── 8. Write output files ─────────────────────────────────────────────────
    fs::write("license.bin", &license_bin).expect("failed to write license.bin");
    fs::write("firmware.bin", &enc_firmware).expect("failed to write firmware.bin");
    fs::write("codesign.bin", &codesign_bin).expect("failed to write codesign.bin");

    // Print secrets to stderr — keeps them out of stdout CI logs.
    // FIRMWARE_SECRET is needed by patch_so (Step 5d in the README).
    eprintln!("FIRMWARE_SECRET={}", hex::encode(firmware_secret));
    eprintln!("OPCODE_SEED={}", hex::encode(opcode_seed));
    eprintln!(
        "firmware_flags={} ({})",
        pack.firmware_flags,
        if pack.firmware_flags & 1 != 0 { "DEBUG MODE ENABLED" } else { "release mode" }
    );
    if pack.valid_until > 0 {
        eprintln!("valid_until={} (Unix timestamp)", pack.valid_until);
    }

    println!("Assets written:");
    println!("  license.bin  ({} bytes)", license_bin.len());
    println!("  firmware.bin ({} bytes)", enc_firmware.len());
    println!("  codesign.bin ({} bytes)", codesign_bin.len());
    println!("Copy them to android-app/app/src/main/assets/");
}
