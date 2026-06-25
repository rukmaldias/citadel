//! Secure VM runtime for Android.
//!
//! This crate provides a small virtual machine, encrypted asset management,
//! and Android JNI entry points. Its purpose is to let an Android app load and
//! run *protected firmware* — bytecode that is encrypted and cryptographically
//! bound to the app's identity so it cannot be extracted, reversed, or run on a
//! different app or device configuration.
//!
//! # Three-layer security model
//!
//! Assets arrive on the device as three binary files in the APK `assets/`
//! directory. They form a chain of trust:
//!
//! ```text
//! codesign.bin  ─────► verify Ed25519 signature over (identity + hashes)
//!                               │
//!                               ▼
//! license.bin   ─────► decrypt with app-identity-derived key
//!                       parse: identity constraints + firmware hash + secrets
//!                               │
//!                               ▼
//! firmware.bin  ─────► decrypt with firmware key (from license secret)
//!                       verify SHA-256 matches hash in license
//!                       parse as VM bytecode
//! ```
//!
//! 1. **`codesign.bin`** contains an Ed25519 signature created by the firmware
//!    vendor. It authenticates the other two blobs and the expected app
//!    identity (package name, signing certificate, installer). Any modification
//!    to `license.bin` or `firmware.bin` after signing is immediately detected.
//!
//! 2. **`license.bin`** is encrypted with a key derived from the app's
//!    signing-certificate hash and package name. Only the exact app the license
//!    was issued for can decrypt it. Inside are the identity constraints,
//!    the expected SHA-256 of the firmware, and two 256-bit secrets used to
//!    derive the firmware decryption key and the customer-data encryption key.
//!
//! 3. **`firmware.bin`** is encrypted with a key that mixes the `firmware_secret`
//!    from the license with the app identity and the firmware's own hash. An
//!    attacker who extracts `firmware.bin` from the APK cannot decrypt it
//!    without also extracting and decrypting the license — which requires
//!    the correct signing certificate.
//!
//! # Building for Android
//!
//! Before building, paste your 32-byte Ed25519 public key into `src/keys.rs`
//! (replace the placeholder zero bytes). The key is compiled into the `.so` via
//! `obfstr::obfbytes!` — it is XOR-encrypted at compile time so no raw key
//! constant appears in the binary.
//!
//! Add the Android targets and build with the `jni` feature and `--release`:
//!
//! ```text
//! rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
//! cargo build --release --target aarch64-linux-android --features jni
//! ```
//!
//! The release profile applies `lto = true`, `strip = true`, `codegen-units = 1`,
//! and `panic = "abort"` — see `[profile.release]` in `Cargo.toml`.
//!
//! Copy the resulting `libsecure_android_vm.so` into your Android project's
//! `jniLibs/<ABI>/` directory. The provided `SecureVm.kt` loads it automatically.
//!
//! # Main use cases
//!
//! ## 1. Secure firmware execution
//!
//! ```kotlin
//! SecureVm().use { vm ->
//!     val code = vm.startFromAssets(context)
//!     if (code != SecureVm.START_OK) { /* handle error */ return }
//!     val result = vm.run()
//! }
//! ```
//!
//! `startFromAssets` reads the three asset files, runs the full verification
//! chain, and — if everything checks out — leaves the VM in the `Running` state
//! with the firmware loaded and the customer-data key available.
//!
//! ## 2. Customer data encryption
//!
//! After a successful `startFromAssets`, the VM holds a session-scoped AES key
//! derived from the license. Use it to encrypt app data:
//!
//! ```kotlin
//! val ciphertext = vm.encryptData(myPlaintextBytes)
//! // store ciphertext, never the key
//! val plaintext = vm.decryptData(ciphertext)
//! ```
//!
//! The key is cleared from memory when `stop()` or `close()` is called. It is
//! re-derived automatically on the next successful `startFromAssets`.
//!
//! # Startup flow
//!
//! See [`SecureVm::start_with_verified_assets`] for the full step-by-step
//! verification pipeline and [`FirmwareBundle::decrypt_program_and_customer_key`]
//! for the crypto chain.
//!
//! # Post-quantum readiness
//!
//! The codesign mechanism uses **Ed25519** (Curve 25519 / Schnorr), which is
//! vulnerable to a sufficiently powerful quantum computer via Shor's algorithm.
//! The symmetric primitives (AES-256-GCM, HMAC-SHA-256, Argon2id) are
//! considered quantum-safe at their current key sizes.
//!
//! A migration path exists when the ecosystem is ready:
//! - Replace Ed25519 with **ML-DSA** (FIPS 204, formerly Dilithium) for the
//!   codesign signature. The `ed25519-dalek` call sites are isolated to
//!   `firmware.rs::sign_code_assets` and `verify_code_signature`, and
//!   `keys.rs::codesign_public_key` — three touch points.
//! - No change is needed to the symmetric layer.
//!
//! No action is required now. Note this section when evaluating the codebase
//! for long-lived deployments (10+ year key lifetimes).

mod bytecode;
mod environment;
mod error;
mod firmware;
mod integrity;
mod memguard;
mod wbc;
#[cfg(feature = "jni")]
mod apk;
#[cfg(feature = "jni")]
mod keys;
#[cfg(all(target_os = "android", feature = "jni"))]
mod keystore;
mod storage;
mod vm;

pub use bytecode::{Instruction, OpcodeTable, Program};
pub use environment::{is_debugger_attached, is_emulator, is_rooted};
pub use integrity::check_so_integrity;
pub use error::{Result, VmError};
pub use firmware::{
    compress_customer_data_tables,
    decrypt_customer_data, decrypt_firmware, decrypt_license, encrypt_customer_data,
    encrypt_firmware, encrypt_license_for_signing_certificate, sha256, sign_code_assets,
    verify_code_signature, CodeIdentity, CustomerKeyInit, FirmwareBundle, FirmwareLicense,
    InstallerPolicy,
};
pub use storage::{EncryptedRecord, SecureStore};
pub use vm::{RunReport, SecureVm, StartCode, VmState};
pub use wbc::WbcAes256Tables;

#[cfg(feature = "jni")]
mod jni_api;
