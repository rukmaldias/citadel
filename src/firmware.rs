//! Firmware asset management: encryption, decryption, and code signing.
//!
//! ## Three-asset startup model
//!
//! When an Android app loads protected firmware it reads three binary assets
//! from its APK `assets/` directory:
//!
//! ```text
//! license.bin    — the license, encrypted to the app's signing certificate
//! firmware.bin   — the VM bytecode, encrypted with a key from the license
//! codesign.bin   — an Ed25519 signature over the other two blobs + the app
//!                  identity
//! ```
//!
//! They form a chain of trust:
//!
//! 1. `codesign.bin` is verified first (using the vendor's Ed25519 public key
//!    that the app ships at compile time). This confirms that both blobs were
//!    created by the vendor and have not been modified in transit or in the
//!    APK.
//! 2. `license.bin` is decrypted using a key derived from the app's package
//!    name and signing-certificate hash. Only the exact app the license was
//!    issued for can decrypt it.
//! 3. The license contains the expected SHA-256 hash of `firmware.bin` and the
//!    secrets needed to derive the firmware decryption key. After decrypting
//!    `firmware.bin`, the actual hash is verified against the expected hash.
//!    This binds a specific firmware version to this license.
//! 4. The decrypted firmware bytes are parsed as VM bytecode.
//!
//! No single asset is useful without the others, and none can be replaced
//! individually without breaking the signature or hash check.

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use flate2::{read::ZlibDecoder, write::ZlibEncoder, Compression};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::{bytecode::OpcodeTable, wbc::WbcAes256Tables, Program, Result, VmError};

// Format version tags ("magic bytes") embedded at the start of every binary
// blob produced by this module. Each asset type has its own distinct magic so
// that the parser rejects cross-type confusion instantly — you cannot feed a
// firmware blob where a license blob is expected and have it parse silently.
// The numeric suffix is the format version, allowing future incompatible changes
// to be detected cleanly.
const PACKAGE_MAGIC: &[u8; 8] = b"SVMENC01"; // Generic encrypted package (license + firmware)
const LICENSE_MAGIC: &[u8; 8] = b"SVMLIC04"; // Decrypted license payload (v4: adds firmware_flags)
const CODESIGN_MAGIC: &[u8; 8] = b"SVMSIG01"; // Code-signature blob
const CUSTOMER_DATA_MAGIC: &[u8; 8] = b"SVMDAT01"; // Customer-data encrypted package
const PROGRAM_MAGIC: &[u8; 8] = b"SVMPRG01"; // Internal session-encrypted program storage
const WBC_TABLES_MAGIC: &[u8; 8] = b"SVMWBC00"; // White-box table block appended to license payload

// Upper bound on the compressed WBC table block accepted in a license payload.
// Uncompressed tables are ~217 KB; zlib typically reduces this to 70–90 KB.
// 300 KB gives ample headroom while preventing a malformed length field from
// triggering a gigabyte-scale allocation before any error is returned.
const WBC_TABLES_MAX_COMPRESSED_LEN: usize = 300_000;

/// Result of the license-verification chain describing how to store the
/// customer-data key in `CustomerKeyStorage`.
///
/// `decrypt_program_and_customer_key` tries the Android Keystore first (when
/// available). If hardware-backed storage is unavailable it returns white-box
/// AES-256 tables that embed the key without storing it as a raw byte array.
pub enum CustomerKeyInit {
    /// Key was placed in Android Keystore (StrongBox or TEE). Only the
    /// alias string is returned; the key bytes never leave secure hardware.
    #[cfg(all(target_os = "android", feature = "jni"))]
    Hardware(String),
    /// White-box AES-256 tables embedding the customer-data key. No raw key
    /// bytes appear in the returned value.
    WhiteBox(WbcAes256Tables),
}

const NONCE_LEN: usize = 12;              // 96-bit AES-GCM nonce
const AES_KEY_LEN: usize = 32;            // 256-bit AES key
const SHA256_LEN: usize = 32;             // 256-bit SHA-256 digest
const ED25519_PUBLIC_KEY_LEN: usize = 32; // Ed25519 public key (compressed curve point)
const ED25519_SIGNATURE_LEN: usize = 64;  // Ed25519 signature (r || s, each 32 bytes)

/// Whether the license enforces a specific installer or allows any source.
///
/// Using a plain `Option<String>` was considered but rejected because `None`
/// is ambiguous — it could mean "intentionally allow all installers" or
/// "someone forgot to set an installer". An explicit enum forces every license
/// author to make a deliberate choice and makes the intent visible in code.
///
/// In production, always use `Required(installer_package_name)` to bind the
/// license to the Google Play Store (or your internal distribution channel).
/// `Any` is appropriate only for development or testing where sideloading is
/// required; using it in production means a cloned APK distributed outside
/// your channel could still pass the installer check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InstallerPolicy {
    /// Only this installer package name is accepted at runtime.
    ///
    /// For Google Play Store apps, use `"com.android.vending"`.
    Required(String),
    /// Any installer (including sideload via `adb install`) is accepted.
    ///
    /// Use with caution — this disables one layer of distribution-channel
    /// binding.
    Any,
}

/// Describes the Android app identity that a license is valid for.
///
/// On Android, an "app identity" has three components that together uniquely
/// identify a specific, authorised build of an app:
///
/// - **Package name** (`com.example.myapp`): the app's unique identifier on
///   the device. A malicious app with the same package name as yours cannot be
///   installed alongside yours.
/// - **Signing certificate hash**: the SHA-256 hash of the DER-encoded X.509
///   certificate used to sign the APK. Even if an attacker repackages your APK
///   with the same package name, they cannot sign it with your private key, so
///   the cert hash will differ. We store the hash rather than the full
///   certificate bytes because a 32-byte hash is easier to embed in a license
///   and is equally unique (SHA-256 is collision-resistant for this use case).
/// - **Installer package** (optional): which app store or distribution channel
///   installed this APK. Restricting to a specific installer channel (e.g.
///   `com.android.vending`) means a copy distributed outside that channel is
///   rejected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CodeIdentity {
    /// The Android package name of the application (e.g. `"com.example.myapp"`).
    pub package_id: String,
    /// SHA-256 hash of the DER-encoded signing certificate bytes.
    pub signing_cert_sha256: [u8; SHA256_LEN],
    /// The package name of the installer (e.g. `"com.android.vending"`) or
    /// `None` if the installer is not known or not restricted.
    pub installer_package: Option<String>,
}

impl CodeIdentity {
    /// Builds a `CodeIdentity` from the raw DER-encoded signing certificate
    /// bytes.
    ///
    /// DER (Distinguished Encoding Rules) is the binary format that Android
    /// uses for APK signing certificates. At runtime, the native `apk` module
    /// reads these bytes directly from `META-INF/*.RSA` inside the APK ZIP,
    /// bypassing the `PackageManager` API entirely so no Java hook point exists.
    ///
    /// The certificate bytes are hashed (SHA-256) and stored as `signing_cert_sha256`
    /// rather than keeping the full cert. This is intentional: the 32-byte hash
    /// is much smaller and still cryptographically unique. An attacker cannot
    /// produce a different certificate with the same SHA-256 hash.
    ///
    /// # Errors
    ///
    /// Returns `InvalidInput` if `signing_certificate` is empty (reading the
    /// APK entry succeeded but produced no bytes, which would produce a hash of
    /// empty data and fail all license checks).
    pub fn from_certificate(
        package_id: impl Into<String>,
        signing_certificate: &[u8],
        installer_package: Option<String>,
    ) -> Result<Self> {
        if signing_certificate.is_empty() {
            return Err(VmError::InvalidInput(
                "signing certificate bytes cannot be empty".to_string(),
            ));
        }

        Ok(Self {
            package_id: package_id.into(),
            signing_cert_sha256: sha256(signing_certificate),
            installer_package,
        })
    }
}

/// The decrypted license payload.
///
/// A license is created at build time by the firmware vendor, encrypted into
/// `license.bin`, and distributed with the APK. At runtime the VM decrypts it
/// using the app identity. The license contains:
///
/// - **Identity constraints** (`package_id`, `signing_cert_sha256`,
///   `installer_policy`): what app this license was issued for.
/// - **Firmware binding** (`firmware_sha256`): the expected SHA-256 hash of
///   the firmware blob. If the firmware is updated without also updating the
///   license (re-issuing with the new hash), the hash check will fail. This
///   prevents an old license from being used to unlock newer firmware or vice
///   versa — every firmware version requires a matching license.
/// - **Key material** (`firmware_secret`, `customer_secret`): high-entropy
///   random values (256 bits each) that are mixed into the Argon2id KDF to
///   produce the AES keys. The firmware key and customer-data key are derived
///   independently so that compromising one does not compromise the other.
///   Even if an attacker extracts `firmware.bin` from the APK, they cannot
///   decrypt it without a valid license because the AES key requires the
///   `firmware_secret` that is inside the license.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FirmwareLicense {
    /// The package name of the app this license was issued for.
    package_id: String,
    /// SHA-256 hash of the signing certificate expected at runtime.
    signing_cert_sha256: [u8; SHA256_LEN],
    /// Installer restriction for this license.
    installer_policy: InstallerPolicy,
    /// Expected SHA-256 hash of the encrypted firmware blob.
    /// The VM verifies the decrypted firmware against this hash after
    /// decryption to confirm the firmware has not been swapped.
    firmware_sha256: [u8; SHA256_LEN],
    /// 256-bit high-entropy secret used to derive the firmware decryption key.
    /// Combined with public context in Argon2id — see `firmware_key()`.
    firmware_secret: [u8; AES_KEY_LEN],
    /// 256-bit high-entropy secret used to derive the customer-data key.
    /// Kept separate from `firmware_secret` so the two keys are independent.
    customer_secret: [u8; AES_KEY_LEN],
    /// 32-byte seed that deterministically generates the per-license opcode
    /// permutation table (see `OpcodeTable::from_seed`). A seed of all zeros
    /// means identity (no remapping). Any other value produces a unique
    /// shuffled table — bytecode encoded with this license's table cannot be
    /// parsed by a VM loaded with a different license.
    opcode_seed: [u8; AES_KEY_LEN],
    /// Unix timestamp (seconds since epoch) after which this license is
    /// considered expired. A value of `0` means the license never expires.
    /// Checked at runtime in `validate_identity` against the device clock.
    valid_until: u64,
    /// Behaviour flags set at license-generation time.
    ///
    /// Bit 0 (`0x01`) — **debug mode**: when set, the VM's `execute()` loop
    /// emits a verbose per-instruction trace to stderr / logcat so vendor
    /// engineers can observe stack state, register writes, and control-flow
    /// changes at runtime. Clear this bit in production licenses.
    firmware_flags: u32,
    /// Zlib-compressed serialisation of `WbcAes256Tables` generated from the
    /// `customer_data_key` at license-build time. When present, the runtime
    /// deserialises and uses these tables directly so no raw key value is
    /// derived or stored. When absent (old license format), the runtime falls
    /// back to deriving the key from `customer_secret` and generating tables
    /// on the fly.
    wbc_tables_compressed: Option<Vec<u8>>,
}

impl FirmwareLicense {
    /// Creates a new license object before it is serialized and encrypted.
    ///
    /// This is a build-tool constructor. At runtime the license is always
    /// loaded through `from_bytes()` after decrypting `license.bin`.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        package_id: impl Into<String>,
        signing_cert_sha256: [u8; SHA256_LEN],
        installer_policy: InstallerPolicy,
        firmware_sha256: [u8; SHA256_LEN],
        firmware_secret: [u8; AES_KEY_LEN],
        customer_secret: [u8; AES_KEY_LEN],
        opcode_seed: [u8; AES_KEY_LEN],
        valid_until: u64,
        firmware_flags: u32,
    ) -> Self {
        Self {
            package_id: package_id.into(),
            signing_cert_sha256,
            installer_policy,
            firmware_sha256,
            firmware_secret,
            customer_secret,
            opcode_seed,
            valid_until,
            firmware_flags,
            wbc_tables_compressed: None,
        }
    }

    /// Attaches pre-generated WBC tables (zlib-compressed) to this license.
    ///
    /// Call this in the license-build tool after generating and compressing
    /// the tables with [`compress_customer_data_tables`]. The tables are
    /// appended to the serialised license payload before encryption.
    pub fn with_wbc_tables(mut self, compressed: Vec<u8>) -> Self {
        self.wbc_tables_compressed = Some(compressed);
        self
    }

    /// Returns the customer-data `WbcAes256Tables` for this license.
    ///
    /// If the license already contains pre-generated compressed tables (new
    /// format), those are decompressed and returned. Otherwise the raw
    /// `customer_data_key` is derived from `customer_secret` via Argon2id and
    /// the tables are generated on the fly (old license format fallback).
    ///
    /// The raw key, if derived at all, exists only transiently on the stack
    /// inside this method and is zeroized before returning.
    ///
    /// # Errors
    ///
    /// Returns `Crypto` if decompression, deserialization, or Argon2id fails.
    pub fn customer_data_tables(&self) -> Result<WbcAes256Tables> {
        if let Some(compressed) = &self.wbc_tables_compressed {
            let raw = decompress_wbc_tables(compressed)?;
            return WbcAes256Tables::from_bytes(&raw).ok_or(VmError::Crypto);
        }
        // Old license: derive the raw key and generate tables on the fly.
        let mut key = derive_customer_data_key(
            &self.customer_secret,
            &self.package_id,
            &self.signing_cert_sha256,
        )?;
        let tables = WbcAes256Tables::generate(&key);
        key.zeroize();
        Ok(tables)
    }

    /// Returns the package id that is allowed to use this license.
    pub fn package_id(&self) -> &str {
        &self.package_id
    }

    /// Returns the expected signing certificate hash.
    pub fn signing_cert_sha256(&self) -> &[u8; SHA256_LEN] {
        &self.signing_cert_sha256
    }

    /// Returns the installer policy encoded in this license.
    pub fn installer_policy(&self) -> &InstallerPolicy {
        &self.installer_policy
    }

    /// Returns the firmware hash that the license expects.
    ///
    /// After decrypting `firmware.bin`, the VM computes SHA-256 over the
    /// decrypted bytes and compares them against this value. A mismatch means
    /// either the firmware was swapped, the license is for a different firmware
    /// version, or the download was corrupted.
    pub fn firmware_sha256(&self) -> &[u8; SHA256_LEN] {
        &self.firmware_sha256
    }

    /// Returns the opcode seed that drives this license's per-customer opcode
    /// remapping table.
    ///
    /// Pass this to `OpcodeTable::from_seed` to reconstruct the table used
    /// when the firmware was compiled. A seed of all zeros means the identity
    /// table (canonical opcode bytes, no remapping).
    pub fn opcode_seed(&self) -> &[u8; AES_KEY_LEN] {
        &self.opcode_seed
    }

    /// Returns the expiry timestamp for this license as Unix seconds.
    ///
    /// A value of `0` means the license never expires. Any other value is
    /// checked at runtime against the device clock in `validate_identity`.
    pub fn valid_until(&self) -> u64 {
        self.valid_until
    }

    /// Returns the behaviour flags embedded in this license.
    ///
    /// Bit 0 (`0x01`) enables VM debug mode. All other bits are reserved and
    /// must be zero in current implementations.
    pub fn firmware_flags(&self) -> u32 {
        self.firmware_flags
    }

    /// Zeroizes and removes the compressed WBC table bytes from this license.
    ///
    /// Call this immediately after the hardware Keystore path succeeds so the
    /// ~70–90 KB compressed blob is not held in memory for the rest of the
    /// `decrypt_program_and_customer_key` scope.
    #[cfg_attr(
        not(all(target_os = "android", feature = "jni")),
        allow(dead_code)
    )]
    pub(crate) fn clear_wbc_tables(&mut self) {
        if let Some(ref mut wbc) = self.wbc_tables_compressed {
            wbc.zeroize();
        }
        self.wbc_tables_compressed = None;
    }

    /// Verifies the .so self-integrity HMAC using this license's `firmware_secret`.
    ///
    /// Delegates to [`crate::integrity::verify_so_hmac`], passing the private
    /// `firmware_secret` field so callers outside this module never see it.
    /// Returns `true` on non-Android targets (dev / CI) and when the HMAC slot
    /// has not yet been patched (all-zero slot = dev bypass).
    pub(crate) fn check_so_hmac(&self) -> bool {
        crate::integrity::verify_so_hmac(&self.firmware_secret)
    }

    /// Derives the 256-bit AES key used to decrypt the protected firmware asset.
    ///
    /// The key is produced by Argon2id from the `firmware_secret` stored in
    /// this license. The `firmware_secret` is a 256-bit high-entropy value that
    /// only exists inside the (encrypted) license, so an attacker who can read
    /// `firmware.bin` from the APK still cannot decrypt it without the license.
    /// See `derive_firmware_key()` for the full KDF details.
    ///
    /// # Errors
    ///
    /// Returns `Crypto` if Argon2id parameter construction fails (should not
    /// happen with the hardcoded parameters).
    pub fn firmware_key(&self) -> Result<[u8; AES_KEY_LEN]> {
        derive_firmware_key(
            &self.firmware_secret,
            &self.package_id,
            &self.signing_cert_sha256,
            &self.firmware_sha256,
        )
    }

    /// Derives the 256-bit AES key used to encrypt and decrypt app customer data.
    ///
    /// The key is produced by Argon2id from the `customer_secret` stored in
    /// this license. It is entirely independent of the firmware key so that a
    /// compromise of one does not affect the other. The key is derived fresh
    /// every time this method is called — it is never stored in the license or
    /// on disk.
    ///
    /// # Errors
    ///
    /// Returns `Crypto` if Argon2id parameter construction fails.
    // The call site is inside `#[cfg(all(target_os = "android", feature = "jni"))]`
    // so the dead_code lint fires on non-Android builds; that is expected.
    #[allow(dead_code)]
    pub(crate) fn customer_data_key(&self) -> Result<[u8; AES_KEY_LEN]> {
        derive_customer_data_key(
            &self.customer_secret,
            &self.package_id,
            &self.signing_cert_sha256,
        )
    }

    /// Serializes the license into a compact binary format for storage in
    /// `license.bin` (after encryption).
    ///
    /// Binary layout:
    /// ```text
    /// [LICENSE_MAGIC: 8]
    /// [package_id: u16-length-prefixed UTF-8]
    /// [signing_cert_sha256: 32]
    /// [installer: presence-flag (1) + optional u16-prefixed UTF-8]
    /// [firmware_sha256: 32]
    /// [firmware_secret: 32]
    /// [customer_secret: 32]
    /// [opcode_seed: 32]
    /// [valid_until: 8 (u64 LE, 0 = never expires)]
    /// [firmware_flags: 4 (u32 LE)]
    /// ```
    ///
    /// # Errors
    ///
    /// Returns `InvalidInput` if any string field is longer than 65535 bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(LICENSE_MAGIC);
        write_string(&mut bytes, &self.package_id)?;
        bytes.extend_from_slice(&self.signing_cert_sha256);
        let installer_name = match &self.installer_policy {
            InstallerPolicy::Required(name) => Some(name.as_str()),
            InstallerPolicy::Any => None,
        };
        write_optional_string(&mut bytes, installer_name)?;
        bytes.extend_from_slice(&self.firmware_sha256);
        bytes.extend_from_slice(&self.firmware_secret);
        bytes.extend_from_slice(&self.customer_secret);
        bytes.extend_from_slice(&self.opcode_seed);
        bytes.extend_from_slice(&self.valid_until.to_le_bytes());
        bytes.extend_from_slice(&self.firmware_flags.to_le_bytes());
        // Optional WBC table block: magic (8) + compressed length (4 LE) + data.
        if let Some(wbc) = &self.wbc_tables_compressed {
            bytes.extend_from_slice(WBC_TABLES_MAGIC);
            let len = u32::try_from(wbc.len())
                .map_err(|_| VmError::InvalidInput("WBC tables too large".to_string()))?;
            bytes.extend_from_slice(&len.to_le_bytes());
            bytes.extend_from_slice(wbc);
        }
        Ok(bytes)
    }

    /// Parses a decrypted license payload back into a `FirmwareLicense`.
    ///
    /// Called after the encrypted `license.bin` blob has been decrypted
    /// with the app-identity-derived key. The `LICENSE_MAGIC` at the start
    /// prevents a firmware blob or customer-data blob from being accidentally
    /// (or maliciously) parsed as a license.
    ///
    /// # Errors
    ///
    /// Returns `InvalidLicense` if the magic bytes are wrong, any field is
    /// truncated, there are trailing bytes, or a string field is not valid
    /// UTF-8.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut offset = 0;
        read_magic(bytes, &mut offset, LICENSE_MAGIC, "license")?;
        let package_id = read_string(bytes, &mut offset, "package id")?;
        let signing_cert_sha256 = read_array::<SHA256_LEN>(bytes, &mut offset, "cert hash")?;
        let installer_policy = match read_optional_string(bytes, &mut offset, "installer")? {
            Some(name) => InstallerPolicy::Required(name),
            None => InstallerPolicy::Any,
        };
        let firmware_sha256 = read_array::<SHA256_LEN>(bytes, &mut offset, "firmware hash")?;
        let firmware_secret = read_array::<AES_KEY_LEN>(bytes, &mut offset, "firmware secret")?;
        let customer_secret = read_array::<AES_KEY_LEN>(bytes, &mut offset, "customer secret")?;
        let opcode_seed     = read_array::<AES_KEY_LEN>(bytes, &mut offset, "opcode seed")?;
        let valid_until     = u64::from_le_bytes(read_array::<8>(bytes, &mut offset, "valid_until")?);
        let firmware_flags  = u32::from_le_bytes(read_array::<4>(bytes, &mut offset, "firmware_flags")?);

        // Optional WBC table block appended after the core fields (new format).
        let wbc_tables_compressed = if offset < bytes.len() {
            if offset + 8 > bytes.len() {
                return Err(VmError::InvalidLicense("truncated WBC header".to_string()));
            }
            if &bytes[offset..offset + 8] != WBC_TABLES_MAGIC {
                return Err(VmError::InvalidLicense("bad WBC magic".to_string()));
            }
            offset += 8;
            if offset + 4 > bytes.len() {
                return Err(VmError::InvalidLicense("truncated WBC length".to_string()));
            }
            let len = u32::from_le_bytes(
                bytes[offset..offset + 4].try_into().map_err(|_| {
                    VmError::InvalidLicense("bad WBC length encoding".to_string())
                })?,
            ) as usize;
            offset += 4;
            if len > WBC_TABLES_MAX_COMPRESSED_LEN {
                return Err(VmError::InvalidLicense(format!(
                    "WBC tables too large: {len} bytes (max {WBC_TABLES_MAX_COMPRESSED_LEN})"
                )));
            }
            if offset + len > bytes.len() {
                return Err(VmError::InvalidLicense("truncated WBC data".to_string()));
            }
            let compressed = bytes[offset..offset + len].to_vec();
            offset += len;
            Some(compressed)
        } else {
            None
        };

        if offset != bytes.len() {
            return Err(VmError::InvalidLicense(
                "trailing license bytes".to_string(),
            ));
        }

        Ok(Self {
            package_id,
            signing_cert_sha256,
            installer_policy,
            firmware_sha256,
            firmware_secret,
            customer_secret,
            opcode_seed,
            valid_until,
            firmware_flags,
            wbc_tables_compressed,
        })
    }

    /// Verifies that the runtime app identity matches what this license was
    /// issued for.
    ///
    /// This is the core access-control check — it prevents a valid license
    /// from being reused by a different app or a repackaged APK:
    ///
    /// - **Package name mismatch**: another app on the device cannot load
    ///   firmware intended for your app. Even if it has the same package name,
    ///   Android's package manager would have blocked installation.
    /// - **Certificate mismatch**: a repackaged APK signed with a different
    ///   key cannot pass this check. An attacker who decompiles and modifies
    ///   your APK must re-sign it, which changes the cert hash.
    /// - **Installer mismatch** (when `Required`): a clone distributed through
    ///   a sideload or a third-party store cannot pass if only the expected
    ///   store is allowed. This defends against redistribution of the APK
    ///   through unofficial channels.
    ///
    /// # Errors
    ///
    /// Returns `InvalidLicense("verification failed")` for any failing check.
    /// The message is intentionally opaque — it does not reveal which field
    /// mismatched or whether the license has expired, so that an attacker
    /// cannot learn which constraint to bypass next.
    ///
    /// Note: expiry is checked against the device clock. An attacker with root
    /// can roll the clock back to bypass expiry; for a stronger guarantee,
    /// combine this with server-side license issuance that refuses to re-issue
    /// expired licenses.
    pub fn validate_identity(&self, identity: &CodeIdentity) -> Result<()> {
        if self.package_id != identity.package_id {
            return Err(VmError::InvalidLicense("verification failed".to_string()));
        }
        // Constant-time comparison for the cert hash to prevent timing oracles
        // that could reveal how many bytes match a guessed certificate hash.
        if !bool::from(self.signing_cert_sha256.ct_eq(&identity.signing_cert_sha256)) {
            return Err(VmError::InvalidLicense("verification failed".to_string()));
        }
        if let InstallerPolicy::Required(expected) = &self.installer_policy {
            if identity.installer_package.as_deref() != Some(expected.as_str()) {
                return Err(VmError::InvalidLicense("verification failed".to_string()));
            }
        }
        if self.valid_until != 0 {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            if now > self.valid_until {
                return Err(VmError::InvalidLicense("verification failed".to_string()));
            }
        }

        Ok(())
    }
}

/// Clears the license secrets from memory when the `FirmwareLicense` is dropped.
///
/// When a `FirmwareLicense` goes out of scope, Rust calls `drop()`. By default
/// this would free the memory but leave the secret bytes in the allocator's
/// free pool — a memory-scanning tool (or a debugger that dumps heap memory)
/// could read them. `zeroize()` overwrites the bytes with zeros before freeing,
/// reducing the window during which secrets sit in RAM to the period between
/// the license being created and the object being dropped. It does not make
/// extraction impossible (a privileged attacker can snapshot RAM continuously)
/// but it raises the cost and reduces the chance of accidental key leakage
/// through memory dumps, core files, or swap.
impl Drop for FirmwareLicense {
    fn drop(&mut self) {
        self.firmware_secret.zeroize();
        self.customer_secret.zeroize();
        self.opcode_seed.zeroize();
        if let Some(ref mut wbc) = self.wbc_tables_compressed {
            wbc.zeroize();
        }
    }
}

/// Groups the three encrypted binary assets the Android app loads at startup.
///
/// In practice these come from the APK `assets/` directory. `FirmwareBundle`
/// is just a convenience type that keeps all three together so the verification
/// chain can be expressed in a single method call.
///
/// Fields are private to prevent post-construction mutation that would bypass
/// the Ed25519 signature check in `decrypt_program_and_customer_key`. Use
/// `FirmwareBundle::new` to construct a bundle from the three asset byte slices.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FirmwareBundle {
    encrypted_license: Vec<u8>,
    encrypted_firmware: Vec<u8>,
    codesign: Vec<u8>,
}

impl FirmwareBundle {
    /// Constructs a bundle from the three encrypted asset byte slices read from
    /// the APK `assets/` directory (`license.bin`, `firmware.bin`, `codesign.bin`).
    pub fn new(
        encrypted_license: Vec<u8>,
        encrypted_firmware: Vec<u8>,
        codesign: Vec<u8>,
    ) -> Self {
        Self { encrypted_license, encrypted_firmware, codesign }
    }
}

impl FirmwareBundle {
    /// Runs the full verification and decryption chain, returning the parsed VM
    /// program and the derived customer-data key.
    ///
    /// Step-by-step:
    ///
    /// 1. **Signature verification** (`verify_code_signature`): checks the
    ///    Ed25519 signature in `codesign.bin` against a payload that includes
    ///    the hashes of `encrypted_license` and `encrypted_firmware` plus the
    ///    runtime app identity. If either encrypted blob was modified after
    ///    signing, this step fails. This is the first check because it is cheap
    ///    (no KDF) and immediately catches tampered assets.
    ///
    /// 2. **License decryption** (`decrypt_license`): the license is encrypted
    ///    with a key derived from the app's signing-cert hash and package name.
    ///    Only the correct app can decrypt it.
    ///
    /// 3. **Identity validation** (`validate_identity`): the decrypted license
    ///    contains the package name, cert hash, and installer policy that it was
    ///    issued for. These must match the runtime identity exactly.
    ///
    /// 4. **Firmware decryption** (`decrypt_firmware`): the firmware key is
    ///    derived from the `firmware_secret` inside the license. Without the
    ///    license, the firmware cannot be decrypted.
    ///
    /// 5. **Firmware hash check**: SHA-256 of the decrypted firmware bytes is
    ///    computed and compared against `license.firmware_sha256`. If someone
    ///    replaced `firmware.bin` (even with a correctly-signed substitute),
    ///    this check catches it because the hash in the *license* won't match.
    ///
    /// 6. **Bytecode parsing** (`Program::from_bytes`): the decrypted bytes are
    ///    parsed as VM bytecode. If the firmware is corrupted, this will fail.
    ///
    /// 7. **Customer-data key derivation**: the customer-data key is derived
    ///    from `customer_secret` in the license and returned alongside the
    ///    program. The `FirmwareLicense` is dropped at the end of this method,
    ///    which zeroizes `firmware_secret` and `customer_secret` in memory.
    ///
    /// # Errors
    ///
    /// Returns the first error encountered in the chain above, mapped to the
    /// appropriate `VmError` variant.
    /// Returns `(program, customer_key_init, firmware_flags)`.
    /// The `firmware_flags` value is taken directly from the decrypted license;
    /// bit 0 enables VM debug mode (see `FirmwareLicense::firmware_flags()`).
    pub fn decrypt_program_and_customer_key(
        &self,
        identity: &CodeIdentity,
        codesign_public_key: &[u8; ED25519_PUBLIC_KEY_LEN],
    ) -> Result<(Program, CustomerKeyInit, u32)> {
        // Step 1: verify the Ed25519 signature before doing any KDF work.
        verify_code_signature(
            identity,
            &self.encrypted_license,
            &self.encrypted_firmware,
            &self.codesign,
            codesign_public_key,
        )?;

        // Step 2: decrypt the license using the app-identity-derived key.
        // `mut` is needed on Android+jni to call clear_wbc_tables() below.
        #[cfg_attr(not(all(target_os = "android", feature = "jni")), allow(unused_mut))]
        let mut license = decrypt_license(&self.encrypted_license, identity)?;

        // Step 3: verify the runtime identity matches the license.
        license.validate_identity(identity)?;

        // Step 3b: HMAC self-integrity check — cryptographically binding.
        //
        // The HMAC is keyed from `firmware_secret`, a 256-bit value that only
        // exists inside the (now decrypted) license. An attacker who patches the
        // .so cannot forge this MAC without `firmware_secret`. Unlike the early
        // SHA-256 check in `check_so_integrity()`, this check cannot be bypassed
        // by zeroing a slot and recomputing the digest.
        if !license.check_so_hmac() {
            return Err(VmError::EnvironmentBlocked);
        }

        // Step 4: derive the firmware key and decrypt the firmware bytes.
        // Zeroizing<[u8; AES_KEY_LEN]> ensures the firmware AES key is erased on
        // every exit path — including the `?` early return from `decrypt_firmware`
        // that would otherwise skip the explicit `.zeroize()` that follows it.
        let firmware_key = Zeroizing::new(license.firmware_key()?);
        let mut firmware = decrypt_firmware(&self.encrypted_firmware, &firmware_key)?;
        // firmware_key drops and zeroes itself automatically here.

        // Step 5: confirm the decrypted firmware matches the hash in the license.
        if sha256(&firmware) != *license.firmware_sha256() {
            firmware.zeroize();
            return Err(VmError::InvalidPackage("verification failed".to_string()));
        }

        // Step 6: decode the bytecode through the per-license opcode table,
        // then zeroize the raw decrypted bytes — the Program holds the
        // instructions in a higher-level form and the raw buffer is not needed.
        let opcode_table = OpcodeTable::from_seed(license.opcode_seed());
        let program = Program::from_bytes_with_table(&firmware, &opcode_table)?;
        firmware.zeroize();

        // Step 7: try the Android Keystore path first (hardware-backed, preferred).
        // The raw key is derived transiently to obtain the Keystore alias and is
        // zeroized immediately — it does not leave this scope.
        #[cfg(all(target_os = "android", feature = "jni"))]
        if let Ok(mut raw_key) = license.customer_data_key() {
            let alias = crate::keystore::derive_alias(&raw_key);
            raw_key.zeroize();
            if crate::keystore::use_or_generate_key(&alias).is_some() {
                // Free the compressed WBC table bytes — they will not be used
                // on the hardware-backed path.
                license.clear_wbc_tables();
                let flags = license.firmware_flags();
                return Ok((program, CustomerKeyInit::Hardware(alias), flags));
            }
        }

        // Step 8: no hardware storage — return the white-box tables.
        // `license` is dropped at the end of this scope, zeroizing secrets.
        let tables = license.customer_data_tables()?;
        let flags = license.firmware_flags();
        Ok((program, CustomerKeyInit::WhiteBox(tables), flags))
    }
}

/// Decrypts `license.bin` using a key derived from the app identity.
///
/// The encryption key is derived from `cert_hash` (as Argon2id salt) and
/// `package_id` (as part of the password). This means only the exact app the
/// license was issued for can decrypt it — a different app, or the same app
/// signed with a different key, derives a different key and gets garbage.
///
/// Called at runtime by `FirmwareBundle::decrypt_program_and_customer_key`.
///
/// # Errors
///
/// Returns `Crypto` if key derivation fails or decryption fails.
/// Returns `InvalidPackage` if the blob format is wrong.
/// Returns `InvalidLicense` if the decrypted payload cannot be parsed.
pub fn decrypt_license(
    encrypted_license: &[u8],
    identity: &CodeIdentity,
) -> Result<FirmwareLicense> {
    // Zeroizing<[u8; AES_KEY_LEN]> ensures the derived AES key is erased on
    // every exit path — including the `?` early return from `decrypt_package`
    // that would otherwise skip the explicit `.zeroize()` at the end.
    let installer_kdf = identity.installer_package.as_deref().unwrap_or("");
    let key = Zeroizing::new(derive_license_key(
        &identity.signing_cert_sha256,
        &identity.package_id,
        installer_kdf,
    )?);
    let mut plaintext = decrypt_package(encrypted_license, &key)?;
    // Parse before zeroizing: plaintext contains firmware_secret and
    // customer_secret in the clear and must be erased after use.
    let license = FirmwareLicense::from_bytes(&plaintext);
    plaintext.zeroize();
    // key drops and zeroes itself automatically here.
    license
}

/// Decrypts the firmware bytecode blob with the firmware key from the license.
///
/// Called by `FirmwareBundle::decrypt_program_and_customer_key` after the
/// firmware key has been derived from the license. The firmware key includes
/// the `firmware_secret` from the license, so this can only succeed if the
/// correct license was provided.
///
/// # Errors
///
/// Returns `Crypto` if decryption fails (wrong key or corrupted ciphertext).
/// Returns `InvalidPackage` if the blob format is wrong.
pub fn decrypt_firmware(
    encrypted_firmware: &[u8],
    firmware_key: &[u8; AES_KEY_LEN],
) -> Result<Vec<u8>> {
    decrypt_package(encrypted_firmware, firmware_key)
}

/// Encrypts a `FirmwareLicense` for the app identified by `signing_certificate`.
///
/// This is a **build-time** function used to produce `license.bin`. It should
/// never be called at runtime on the device. The license is serialized to bytes
/// and then encrypted with a key derived from the certificate's SHA-256 hash
/// and the license's package id, so only the exact app can decrypt it.
///
/// # Errors
///
/// Returns `InvalidInput` if any string field is too long to serialize.
/// Returns `Crypto` if key derivation or AES-GCM encryption fails.
pub fn encrypt_license_for_signing_certificate(
    license: &FirmwareLicense,
    signing_certificate: &[u8],
) -> Result<Vec<u8>> {
    let cert_hash = sha256(signing_certificate);
    // Derive the same installer_kdf value that decrypt_license will compute at
    // runtime: Required(name) → name, Any → "".  Any-policy licences always use
    // "" so they accept every runtime installer (the KDF is installer-agnostic).
    let installer_kdf = match license.installer_policy() {
        InstallerPolicy::Required(name) => name.as_str(),
        InstallerPolicy::Any => "",
    };
    // Zeroizing clears the derived key even if `license.to_bytes()` or
    // `encrypt_package` returns an error — without it the key leaks on the
    // error path via `?`.
    let key = Zeroizing::new(derive_license_key(&cert_hash, license.package_id(), installer_kdf)?);
    encrypt_package(&license.to_bytes()?, &key)
}

/// Encrypts the VM bytecode for storage in `firmware.bin`.
///
/// This is a **build-time** function. The firmware key must be derived from
/// `FirmwareLicense::firmware_key()` using the license that will be distributed
/// alongside this firmware blob, so the two are cryptographically bound.
///
/// # Errors
///
/// Returns `Crypto` if AES-GCM encryption fails.
pub fn encrypt_firmware(bytecode: &[u8], firmware_key: &[u8; AES_KEY_LEN]) -> Result<Vec<u8>> {
    encrypt_package(bytecode, firmware_key)
}

/// Encrypts arbitrary customer data with the customer-data key.
///
/// The customer-data key is derived from the `FirmwareLicense` during
/// `start_with_verified_assets()` and lives in the `SecureVm` for the
/// duration of the session. On Android this function is exposed through
/// `SecureVm::encryptData()`. Only call this after a successful
/// `startFromAssets()` — the key does not exist before that.
///
/// The `SVMDAT01` magic differentiates customer-data ciphertext from license
/// or firmware packages, preventing cross-type decryption attempts.
///
/// # Errors
///
/// Returns `Crypto` if AES-GCM encryption fails.
pub fn encrypt_customer_data(
    plaintext: &[u8],
    customer_data_key: &[u8; AES_KEY_LEN],
) -> Result<Vec<u8>> {
    encrypt_package_with_magic(plaintext, customer_data_key, CUSTOMER_DATA_MAGIC)
}

/// Decrypts data previously encrypted with `encrypt_customer_data`.
///
/// Requires the same customer-data key that was used to encrypt. The key is
/// only available after a successful `start_with_verified_assets()` call, so
/// this cannot be used offline without first completing the full verification
/// chain.
///
/// # Errors
///
/// Returns `Crypto` if decryption or GCM authentication fails (wrong key or
/// corrupted ciphertext).
/// Returns `InvalidPackage` if the blob does not have the `SVMDAT01` magic.
pub fn decrypt_customer_data(
    ciphertext: &[u8],
    customer_data_key: &[u8; AES_KEY_LEN],
) -> Result<Vec<u8>> {
    decrypt_package_with_magic(ciphertext, customer_data_key, CUSTOMER_DATA_MAGIC)
}

/// Encrypts program bytecode for session-ephemeral storage inside `SecureVm`.
///
/// Uses the `SVMPRG01` magic to distinguish internal program blobs from
/// customer-data blobs (`SVMDAT01`), preventing cross-type decryption.
pub(crate) fn encrypt_program(
    plaintext: &[u8],
    program_key: &[u8; AES_KEY_LEN],
) -> Result<Vec<u8>> {
    encrypt_package_with_magic(plaintext, program_key, PROGRAM_MAGIC)
}

/// Decrypts a program blob produced by [`encrypt_program`].
pub(crate) fn decrypt_program(
    ciphertext: &[u8],
    program_key: &[u8; AES_KEY_LEN],
) -> Result<Vec<u8>> {
    decrypt_package_with_magic(ciphertext, program_key, PROGRAM_MAGIC)
}

/// Produces the detached Ed25519 signature blob stored in `codesign.bin`.
///
/// **Why sign the encrypted blobs rather than the plaintext?** Because the
/// recipient never sees the plaintext at signing time (the build tool signs
/// them), and more importantly because an attacker who modifies the encrypted
/// bytes (even without being able to decrypt them) would break the signature.
/// Signing plaintext would allow someone to re-encrypt with a different key
/// and produce a new valid ciphertext without changing the signed bytes.
///
/// The signature covers a payload that includes the app identity and the
/// SHA-256 hashes of both blobs (see `code_signature_payload`). This binds
/// the signature to a specific package + cert + firmware + license combination.
///
/// The private key is provided through the `signer` callback. This means the
/// private key never touches this crate — it can live in an HSM, a CI secret,
/// or a separate signing service.
///
/// # Errors
///
/// Returns `InvalidInput` if the payload serialisation fails.
/// Returns whatever error the `signer` callback returns.
pub fn sign_code_assets(
    identity: &CodeIdentity,
    encrypted_license: &[u8],
    encrypted_firmware: &[u8],
    signer: impl FnOnce(&[u8]) -> Result<[u8; ED25519_SIGNATURE_LEN]>,
) -> Result<Vec<u8>> {
    let payload = code_signature_payload(identity, encrypted_license, encrypted_firmware)?;
    let signature = signer(&payload)?;
    let mut codesign = Vec::with_capacity(CODESIGN_MAGIC.len() + ED25519_SIGNATURE_LEN);
    codesign.extend_from_slice(CODESIGN_MAGIC);
    codesign.extend_from_slice(&signature);
    Ok(codesign)
}

/// Verifies that the assets and runtime identity match the detached signature
/// in `codesign.bin`.
///
/// **Ed25519** is a fast asymmetric signature scheme based on the Edwards
/// Curve 25519. It uses a 32-byte public key and produces 64-byte signatures.
/// Ed25519 is chosen here because: it is fast to verify (important on mobile
/// CPUs), the keys are small, it is widely regarded as secure against classical
/// and some post-quantum attacks, and the Rust ecosystem has a mature
/// implementation (`ed25519-dalek`).
///
/// The verification re-derives the same payload that `sign_code_assets`
/// signed. If either encrypted blob has been modified (byte flipped, replaced,
/// truncated), or if the app identity at runtime differs from what was signed,
/// the reconstructed payload will differ and the signature will not verify.
///
/// # Errors
///
/// Returns `InvalidPackage("verification failed")` for any failure — wrong
/// size, bad magic, invalid encoding, invalid public key, or signature
/// mismatch. The message is deliberately uniform so that callers cannot
/// distinguish between these cases from the error alone.
pub fn verify_code_signature(
    identity: &CodeIdentity,
    encrypted_license: &[u8],
    encrypted_firmware: &[u8],
    codesign: &[u8],
    public_key: &[u8; ED25519_PUBLIC_KEY_LEN],
) -> Result<()> {
    if codesign.len() != CODESIGN_MAGIC.len() + ED25519_SIGNATURE_LEN {
        return Err(VmError::InvalidPackage("verification failed".to_string()));
    }
    if &codesign[..CODESIGN_MAGIC.len()] != CODESIGN_MAGIC {
        return Err(VmError::InvalidPackage("verification failed".to_string()));
    }

    let signature = Signature::from_slice(&codesign[CODESIGN_MAGIC.len()..])
        .map_err(|_| VmError::InvalidPackage("verification failed".to_string()))?;
    let verifying_key = VerifyingKey::from_bytes(public_key)
        .map_err(|_| VmError::InvalidPackage("verification failed".to_string()))?;
    let payload = code_signature_payload(identity, encrypted_license, encrypted_firmware)?;

    verifying_key
        .verify(&payload, &signature)
        .map_err(|_| VmError::InvalidPackage("verification failed".to_string()))
}

/// Computes SHA-256 over `bytes` and returns the 32-byte digest.
///
/// This function is `pub` because build tools outside this crate need it —
/// specifically to compute the `firmware_sha256` field that goes into a
/// `FirmwareLicense` before encrypting it. At runtime the VM also calls it
/// internally to verify the firmware hash.
pub fn sha256(bytes: &[u8]) -> [u8; SHA256_LEN] {
    Sha256::digest(bytes).into()
}

/// Encrypts a payload with the generic encrypted-package format (`SVMENC01`
/// magic).
///
/// This is a thin wrapper around `encrypt_package_with_magic` that uses the
/// default `PACKAGE_MAGIC`. Used for license and firmware encryption where no
/// special magic tag is needed.
fn encrypt_package(plaintext: &[u8], key: &[u8; AES_KEY_LEN]) -> Result<Vec<u8>> {
    encrypt_package_with_magic(plaintext, key, PACKAGE_MAGIC)
}

/// Encrypts a payload with AES-256-GCM and a caller-specified format magic.
///
/// A fresh 12-byte nonce is generated for every call using `OsRng` (the OS's
/// cryptographically secure random source on Android). Binary layout of the
/// output:
///
/// ```text
/// [magic: 8][nonce: 12][ciphertext: plaintext_len + 16 (GCM tag)]
/// ```
///
/// The GCM authentication tag (16 bytes, appended to the ciphertext by the
/// AES-GCM library) ensures that any modification to the ciphertext is
/// detected on decryption.
///
/// # Errors
///
/// Returns `Crypto` if AES-GCM key initialisation or encryption fails.
fn encrypt_package_with_magic(
    plaintext: &[u8],
    key: &[u8; AES_KEY_LEN],
    magic: &[u8; 8],
) -> Result<Vec<u8>> {
    let mut nonce = [0_u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);

    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| VmError::Crypto)?;
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .map_err(|_| VmError::Crypto)?;

    let mut package = Vec::with_capacity(magic.len() + NONCE_LEN + ciphertext.len());
    package.extend_from_slice(magic);
    package.extend_from_slice(&nonce);
    package.extend_from_slice(&ciphertext);
    Ok(package)
}

/// Decrypts a payload using the generic encrypted-package format (`SVMENC01`
/// magic).
///
/// Thin wrapper around `decrypt_package_with_magic` using the default
/// `PACKAGE_MAGIC`.
fn decrypt_package(package: &[u8], key: &[u8; AES_KEY_LEN]) -> Result<Vec<u8>> {
    decrypt_package_with_magic(package, key, PACKAGE_MAGIC)
}

/// Decrypts an AES-256-GCM package and verifies the format magic.
///
/// The magic check happens before any decryption. This ensures that passing
/// a blob of the wrong type returns a clear `InvalidPackage` error rather than
/// a `Crypto` error that could be confused with a wrong-key failure.
///
/// AES-256-GCM decryption verifies the GCM authentication tag internally. If
/// the key is wrong, the ciphertext is corrupt, or an attacker has modified
/// even one byte, decryption returns `Err` (the `Crypto` variant). The error
/// is intentionally opaque: we do not distinguish "wrong key" from "corrupt
/// ciphertext" to avoid oracle attacks.
///
/// # Errors
///
/// Returns `InvalidPackage` if the package is too short or the magic does not
/// match. Returns `Crypto` if AES-GCM decryption or authentication fails.
fn decrypt_package_with_magic(
    package: &[u8],
    key: &[u8; AES_KEY_LEN],
    magic: &[u8; 8],
) -> Result<Vec<u8>> {
    if package.len() <= magic.len() + NONCE_LEN {
        return Err(VmError::InvalidPackage("package is too short".to_string()));
    }
    if &package[..magic.len()] != magic {
        return Err(VmError::InvalidPackage(
            "package magic mismatch".to_string(),
        ));
    }

    let nonce_start = magic.len();
    let ciphertext_start = nonce_start + NONCE_LEN;
    let nonce = Nonce::from_slice(&package[nonce_start..ciphertext_start]);
    let ciphertext = &package[ciphertext_start..];

    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| VmError::Crypto)?;
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| VmError::Crypto)
}

/// Derives the AES key used to encrypt and decrypt `license.bin`.
///
/// **Why the embed secret matters**: `cert_hash` and `package_id` are both
/// fully observable by anyone who downloads the APK (the cert is in the
/// signing block; the package id is in `AndroidManifest.xml`). With only
/// public inputs, an attacker runs Argon2id once with known values and the
/// license key falls out in 1–2 s on a workstation — Argon2id only defends
/// against *unknown* input search.
///
/// The `LICENSE_EMBED_SECRET` is a 32-byte vendor-held constant compiled into
/// the `.so` via `obfstr::obfbytes!` (XOR-obfuscated at compile time; no
/// plaintext appears in `.rodata`). An attacker who has only the APK cannot
/// observe this secret and therefore cannot compute the license key. They must
/// reverse-engineer the stripped AArch64 `.so` — a meaningfully harder bar.
///
/// The vendor's license-creation tooling compiles from the same `firmware.rs`,
/// so it uses the identical secret automatically.
///
/// KDF inputs:
/// - **Salt**: `cert_hash` — 32 bytes, stable and unique per signing key.
/// - **Password**: domain prefix + `package_id` + `LICENSE_EMBED_SECRET`.
///   Domain prefix provides separation from other KDFs in this codebase.
///
/// # Errors
///
/// Returns `Crypto` if Argon2id parameter construction fails.
// KDF password layout (v4): all fields are \x00-separated so that a change
// in any field length cannot alias another field's value.
//
//   "secure-android-vm-license-v4" \x00
//   <package_id bytes>             \x00
//   <installer_kdf bytes>          \x00
//   <embed[32]>
//
// `installer_kdf` is the installer package name that was promised at license-
// issuance time:
//   • InstallerPolicy::Required(name) → name
//   • InstallerPolicy::Any            → "" (empty)
//
// At runtime, `decrypt_license` passes
// `identity.installer_package.as_deref().unwrap_or("")`.  For Required
// licenses, the correct installer must be present or the derived key is wrong
// and AES-GCM decryption fails — no plaintext, no policy check to bypass.
// For Any licenses both sides use "" so decryption succeeds regardless of
// the actual installer.
//
// BREAKING CHANGE vs v3: all existing license.bin files must be regenerated.
fn derive_license_key(
    cert_hash: &[u8; SHA256_LEN],
    package_id: &str,
    installer_kdf: &str,
) -> Result<[u8; AES_KEY_LEN]> {
    // 32-byte vendor secret compiled into the .so via obfbytes! (XOR-obfuscated;
    // no plaintext in the binary). Replace the placeholder zeros with 32 random
    // bytes before any production release — the same value must be used by the
    // license-creation tooling (automatic, as it compiles from this same file).
    //
    // Generate with: openssl rand -hex 32
    //
    // WARNING: with the all-zero placeholder, the license key is derived from
    // public APK data alone (cert hash + package id + installer). Anyone can
    // compute it. Enforce replacement by building with --features enforce_embed_secret.
    // Zeroizing ensures the embed secret is zeroed on any exit path — including
    // the early-return error paths below — not just on the happy path.
    let embed = Zeroizing::new(*obfstr::obfbytes!(
        b"\x00\x00\x00\x00\x00\x00\x00\x00\
          \x00\x00\x00\x00\x00\x00\x00\x00\
          \x00\x00\x00\x00\x00\x00\x00\x00\
          \x00\x00\x00\x00\x00\x00\x00\x00"
    ));

    // Reject all-zero embed in production builds when enforcement is enabled.
    // In test builds (#[cfg(test)]) the check is omitted so unit tests that do
    // not set up a real vendor secret can still exercise the KDF code paths.
    #[cfg(all(feature = "enforce_embed_secret", not(test)))]
    if *embed == [0u8; 32] {
        return Err(VmError::InvalidInput(
            "LICENSE_EMBED_SECRET is all-zeros; replace before shipping \
             (run `openssl rand -hex 32` and update firmware.rs)"
                .into(),
        ));
    }

    // Capacity: domain(29) + NUL + package_id + NUL + installer_kdf + NUL + embed(32)
    let mut password = Zeroizing::new(Vec::<u8>::with_capacity(
        29 + 1 + package_id.len() + 1 + installer_kdf.len() + 1 + embed.len(),
    ));
    password.extend_from_slice(b"secure-android-vm-license-v4");
    password.push(0u8);
    password.extend_from_slice(package_id.as_bytes());
    password.push(0u8);
    password.extend_from_slice(installer_kdf.as_bytes());
    password.push(0u8);
    password.extend_from_slice(&*embed);

    let mut key = [0_u8; AES_KEY_LEN];
    // 128 MB, t=4 makes GPU brute-force ~8× harder than the OWASP minimum without
    // significant startup cost (runs once per session, not per operation).
    let params = Params::new(131_072, 4, 1, Some(AES_KEY_LEN)).map_err(|_| VmError::Crypto)?;
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(&password, cert_hash, &mut key)
        .map_err(|_| VmError::Crypto)?;
    Ok(key)
}

/// Derives the AES key used to decrypt `firmware.bin`.
///
/// The high-entropy `firmware_secret` from the license is the core secret.
/// Without the license, `firmware_secret` is unknown and the firmware cannot
/// be decrypted — even if an attacker has the raw `firmware.bin` bytes.
///
/// KDF inputs:
/// - **Salt**: `firmware_hash` (SHA-256 of the firmware blob) — unique per
///   firmware build. Each firmware version requires its own KDF instance. An
///   attacker cannot pre-compute the key for future firmware without knowing
///   the firmware content.
/// - **Password**: domain prefix + `firmware_secret` + `package_id` + `cert_hash`
///   — the domain prefix provides domain separation; folding in both the
///   secret and the public identity context binds the derived key to this
///   specific app + firmware combination.
///
/// # Errors
///
/// Returns `Crypto` if Argon2id parameter construction fails.
fn derive_firmware_key(
    firmware_secret: &[u8; AES_KEY_LEN],
    package_id: &str,
    cert_hash: &[u8; SHA256_LEN],
    firmware_hash: &[u8; SHA256_LEN],
) -> Result<[u8; AES_KEY_LEN]> {
    let mut password = Zeroizing::new(Vec::<u8>::with_capacity(
        32 + AES_KEY_LEN + package_id.len() + SHA256_LEN,
    ));
    password.extend_from_slice(b"secure-android-vm-firmware-v3");
    password.extend_from_slice(firmware_secret);
    password.extend_from_slice(package_id.as_bytes());
    password.extend_from_slice(cert_hash);

    let mut key = [0_u8; AES_KEY_LEN];
    let params = Params::new(65_536, 3, 1, Some(AES_KEY_LEN)).map_err(|_| VmError::Crypto)?;
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(&password, firmware_hash, &mut key)
        .map_err(|_| VmError::Crypto)?;
    Ok(key)
}

/// Derives the AES key used to encrypt and decrypt customer app data.
///
/// The `customer_secret` from the license is the core secret — independent of
/// `firmware_secret` so that the firmware key and customer-data key cannot be
/// derived from each other.
///
/// KDF inputs:
/// - **Salt**: `cert_hash` — ties the key to the app's signing identity, the
///   same convention used by `derive_license_key`. Consistent salt choice
///   across derivations makes the system easier to reason about.
/// - **Password**: domain prefix + `customer_secret` + `package_id`
///   — domain separation ensures this key is distinct from the license key
///   even though the salt is the same.
///
/// # Errors
///
/// Returns `Crypto` if Argon2id parameter construction fails.
fn derive_customer_data_key(
    customer_secret: &[u8; AES_KEY_LEN],
    package_id: &str,
    cert_hash: &[u8; SHA256_LEN],
) -> Result<[u8; AES_KEY_LEN]> {
    let mut password = Zeroizing::new(Vec::<u8>::with_capacity(
        36 + AES_KEY_LEN + package_id.len(),
    ));
    password.extend_from_slice(b"secure-android-vm-customer-data-v2");
    password.extend_from_slice(customer_secret);
    password.extend_from_slice(package_id.as_bytes());

    let mut key = [0_u8; AES_KEY_LEN];
    let params = Params::new(65_536, 3, 1, Some(AES_KEY_LEN)).map_err(|_| VmError::Crypto)?;
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(&password, cert_hash, &mut key)
        .map_err(|_| VmError::Crypto)?;
    Ok(key)
}

// ── WBC table compression ──────────────────────────────────────────────────────

/// Zlib-compresses raw WBC table bytes for embedding in a license blob.
///
/// White-box tables are ~200 KB uncompressed; zlib brings them to ~50 KB,
/// keeping the license asset within reasonable APK size limits.
fn compress_wbc_tables(data: &[u8]) -> Result<Vec<u8>> {
    let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
    enc.write_all(data).map_err(|_| VmError::Crypto)?;
    enc.finish().map_err(|_| VmError::Crypto)
}

/// Zlib-decompresses WBC table bytes previously compressed by `compress_wbc_tables`.
fn decompress_wbc_tables(data: &[u8]) -> Result<Vec<u8>> {
    let mut dec = ZlibDecoder::new(data);
    let mut out = Vec::new();
    dec.read_to_end(&mut out).map_err(|_| VmError::Crypto)?;
    Ok(out)
}

/// Serialises and zlib-compresses `WbcAes256Tables` for embedding in a license.
///
/// Call this from the build tool after generating tables via
/// `WbcAes256Tables::generate(key)`. Pass the result to
/// `FirmwareLicense::with_wbc_tables(compressed)`.
pub fn compress_customer_data_tables(tables: &WbcAes256Tables) -> Result<Vec<u8>> {
    compress_wbc_tables(&tables.to_bytes())
}

/// Builds the byte payload that `codesign.bin` authenticates with Ed25519.
///
/// The payload includes:
/// - A domain-separation prefix (`"SVM-CODESIGN-PAYLOAD-V1"`)
/// - The app's package id (length-prefixed UTF-8)
/// - The app's signing-cert hash (32 bytes)
/// - The installer package (optional, presence-flagged)
/// - SHA-256 of `encrypted_license` (32 bytes)
/// - SHA-256 of `encrypted_firmware` (32 bytes)
///
/// By including both blob hashes and the identity, the signature is
/// simultaneously bound to: the specific identity the assets were built for,
/// and the exact binary content of both assets. Changing any one of these six
/// components without access to the vendor's Ed25519 private key produces a
/// signature that fails `verify_code_signature`.
///
/// # Errors
///
/// Returns `InvalidInput` if any string field is too long to serialize.
fn code_signature_payload(
    identity: &CodeIdentity,
    encrypted_license: &[u8],
    encrypted_firmware: &[u8],
) -> Result<Vec<u8>> {
    let mut payload = Vec::new();
    payload.extend_from_slice(b"SVM-CODESIGN-PAYLOAD-V1");
    write_string(&mut payload, &identity.package_id)?;
    payload.extend_from_slice(&identity.signing_cert_sha256);
    write_optional_string(&mut payload, identity.installer_package.as_deref())?;
    payload.extend_from_slice(&sha256(encrypted_license));
    payload.extend_from_slice(&sha256(encrypted_firmware));
    Ok(payload)
}

/// Writes a UTF-8 string to a byte buffer using a 2-byte little-endian length
/// prefix.
///
/// The length-prefix format (`u16 LE + bytes`) allows strings of up to 65535
/// bytes to be stored unambiguously in a binary stream. The parser reads the
/// length first, then exactly that many bytes, so there are no delimiters to
/// mis-parse or inject.
///
/// # Errors
///
/// Returns `InvalidInput` if the string is longer than 65535 bytes.
fn write_string(bytes: &mut Vec<u8>, value: &str) -> Result<()> {
    let len = u16::try_from(value.len())
        .map_err(|_| VmError::InvalidInput("string is too long".to_string()))?;
    bytes.extend_from_slice(&len.to_le_bytes());
    bytes.extend_from_slice(value.as_bytes());
    Ok(())
}

/// Writes an optional string by storing a one-byte presence flag followed by
/// the string (if present) using the same length-prefix format as
/// `write_string`.
///
/// - `0x00` flag: the `Option` was `None` — no string follows.
/// - `0x01` flag: the `Option` was `Some` — a length-prefixed string follows.
///
/// # Errors
///
/// Returns `InvalidInput` if the inner string is too long.
fn write_optional_string(bytes: &mut Vec<u8>, value: Option<&str>) -> Result<()> {
    match value {
        Some(value) => {
            bytes.push(1);
            write_string(bytes, value)
        }
        None => {
            bytes.push(0);
            Ok(())
        }
    }
}

/// Checks that the next bytes in the input match the expected magic value and
/// advances the offset.
///
/// Called at the start of every `from_bytes` parser to confirm the blob type
/// before reading any length fields. Checking the magic first avoids
/// misinterpreting garbage length fields from a wrong-type or corrupt blob.
///
/// # Errors
///
/// Returns `InvalidLicense` with a descriptive label if the magic does not
/// match.
fn read_magic(bytes: &[u8], offset: &mut usize, magic: &[u8], label: &str) -> Result<()> {
    if bytes.get(*offset..*offset + magic.len()) != Some(magic) {
        return Err(VmError::InvalidLicense(format!("{label} magic mismatch")));
    }
    *offset += magic.len();
    Ok(())
}

/// Reads a length-prefixed UTF-8 string from a byte buffer, advancing `offset`.
///
/// Reads a 2-byte little-endian length, then that many bytes, and decodes them
/// as UTF-8. All operations check bounds before accessing the slice, so a
/// truncated blob produces `InvalidLicense` rather than a panic.
///
/// # Errors
///
/// Returns `InvalidLicense` if the slice is too short or the bytes are not
/// valid UTF-8.
fn read_string(bytes: &[u8], offset: &mut usize, label: &str) -> Result<String> {
    let len = u16::from_le_bytes(read_array::<2>(bytes, offset, label)?) as usize;
    let Some(raw) = bytes.get(*offset..*offset + len) else {
        return Err(VmError::InvalidLicense(format!("{label} is truncated")));
    };
    *offset += len;
    String::from_utf8(raw.to_vec())
        .map_err(|_| VmError::InvalidLicense(format!("{label} is not utf-8")))
}

/// Reads an optional string that was written with `write_optional_string`.
///
/// Reads the presence flag byte first:
/// - `0`: returns `Ok(None)`.
/// - `1`: reads the length-prefixed string and returns `Ok(Some(...))`.
/// - Any other value: returns `InvalidLicense`.
///
/// # Errors
///
/// Returns `InvalidLicense` if the flag byte is missing, is not 0 or 1, or
/// the string itself is malformed.
fn read_optional_string(bytes: &[u8], offset: &mut usize, label: &str) -> Result<Option<String>> {
    let Some(flag) = bytes.get(*offset).copied() else {
        return Err(VmError::InvalidLicense(format!("{label} flag missing")));
    };
    *offset += 1;

    match flag {
        0 => Ok(None),
        1 => read_string(bytes, offset, label).map(Some),
        _ => Err(VmError::InvalidLicense(format!("{label} flag is invalid"))),
    }
}

/// Reads exactly `N` bytes from `bytes` starting at `*offset`, returns them as
/// a fixed-size array, and advances `offset` by `N`.
///
/// Generic over `N` so it can be used for both 32-byte hashes and 2-byte
/// length prefixes without code duplication.
///
/// # Errors
///
/// Returns `InvalidLicense` if there are fewer than `N` bytes remaining.
fn read_array<const N: usize>(bytes: &[u8], offset: &mut usize, label: &str) -> Result<[u8; N]> {
    let Some(raw) = bytes.get(*offset..*offset + N) else {
        return Err(VmError::InvalidLicense(format!("{label} is truncated")));
    };
    let mut out = [0_u8; N];
    out.copy_from_slice(raw);
    *offset += N;
    Ok(out)
}

// ── Integration tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytecode::{Instruction, Program};
    use ed25519_dalek::{Signer, SigningKey};

    const TEST_CERT: &[u8] = b"test-certificate-der-bytes";
    const TEST_PACKAGE: &str = "com.example.test";

    fn make_identity() -> CodeIdentity {
        CodeIdentity::from_certificate(TEST_PACKAGE, TEST_CERT, None).unwrap()
    }

    fn make_license(identity: &CodeIdentity, firmware_bytes: &[u8]) -> FirmwareLicense {
        FirmwareLicense::new(
            identity.package_id.clone(),
            identity.signing_cert_sha256,
            InstallerPolicy::Any,
            sha256(firmware_bytes),
            [0xAAu8; 32], // firmware_secret
            [0xBBu8; 32], // customer_secret
            [0u8; 32],    // opcode_seed → identity table
            0,            // no expiry
            0,            // firmware_flags: 0 = no debug
        )
    }

    fn sign_bundle(
        identity: &CodeIdentity,
        enc_license: &[u8],
        enc_firmware: &[u8],
    ) -> (Vec<u8>, [u8; 32]) {
        let mut secret = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut secret);
        let signing_key = SigningKey::from_bytes(&secret);
        let pk = signing_key.verifying_key().to_bytes();
        let codesign = sign_code_assets(identity, enc_license, enc_firmware, |payload| {
            Ok(signing_key.sign(payload).to_bytes())
        })
        .unwrap();
        (codesign, pk)
    }

    #[test]
    fn license_serialise_roundtrip() {
        let identity = make_identity();
        let firmware_bytes = b"placeholder firmware";
        let license = make_license(&identity, firmware_bytes);
        let bytes = license.to_bytes().unwrap();
        let restored = FirmwareLicense::from_bytes(&bytes).unwrap();
        assert_eq!(restored.package_id(), license.package_id());
        assert_eq!(restored.signing_cert_sha256(), license.signing_cert_sha256());
        assert_eq!(restored.firmware_sha256(), license.firmware_sha256());
        assert_eq!(restored.valid_until(), 0);
    }

    #[test]
    fn identity_validation_passes_matching_identity() {
        let identity = make_identity();
        let license = make_license(&identity, b"fw");
        assert!(license.validate_identity(&identity).is_ok());
    }

    #[test]
    fn identity_validation_rejects_wrong_cert() {
        let identity = make_identity();
        let license = make_license(&identity, b"fw");
        let mut other = identity.clone();
        other.signing_cert_sha256 = [0xFFu8; 32];
        assert!(license.validate_identity(&other).is_err());
    }

    #[test]
    fn identity_validation_rejects_wrong_package() {
        let identity = make_identity();
        let license = make_license(&identity, b"fw");
        let mut other = identity.clone();
        other.package_id = "com.evil.attacker".to_string();
        assert!(license.validate_identity(&other).is_err());
    }

    #[test]
    fn full_verification_chain_succeeds() {
        let identity = make_identity();
        let program =
            Program::new(vec![Instruction::PushI64(42), Instruction::Halt]).unwrap();
        let firmware_bytes = program.to_bytes();

        let license = make_license(&identity, &firmware_bytes);
        let enc_license =
            encrypt_license_for_signing_certificate(&license, TEST_CERT).unwrap();
        let firmware_key = license.firmware_key().unwrap();
        let enc_firmware = encrypt_firmware(&firmware_bytes, &firmware_key).unwrap();

        let (codesign, pk) = sign_bundle(&identity, &enc_license, &enc_firmware);
        let bundle = FirmwareBundle::new(enc_license, enc_firmware, codesign);

        let (parsed, _key_init, _flags) =
            bundle.decrypt_program_and_customer_key(&identity, &pk).unwrap();

        assert_eq!(
            parsed.instructions(),
            &[Instruction::PushI64(42), Instruction::Halt]
        );
    }

    #[test]
    fn tampered_firmware_is_rejected() {
        let identity = make_identity();
        let program = Program::new(vec![Instruction::Halt]).unwrap();
        let firmware_bytes = program.to_bytes();

        let license = make_license(&identity, &firmware_bytes);
        let enc_license =
            encrypt_license_for_signing_certificate(&license, TEST_CERT).unwrap();
        let firmware_key = license.firmware_key().unwrap();
        let enc_firmware = encrypt_firmware(&firmware_bytes, &firmware_key).unwrap();

        let (codesign, pk) = sign_bundle(&identity, &enc_license, &enc_firmware);

        // Tamper with the encrypted firmware after signing — signature check fails.
        let mut tampered = enc_firmware.clone();
        let mid = tampered.len() / 2;
        tampered[mid] ^= 0xFF;

        let bundle = FirmwareBundle::new(enc_license, tampered, codesign);
        assert!(bundle.decrypt_program_and_customer_key(&identity, &pk).is_err());
    }

    #[test]
    fn wrong_signing_key_is_rejected() {
        let identity = make_identity();
        let program = Program::new(vec![Instruction::Halt]).unwrap();
        let firmware_bytes = program.to_bytes();

        let license = make_license(&identity, &firmware_bytes);
        let enc_license =
            encrypt_license_for_signing_certificate(&license, TEST_CERT).unwrap();
        let firmware_key = license.firmware_key().unwrap();
        let enc_firmware = encrypt_firmware(&firmware_bytes, &firmware_key).unwrap();

        let (codesign, _right_pk) = sign_bundle(&identity, &enc_license, &enc_firmware);
        // Verify with a different key — signature check fails.
        let mut wrong_secret = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut wrong_secret);
        let wrong_pk: [u8; 32] =
            SigningKey::from_bytes(&wrong_secret).verifying_key().to_bytes();

        let bundle = FirmwareBundle::new(enc_license, enc_firmware, codesign);
        assert!(bundle.decrypt_program_and_customer_key(&identity, &wrong_pk).is_err());
    }

    // ── installer KDF binding ──────────────────────────────────────────────────

    /// Build a Required-installer identity for KDF tests.
    fn make_identity_with_installer(installer: Option<&str>) -> CodeIdentity {
        CodeIdentity::from_certificate(TEST_PACKAGE, TEST_CERT, installer.map(str::to_owned))
            .unwrap()
    }

    /// Build a Required-installer license (non-Any policy).
    fn make_required_license(identity: &CodeIdentity, firmware_bytes: &[u8]) -> FirmwareLicense {
        FirmwareLicense::new(
            identity.package_id.clone(),
            identity.signing_cert_sha256,
            InstallerPolicy::Required("com.android.vending".to_owned()),
            sha256(firmware_bytes),
            [0xAAu8; 32],
            [0xBBu8; 32],
            [0u8; 32],
            0,
            0,
        )
    }

    #[test]
    fn required_installer_decrypts_with_correct_installer() {
        // License issued for "com.android.vending" — runtime identity matches.
        let identity = make_identity_with_installer(Some("com.android.vending"));
        let firmware_bytes = b"test firmware";
        let license = make_required_license(&identity, firmware_bytes);
        let enc = encrypt_license_for_signing_certificate(&license, TEST_CERT).unwrap();
        // Decrypt with the same identity — must succeed.
        assert!(decrypt_license(&enc, &identity).is_ok());
    }

    #[test]
    fn required_installer_rejects_wrong_installer_at_kdf_level() {
        // License issued for "com.android.vending".
        let issuing_identity = make_identity_with_installer(Some("com.android.vending"));
        let firmware_bytes = b"test firmware";
        let license = make_required_license(&issuing_identity, firmware_bytes);
        let enc = encrypt_license_for_signing_certificate(&license, TEST_CERT).unwrap();

        // Runtime identity has a different installer (sideload → "").
        // The KDF produces a different key → AES-GCM authentication tag fails.
        let sideload_identity = make_identity_with_installer(None);
        assert!(
            decrypt_license(&enc, &sideload_identity).is_err(),
            "sideloaded installer must not decrypt a Required-installer license"
        );

        // A spoofed-but-wrong installer name also fails.
        let wrong_identity = make_identity_with_installer(Some("com.attacker.store"));
        assert!(
            decrypt_license(&enc, &wrong_identity).is_err(),
            "wrong installer must not decrypt a Required-installer license"
        );
    }

    #[test]
    fn any_installer_policy_accepts_all_installers() {
        // License issued with InstallerPolicy::Any — KDF installer is always "".
        let identity_none = make_identity_with_installer(None);
        let firmware_bytes = b"test firmware";
        let license = make_license(&identity_none, firmware_bytes); // Any policy
        let enc = encrypt_license_for_signing_certificate(&license, TEST_CERT).unwrap();

        // Sideloaded (installer = None → "") must decrypt.
        assert!(decrypt_license(&enc, &identity_none).is_ok());

        // Installer present (e.g. Play Store) — Any KDF uses "" at generation
        // time, but runtime passes "com.android.vending". The KDF produces a
        // different key and decryption fails. This is the documented Any+Play
        // Store limitation: Any policy is intended for sideload / unknown
        // installer scenarios only. Production apps must use Required.
        let play_identity = make_identity_with_installer(Some("com.android.vending"));
        assert!(
            decrypt_license(&enc, &play_identity).is_err(),
            "Any-policy license with non-empty installer must fail (use Required for Play Store)"
        );
    }

    #[test]
    fn expired_license_is_rejected() {
        let identity = make_identity();
        // valid_until = 1 (Unix epoch + 1 second) — long in the past.
        let license = FirmwareLicense::new(
            TEST_PACKAGE,
            identity.signing_cert_sha256,
            InstallerPolicy::Any,
            sha256(b"fw"),
            [0xAAu8; 32],
            [0xBBu8; 32],
            [0u8; 32],
            1, // expired
            0, // firmware_flags
        );
        assert!(license.validate_identity(&identity).is_err());
    }
}
