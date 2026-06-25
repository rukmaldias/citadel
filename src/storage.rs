//! Encrypted key-value store backed by Argon2id + AES-256-GCM.
//!
//! ## Design
//!
//! Every value is stored as an [`EncryptedRecord`]: a fresh random 128-bit
//! Argon2id salt, a fresh random 96-bit AES-GCM nonce, and the AES-GCM
//! ciphertext (which includes the 16-byte authentication tag). The passphrase
//! is never retained — it is supplied at the call site and zeroed from heap
//! buffers as soon as the derived key is no longer needed.
//!
//! ## Key-name privacy
//!
//! Key names (e.g. `"oauth_token"`) are **never written to the serialized
//! blob in plaintext**. Instead, each key name is hashed with
//! `HMAC-SHA-256(key_id_salt, "SVM-STORE-KEY-V1" ‖ key_name)` and the
//! resulting 32-byte key ID is written in its place. The 32-byte `key_id_salt`
//! is generated once per store and stored in the blob header; without it an
//! attacker cannot reverse the HMAC to recover key names.
//!
//! ## Serialized blob format (SVMSTORE03 / SVMSTORE04)
//!
//! ```text
//! [magic:       10 bytes]                 — "SVMSTORE03" or "SVMSTORE04"
//! [key_id_salt: 32 bytes]                 — random per-store HMAC base key
//! [count:        4 bytes LE u32]          — number of records
//! ([key_id:    32 bytes]                  — HMAC(salt, key_name) per record
//!  [salt:      16 bytes]                  — Argon2id salt
//!  [nonce:     12 bytes]                  — AES-GCM nonce
//!  [ct_len:     4 bytes LE u32]           — ciphertext + GCM tag length
//!  [ciphertext: ct_len bytes]) × count
//! ```
//!
//! ## Format migration
//!
//! The numeric suffix in the magic is the format version. SVMSTORE01 and
//! SVMSTORE02 (plaintext key names, written by earlier versions) are **not**
//! readable by this code — they will fail with "store magic mismatch". Blobs
//! must be re-written using the new format if upgrading from a prior version.

use std::collections::BTreeMap;

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{Result, VmError};

type HmacSha256 = Hmac<Sha256>;

// ── Format constants ──────────────────────────────────────────────────────────

/// Byte length of the per-record random Argon2id salt.
const SALT_LEN: usize = 16;

/// Byte length of the per-record random AES-256-GCM nonce.
const NONCE_LEN: usize = 12;

/// Byte length of the AES-256 key produced by `derive_key`.
const KEY_LEN: usize = 32;

/// Byte length of the HMAC-SHA-256 key ID that replaces the plaintext key name
/// in the serialized format.
const KEY_ID_LEN: usize = 32;

/// Byte length of the per-store random salt used to derive key IDs.
const KEY_ID_SALT_LEN: usize = 32;

/// Byte length of the fixed per-record binary header:
/// `salt(16) + nonce(12) + ct_len(4)`.
const RECORD_HEADER_LEN: usize = SALT_LEN + NONCE_LEN + 4;

// Format-version magic. The suffix distinguishes this version (HMAC key names)
// from the old SVMSTORE01/02 (plaintext key names). SVMSTORE03 uses the
// default Argon2id cost (m=65_536, t=3); SVMSTORE04 uses the stronger cost
// (m=131_072, t=4, enabled via the `store_strong_kdf` feature).
// Old SVMSTORE01 / SVMSTORE02 blobs fail immediately at the magic check.
#[cfg(feature = "store_strong_kdf")]
const STORE_MAGIC: &[u8; 10] = b"SVMSTORE04";
#[cfg(not(feature = "store_strong_kdf"))]
const STORE_MAGIC: &[u8; 10] = b"SVMSTORE03";

// Argon2id cost parameters for `derive_key`. Named constants so that a
// pinning test can catch accidental changes that would silently make all
// existing blobs unreadable.
#[cfg(feature = "store_strong_kdf")]
pub(crate) const KDF_M_COST: u32 = 131_072; // 128 MB — matches the license KDF
#[cfg(feature = "store_strong_kdf")]
pub(crate) const KDF_T_COST: u32 = 4;
#[cfg(not(feature = "store_strong_kdf"))]
pub(crate) const KDF_M_COST: u32 = 65_536; // 64 MB — OWASP 2021 minimum
#[cfg(not(feature = "store_strong_kdf"))]
pub(crate) const KDF_T_COST: u32 = 3;
pub(crate) const KDF_LANES: u32 = 1;

// ── EncryptedRecord ───────────────────────────────────────────────────────────

/// One AES-256-GCM–encrypted value stored in the [`SecureStore`].
///
/// Each record carries its own independent random salt and nonce, ensuring
/// that:
///
/// - **Salt prevents rainbow-table attacks**: every record requires a separate
///   Argon2id computation regardless of whether the same passphrase was used
///   for other records.
///
/// - **Nonce prevents ciphertext comparison**: with a fresh nonce per record
///   the AES-GCM keystream is never reused, so an attacker cannot learn
///   anything about the plaintexts by XOR-ing two ciphertexts.
///
/// The salt and nonce are not secret — they are stored in plaintext in the
/// serialized blob. Without the passphrase, knowing them gives no advantage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptedRecord {
    /// 128-bit random salt input for Argon2id key derivation for this record.
    pub salt: [u8; SALT_LEN],
    /// 96-bit random nonce for AES-256-GCM encryption of this record.
    pub nonce: [u8; NONCE_LEN],
    /// AES-256-GCM ciphertext including the 16-byte authentication tag.
    pub ciphertext: Vec<u8>,
}

impl EncryptedRecord {
    /// Serializes the record into a self-contained byte blob.
    ///
    /// Binary layout:
    /// ```text
    /// [salt: 16][nonce: 12][ciphertext_len: 4 LE u32][ciphertext: ciphertext_len]
    /// ```
    pub fn to_bytes(&self) -> Vec<u8> {
        let ct_len = self.ciphertext.len() as u32;
        let mut out = Vec::with_capacity(RECORD_HEADER_LEN + self.ciphertext.len());
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&ct_len.to_le_bytes());
        out.extend_from_slice(&self.ciphertext);
        out
    }

    /// Parses a record from a byte slice produced by [`to_bytes`](Self::to_bytes).
    ///
    /// # Errors
    ///
    /// Returns `InvalidInput` if the slice is too short, the ciphertext length
    /// field overflows `usize` (32-bit targets), or the declared length does not
    /// match the actual slice length.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < RECORD_HEADER_LEN {
            return Err(VmError::InvalidInput(
                "encrypted record too short".to_string(),
            ));
        }

        // These slices are guaranteed in-bounds by the check above.
        let salt  = bytes[..SALT_LEN].try_into()
            .unwrap_or_else(|_| unreachable!("slice is exactly SALT_LEN bytes"));
        let nonce = bytes[SALT_LEN..SALT_LEN + NONCE_LEN].try_into()
            .unwrap_or_else(|_| unreachable!("slice is exactly NONCE_LEN bytes"));
        let ct_len = u32::from_le_bytes(
            bytes[SALT_LEN + NONCE_LEN..RECORD_HEADER_LEN].try_into()
                .unwrap_or_else(|_| unreachable!("slice is exactly 4 bytes")),
        ) as usize;

        // Guard against overflow on 32-bit ARM where `usize == u32`.
        // Without `checked_add`, a ct_len near u32::MAX would wrap around to a
        // small value and pass the length check, leading to a slice panic later.
        let expected_total = RECORD_HEADER_LEN.checked_add(ct_len).ok_or_else(|| {
            VmError::InvalidInput(
                "encrypted record ciphertext length overflow".to_string(),
            )
        })?;

        if bytes.len() != expected_total {
            return Err(VmError::InvalidInput(
                "encrypted record length mismatch".to_string(),
            ));
        }

        Ok(Self {
            salt,
            nonce,
            ciphertext: bytes[RECORD_HEADER_LEN..].to_vec(),
        })
    }
}

// ── SecureStore ───────────────────────────────────────────────────────────────

/// A small AES-256-GCM–encrypted key-value store for secrets.
///
/// `SecureStore` holds encrypted records in memory and provides
/// `to_bytes` / `from_bytes` for persisting them across process restarts
/// (e.g. to `SharedPreferences` or a database column). **All secrets are
/// stored as ciphertext — even in RAM.** The passphrase is supplied at
/// read / write time and is never retained.
///
/// ## Key-name privacy
///
/// Key names are not stored in plaintext anywhere. `put(key, ...)` derives a
/// 32-byte HMAC-SHA-256 key ID from the key name and the store-level
/// `key_id_salt`, and uses that ID as the map key. An attacker who obtains the
/// serialized blob learns the number of records and their sizes, but not the
/// names (or values) of any stored secrets.
///
/// ## Persistence pattern
///
/// ```text
/// 1. After writing secrets: blob = store.to_bytes()?
/// 2. Persist blob (SharedPreferences, file, DB column).
/// 3. On next launch: store = SecureStore::from_bytes(&blob)?
/// 4. Retrieve a value: store.get("my_key", passphrase)?
/// ```
///
/// Thread safety: `SecureStore` is not `Sync`. In the JNI layer the owning
/// `SecureVm` is wrapped in a `Mutex`, so all cross-thread access is
/// serialised automatically.
#[derive(Debug)]
pub struct SecureStore {
    /// Random 32-byte salt used to derive key IDs from key names via HMAC.
    /// Generated once on construction; serialized in the blob header.
    key_id_salt: [u8; KEY_ID_SALT_LEN],
    /// Records keyed by HMAC(key_id_salt, "SVM-STORE-KEY-V1" ‖ key_name).
    records: BTreeMap<[u8; KEY_ID_LEN], EncryptedRecord>,
}

impl Default for SecureStore {
    /// Creates an empty store with a freshly randomized `key_id_salt`.
    fn default() -> Self {
        Self::new()
    }
}

impl SecureStore {
    /// Creates a new empty store.
    ///
    /// A random 32-byte `key_id_salt` is generated from `OsRng` and stored
    /// with the blob. Different store instances produce different key IDs for
    /// the same key name, which is intentional — two blobs cannot be
    /// correlated by comparing key IDs.
    pub fn new() -> Self {
        let mut key_id_salt = [0u8; KEY_ID_SALT_LEN];
        OsRng.fill_bytes(&mut key_id_salt);
        Self {
            key_id_salt,
            records: BTreeMap::new(),
        }
    }

    /// Encrypts `value` with a passphrase-derived key and stores it under `key`.
    ///
    /// Full encryption flow:
    ///
    /// 1. Derive a 32-byte key ID: `HMAC-SHA-256(key_id_salt, "SVM-STORE-KEY-V1" ‖ key)`.
    /// 2. Generate 16 random bytes as the Argon2id salt.
    /// 3. Generate 12 random bytes as the AES-GCM nonce.
    /// 4. Run Argon2id on `passphrase` + salt → 256-bit AES key.
    /// 5. Encrypt `value` with AES-256-GCM; the derived key is zeroed on drop.
    /// 6. Store the record under the key ID — the plaintext key name is not
    ///    retained.
    ///
    /// # Errors
    ///
    /// Returns `InvalidInput` if `passphrase` is shorter than 12 bytes.
    /// Returns `Crypto` if key derivation or AES-GCM encryption fails.
    ///
    /// # Security
    ///
    /// The derived AES key is wrapped in `Zeroizing` and is cleared when it
    /// goes out of scope — including on any error path. The `passphrase` buffer
    /// is owned by the caller and is **not** zeroized here; zero it after the
    /// call (e.g. with `zeroize::Zeroize::zeroize`).
    pub fn put(&mut self, key: impl Into<String>, value: &[u8], passphrase: &[u8]) -> Result<()> {
        let key_name: String = key.into();
        validate_passphrase(passphrase)?;

        let mut salt  = [0_u8; SALT_LEN];
        let mut nonce = [0_u8; NONCE_LEN];
        OsRng.fill_bytes(&mut salt);
        OsRng.fill_bytes(&mut nonce);

        // Zeroizing clears the derived key on drop regardless of whether the
        // AES-GCM operations below succeed or fail.
        let derived_key = Zeroizing::new(derive_key(passphrase, &salt)?);
        let cipher = Aes256Gcm::new_from_slice(&*derived_key).map_err(|_| VmError::Crypto)?;
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), value)
            .map_err(|_| VmError::Crypto)?;

        let id = key_id(&self.key_id_salt, &key_name);
        self.records.insert(id, EncryptedRecord { salt, nonce, ciphertext });

        Ok(())
    }

    /// Decrypts and returns the value stored under `key`.
    ///
    /// The passphrase must match the one used in the corresponding `put()` call.
    /// If it is wrong, AES-GCM authentication fails — the error is
    /// indistinguishable from a corrupt ciphertext, which prevents oracle
    /// attacks.
    ///
    /// # Errors
    ///
    /// Returns `KeyNotFound` if no record exists for `key`.
    /// Returns `InvalidInput` if `passphrase` is shorter than 12 bytes.
    /// Returns `Crypto` if decryption or authentication fails (wrong passphrase
    /// or corrupted ciphertext).
    ///
    /// # Security
    ///
    /// The derived AES key is wrapped in `Zeroizing` and is cleared on any exit
    /// path (success or error). The `passphrase` buffer is owned by the caller
    /// and is **not** zeroized here; zero it after the call.
    pub fn get(&self, key: &str, passphrase: &[u8]) -> Result<Vec<u8>> {
        validate_passphrase(passphrase)?;

        let id = key_id(&self.key_id_salt, key);
        let record = self.records.get(&id).ok_or(VmError::KeyNotFound)?;

        let derived_key = Zeroizing::new(derive_key(passphrase, &record.salt)?);
        let cipher = Aes256Gcm::new_from_slice(&*derived_key).map_err(|_| VmError::Crypto)?;
        let plaintext = cipher
            .decrypt(Nonce::from_slice(&record.nonce), record.ciphertext.as_ref())
            .map_err(|_| VmError::Crypto)?;

        Ok(plaintext)
    }

    /// Removes the record for `key` and returns `true` if it existed.
    pub fn delete(&mut self, key: &str) -> bool {
        let id = key_id(&self.key_id_salt, key);
        self.records.remove(&id).is_some()
    }

    /// Returns `true` if a record exists for `key`.
    pub fn contains_key(&self, key: &str) -> bool {
        let id = key_id(&self.key_id_salt, key);
        self.records.contains_key(&id)
    }

    /// Serializes all encrypted records to a portable blob.
    ///
    /// The blob contains ciphertext, salts, nonces, and HMAC-derived key IDs
    /// — **no plaintext keys or values**. It is safe to write to
    /// `SharedPreferences` or a database without additional encryption (though
    /// at-rest encryption is still recommended).
    ///
    /// # Errors
    ///
    /// Returns `InvalidInput` if there are more than `u32::MAX` records.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let count = u32::try_from(self.records.len())
            .map_err(|_| VmError::InvalidInput("too many records".to_string()))?;

        let mut out = Vec::new();
        out.extend_from_slice(STORE_MAGIC);
        out.extend_from_slice(&self.key_id_salt);
        out.extend_from_slice(&count.to_le_bytes());

        for (id, record) in &self.records {
            out.extend_from_slice(id);
            out.extend_from_slice(&record.to_bytes());
        }

        Ok(out)
    }

    /// Rebuilds a [`SecureStore`] from a blob produced by [`to_bytes`](Self::to_bytes).
    ///
    /// The `key_id_salt` and all record key IDs are read from the blob header,
    /// so `get()` / `delete()` / `contains_key()` work correctly after
    /// deserialization without needing the original key names.
    ///
    /// # Errors
    ///
    /// Returns `InvalidInput` if the magic does not match (including old
    /// SVMSTORE01/02 blobs), the blob is truncated, or any field is malformed.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        // Minimum header: magic (10) + key_id_salt (32) + count (4).
        let header_min = STORE_MAGIC.len() + KEY_ID_SALT_LEN + 4;
        if bytes.len() < header_min {
            return Err(VmError::InvalidInput("store blob too short".to_string()));
        }
        if &bytes[..STORE_MAGIC.len()] != STORE_MAGIC {
            return Err(VmError::InvalidInput("store magic mismatch".to_string()));
        }

        let mut pos = STORE_MAGIC.len();

        // Read the per-store key ID salt from the header.
        let key_id_salt: [u8; KEY_ID_SALT_LEN] = bytes[pos..pos + KEY_ID_SALT_LEN]
            .try_into()
            .unwrap_or_else(|_| unreachable!("slice is exactly KEY_ID_SALT_LEN bytes"));
        pos += KEY_ID_SALT_LEN;

        let count = u32::from_le_bytes(
            bytes[pos..pos + 4]
                .try_into()
                .unwrap_or_else(|_| unreachable!("slice is exactly 4 bytes")),
        ) as usize;
        pos += 4;

        let mut records = BTreeMap::new();
        for _ in 0..count {
            // ── Key ID (32 bytes) ──────────────────────────────────────────
            if pos + KEY_ID_LEN > bytes.len() {
                return Err(VmError::InvalidInput(
                    "store truncated at key id".to_string(),
                ));
            }
            let id: [u8; KEY_ID_LEN] = bytes[pos..pos + KEY_ID_LEN]
                .try_into()
                .unwrap_or_else(|_| unreachable!("slice is exactly KEY_ID_LEN bytes"));
            pos += KEY_ID_LEN;

            // ── Record header (salt + nonce + ct_len) ─────────────────────
            if pos + RECORD_HEADER_LEN > bytes.len() {
                return Err(VmError::InvalidInput(
                    "store truncated at record header".to_string(),
                ));
            }
            let ct_len = u32::from_le_bytes(
                bytes[pos + SALT_LEN + NONCE_LEN..pos + RECORD_HEADER_LEN]
                    .try_into()
                    .unwrap_or_else(|_| unreachable!("slice is exactly 4 bytes")),
            ) as usize;

            // Guard against overflow on 32-bit targets (usize == u32).
            let record_end = pos
                .checked_add(RECORD_HEADER_LEN)
                .and_then(|n| n.checked_add(ct_len))
                .ok_or_else(|| {
                    VmError::InvalidInput("store record length overflow".to_string())
                })?;

            if record_end > bytes.len() {
                return Err(VmError::InvalidInput(
                    "store truncated at ciphertext".to_string(),
                ));
            }

            records.insert(id, EncryptedRecord::from_bytes(&bytes[pos..record_end])?);
            pos = record_end;
        }

        if pos != bytes.len() {
            return Err(VmError::InvalidInput(
                "store blob has trailing bytes".to_string(),
            ));
        }

        Ok(Self { key_id_salt, records })
    }

    /// Exports all encrypted records keyed by their HMAC-derived key IDs.
    ///
    /// The companion `key_id_salt` (needed to reconstruct key IDs from key names)
    /// is returned alongside the records. Both must be preserved together and
    /// passed to [`import_records`](Self::import_records) for the store to
    /// remain queryable.
    ///
    /// Prefer [`to_bytes`](Self::to_bytes) / [`from_bytes`](Self::from_bytes)
    /// for persistence — this pair is intended for in-process record migration
    /// (e.g. merging two stores in the JNI layer).
    pub fn export_records(
        &self,
    ) -> ([u8; KEY_ID_SALT_LEN], BTreeMap<[u8; KEY_ID_LEN], EncryptedRecord>) {
        (self.key_id_salt, self.records.clone())
    }

    /// Rebuilds a [`SecureStore`] from a previously exported
    /// `(key_id_salt, records)` pair.
    ///
    /// The `key_id_salt` must be the one that was used when the records were
    /// originally stored. Passing a different salt produces a store where
    /// `get()` always returns `KeyNotFound` because the key IDs won't match.
    pub fn import_records(
        key_id_salt: [u8; KEY_ID_SALT_LEN],
        records: BTreeMap<[u8; KEY_ID_LEN], EncryptedRecord>,
    ) -> Self {
        Self { key_id_salt, records }
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Derives a 32-byte key ID for `key_name` using the store's `key_id_salt`.
///
/// `HMAC-SHA-256(key_id_salt, "SVM-STORE-KEY-V1" ‖ key_name_bytes)` provides:
///
/// - **Collision resistance**: different key names produce different IDs.
/// - **Pre-image resistance**: given an ID, recovering the key name requires
///   knowledge of `key_id_salt` (stored only in the blob header, not in the
///   record itself).
/// - **Domain separation**: the `"SVM-STORE-KEY-V1"` prefix ensures these IDs
///   cannot be confused with any other HMAC usage in this codebase.
fn key_id(salt: &[u8; KEY_ID_SALT_LEN], key_name: &str) -> [u8; KEY_ID_LEN] {
    // Use fully-qualified syntax to disambiguate `new_from_slice` — both
    // `hmac::Mac` and `aes_gcm::aead::KeyInit` define it, and both traits are
    // in scope in this module.
    let mut m = <HmacSha256 as Mac>::new_from_slice(salt)
        .unwrap_or_else(|_| unreachable!("HMAC-SHA-256 accepts any key length"));
    m.update(b"SVM-STORE-KEY-V1");
    m.update(key_name.as_bytes());
    m.finalize().into_bytes().into()
}

/// Rejects passphrases that are too short for meaningful brute-force resistance.
///
/// 12 bytes is the practical floor: short enough not to frustrate callers but
/// long enough that, combined with Argon2id's cost, each wrong-passphrase guess
/// is expensive for an attacker.
fn validate_passphrase(passphrase: &[u8]) -> Result<()> {
    if passphrase.len() < 12 {
        return Err(VmError::InvalidInput(
            "passphrase must be at least 12 bytes".to_string(),
        ));
    }
    Ok(())
}

/// Runs Argon2id on `passphrase` + `salt` to produce a 256-bit AES key.
///
/// **Why Argon2id?** It is the Password Hashing Competition winner (2015) and
/// is resistant to both GPU brute-force and side-channel cache-timing attacks.
/// The `id` variant combines the data-dependent (fast for legitimate use) and
/// data-independent (resistant to cache-timing) memory traversal patterns.
///
/// Cost parameters:
/// - `m = KDF_M_COST` KB of RAM per guess (64 MB default; 128 MB with
///   `store_strong_kdf`), making GPU cracking impractical.
/// - `t = KDF_T_COST` passes (3 default; 4 with `store_strong_kdf`).
/// - `p = 1` lane: single-threaded KDF so the attacker cannot parallelize it.
fn derive_key(passphrase: &[u8], salt: &[u8; SALT_LEN]) -> Result<[u8; KEY_LEN]> {
    let mut key = [0_u8; KEY_LEN];
    let params = Params::new(KDF_M_COST, KDF_T_COST, KDF_LANES, Some(KEY_LEN))
        .map_err(|_| VmError::Crypto)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    argon2
        .hash_password_into(passphrase, salt, &mut key)
        .map_err(|_| VmError::Crypto)?;
    Ok(key)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Passphrase too short must be rejected before any KDF work is started.
    #[test]
    fn short_passphrase_is_rejected() {
        assert!(validate_passphrase(b"11 bytes!!!").is_err()); // 11 bytes — below minimum
        assert!(validate_passphrase(b"12 bytes!!!!").is_ok()); // 12 bytes — at minimum
        assert!(validate_passphrase(b"much longer passphrase here").is_ok());
    }

    /// End-to-end round-trip: two entries with different passphrases serialise
    /// and deserialise correctly. Also confirms that:
    /// 1. Neither plaintext value appears in the blob.
    /// 2. Neither plaintext key name ("alpha", "beta") appears in the blob.
    /// 3. BTreeMap serialisation order is alphabetical (deterministic).
    #[test]
    fn store_roundtrips_two_entries() {
        let mut store = SecureStore::new();
        store.put("beta",  b"secret-beta",  b"passphrase-for-beta" ).unwrap();
        store.put("alpha", b"secret-alpha", b"passphrase-for-alpha").unwrap();

        let blob = store.to_bytes().unwrap();

        // Neither value must appear in plaintext.
        assert!(!blob.windows(b"secret-beta".len()).any(|w| w == b"secret-beta"));
        assert!(!blob.windows(b"secret-alpha".len()).any(|w| w == b"secret-alpha"));

        // Neither key name must appear in plaintext.
        assert!(!blob.windows(4).any(|w| w == b"beta"));
        assert!(!blob.windows(5).any(|w| w == b"alpha"));

        let restored = SecureStore::from_bytes(&blob).unwrap();
        assert_eq!(
            restored.get("alpha", b"passphrase-for-alpha").unwrap(),
            b"secret-alpha"
        );
        assert_eq!(
            restored.get("beta", b"passphrase-for-beta").unwrap(),
            b"secret-beta"
        );
    }

    /// Pinning test: if KDF_M_COST or KDF_T_COST changes, all existing blobs
    /// become permanently unreadable. This test catches the change so the author
    /// is forced to also bump STORE_MAGIC before shipping.
    #[test]
    fn kdf_params_are_pinned() {
        #[cfg(not(feature = "store_strong_kdf"))]
        {
            assert_eq!(KDF_M_COST, 65_536,
                "SecureStore KDF m-cost changed — SVMSTORE03 blobs become unreadable");
            assert_eq!(KDF_T_COST, 3,
                "SecureStore KDF t-cost changed — SVMSTORE03 blobs become unreadable");
        }
        #[cfg(feature = "store_strong_kdf")]
        {
            assert_eq!(KDF_M_COST, 131_072,
                "SecureStore KDF m-cost changed — SVMSTORE04 blobs become unreadable");
            assert_eq!(KDF_T_COST, 4,
                "SecureStore KDF t-cost changed — SVMSTORE04 blobs become unreadable");
        }
        assert_eq!(KDF_LANES, 1);
    }
}
