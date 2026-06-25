//! White-box AES-256 with key-embedded T-tables.
//!
//! The customer-data key is never stored as a raw byte array. Instead it is
//! absorbed into 256-entry lookup tables during license generation; those tables
//! perform AES-256 encryption without the key being directly readable as a
//! contiguous byte sequence in memory.
//!
//! ## Table structure
//!
//! AES-256 has 14 rounds. The first 13 are "full" rounds that combine
//! SubBytes + ShiftRows + MixColumns + AddRoundKey into four T-tables of 256
//! u32 entries each. Round 14 omits MixColumns and uses a simpler table of 256
//! u8 entries per state byte position. Together these are called `enc_lut` (13
//! rounds × 16 state-byte positions × 256 u32 entries) and `enc_fin` (16 state
//! positions × 256 u8 entries).
//!
//! The initial AddRoundKey (round key 0) is pre-absorbed into the round-0
//! tables; round key `r+1` is pre-absorbed into the row-0 tables for round `r`.
//! An attacker who inspects the tables sees 256-entry mappings with no key
//! bytes present as a contiguous sequence — the key material is only recoverable
//! through knowledge of the AES T-table structure.
//!
//! ## Encryption mode
//!
//! Both directions use AES-256-CTR (counter mode), which is symmetric: the same
//! `encrypt_block` call generates the keystream for both encryption and
//! decryption. Only the forward-cipher tables are therefore needed.
//!
//! ## Authenticated encryption (format v2)
//!
//! CTR alone provides confidentiality but no integrity. `SVMWBC02` blobs use
//! Encrypt-then-MAC with HMAC-SHA-256:
//!
//! - Counter blocks 0–1 (32 bytes of keystream) are reserved as the MAC key.
//! - Counter blocks 2+ are used for encryption.
//! - The MAC covers `magic ‖ nonce ‖ ciphertext` and is appended as the last 32 bytes.
//!
//! Output format: `[SVMWBC02 (8)][nonce (12)][ciphertext][HMAC-SHA-256 (32)]`.
//!
//! ## Known limitations
//!
//! The T-table construction follows the Chow et al. 2002 scheme without external
//! encodings. The Billet-Gilbert-Ech-Chatbi (BGE) 2004 attack can recover the
//! embedded AES-256 key from the published table entries in approximately 2³²
//! operations using only offline analysis of the table data — no running process
//! is required. HMAC authentication prevents third-party blob tampering but does
//! not protect the key from algebraic extraction. Mitigating BGE requires adding
//! random bijective encodings at every table boundary (the full Chow scheme),
//! which is a significant cryptographic redesign. This limitation is accepted:
//! the WBC path is a defence-in-depth fallback for devices without a hardware
//! Keystore; the hardware Keystore path provides a properly isolated key.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::{Result, VmError};

type HmacSha256 = Hmac<Sha256>;
const HMAC_LEN: usize = 32;

// ── AES constants ─────────────────────────────────────────────────────────────

#[rustfmt::skip]
const SBOX: [u8; 256] = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
];

// AES-256 key schedule round constants: RCON[k] = 2^(k-1) mod 0x11b.
// Used at words W[8], W[16], ..., W[56] (i.e. RCON[i/8] for i in {8,16..56}).
const RCON: [u8; 7] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40];

// AES block size (16 bytes = 128 bits).
const BLOCK: usize = 16;
// Number of full (MixColumns) T-table rounds for AES-256.
// AES-256 has 14 rounds total; the last is "final" (no MixColumns).
const NR_FULL: usize = 13;
// Total round key material: 15 × 16-byte round keys (NR+1 for AES-256).
const NR_KEYS: usize = 15;
// Flat index stride: NR_FULL rounds × BLOCK positions per round.
const LUT_ENTRIES: usize = NR_FULL * BLOCK;

// ── GF(2^8) ───────────────────────────────────────────────────────────────────

// Multiply by 2 (xtime) in GF(2^8) with irreducible polynomial 0x11b.
#[inline(always)]
const fn xtime(b: u8) -> u8 {
    (b << 1) ^ (if b & 0x80 != 0 { 0x1b } else { 0 })
}

// ── AES-256 key schedule ──────────────────────────────────────────────────────

// Expands a 32-byte key into 15 round keys of 16 bytes each (60 32-bit words).
// Round keys are stored in column-major byte order: rk[r][c*4..c*4+4] holds the
// 4 bytes of column c in big-endian (row 0 = MSB).
fn key_schedule(key: &[u8; 32]) -> [[u8; BLOCK]; NR_KEYS] {
    let mut w = [0u32; 60];
    for i in 0..8 {
        w[i] = u32::from_be_bytes([
            key[4 * i],
            key[4 * i + 1],
            key[4 * i + 2],
            key[4 * i + 3],
        ]);
    }
    for i in 8..60 {
        let mut temp = w[i - 1];
        if i % 8 == 0 {
            // RotWord (left-rotate one byte) + SubWord + XOR round constant.
            temp = temp.rotate_left(8);
            let [b0, b1, b2, b3] = temp.to_be_bytes();
            temp = u32::from_be_bytes([
                SBOX[b0 as usize],
                SBOX[b1 as usize],
                SBOX[b2 as usize],
                SBOX[b3 as usize],
            ]);
            // RCON is XORed with the MSB (byte 0 of big-endian u32).
            temp ^= (RCON[i / 8 - 1] as u32) << 24;
        } else if i % 8 == 4 {
            // SubWord only (AES-256 extra half-key step).
            let [b0, b1, b2, b3] = temp.to_be_bytes();
            temp = u32::from_be_bytes([
                SBOX[b0 as usize],
                SBOX[b1 as usize],
                SBOX[b2 as usize],
                SBOX[b3 as usize],
            ]);
        }
        w[i] = w[i - 8] ^ temp;
    }
    let mut rk = [[0u8; BLOCK]; NR_KEYS];
    for r in 0..NR_KEYS {
        for j in 0..4 {
            rk[r][j * 4..j * 4 + 4].copy_from_slice(&w[r * 4 + j].to_be_bytes());
        }
    }
    rk
}

// ── T-table construction ──────────────────────────────────────────────────────

// Builds the base encryption T-table T0.
// T0[a] = [2·S(a), S(a), S(a), 3·S(a)] as a little-endian u32.
// T1–T3 are 8/16/24-bit right-rotations of T0 and are computed inline.
fn make_t0() -> [u32; 256] {
    let mut t = [0u32; 256];
    for (i, entry) in t.iter_mut().enumerate() {
        let s = SBOX[i];
        let x2 = xtime(s);
        let x3 = x2 ^ s;
        // LE byte layout: [row0=2s, row1=s, row2=s, row3=3s].
        *entry = u32::from_le_bytes([x2, s, s, x3]);
    }
    t
}

// ── WBC table generation ──────────────────────────────────────────────────────

// AES state uses column-major order: byte b = col*4 + row.
// For b in 0..16: row = b % 4, col = b / 4.
// After ShiftRows (row i shifted left by i), input at (row, col) contributes
// to output column (col - row + 4) % 4.

fn build_enc_lut(
    rk: &[[u8; BLOCK]; NR_KEYS],
    t0: &[u32; 256],
) -> crate::memguard::LockedPage<[[u32; 256]; LUT_ENTRIES]> {
    // Allocate via mmap to avoid a 208 KB stack frame. MAP_ANONYMOUS pages are
    // always zero-initialised by the kernel, so the zeroed state is valid here.
    let mut lut: crate::memguard::LockedPage<[[u32; 256]; LUT_ENTRIES]> =
        unsafe { crate::memguard::LockedPage::new_zeroed() };

    for r in 0..NR_FULL {
        for b in 0..BLOCK {
            let row = b % 4;
            let col = b / 4;
            let out_col = (col + 4 - row) % 4;

            // For r == 0, absorb the initial AddRoundKey (rk[0]) into the
            // table's input XOR so the raw input to encrypt_block is the
            // plaintext with no pre-applied key.
            let in_key: u8 = if r == 0 { rk[0][b] } else { 0 };

            // The round key for T-table round r is rk[r+1]. To avoid storing
            // the round key separately, absorb it into the row-0 table only
            // (the four row-0 positions per output column collectively carry
            // the full round key column as a LE u32).
            let out_key: u32 = if row == 0 {
                u32::from_le_bytes([
                    rk[r + 1][out_col * 4],
                    rk[r + 1][out_col * 4 + 1],
                    rk[r + 1][out_col * 4 + 2],
                    rk[r + 1][out_col * 4 + 3],
                ])
            } else {
                0
            };

            let table = &mut lut[r * BLOCK + b];
            #[allow(clippy::needless_range_loop)] // x is used as both index and plaintext byte value
            for x in 0usize..256 {
                let idx = (x as u8 ^ in_key) as usize;
                let tv = match row {
                    0 => t0[idx],
                    1 => t0[idx].rotate_right(24), // Te1=[3s,2s,s,s]: byte3→byte0
                    2 => t0[idx].rotate_right(16), // Te2=[s,3s,2s,s]
                    3 => t0[idx].rotate_right(8),  // Te3=[s,s,3s,2s]: byte3→byte2
                    _ => unreachable!(),
                };
                table[x] = tv ^ out_key;
            }
        }
    }
    lut
}

fn build_enc_fin(rk: &[[u8; BLOCK]; NR_KEYS]) -> crate::memguard::LockedPage<[[u8; 256]; BLOCK]> {
    // Final round: SubBytes + ShiftRows + AddRoundKey (no MixColumns).
    // For input position b, the output lands at out_col*4 + row after ShiftRows.
    let mut fin: crate::memguard::LockedPage<[[u8; 256]; BLOCK]> =
        unsafe { crate::memguard::LockedPage::new_zeroed() };

    for b in 0..BLOCK {
        let row = b % 4;
        let col = b / 4;
        let out_col = (col + 4 - row) % 4;
        let out_pos = out_col * 4 + row;
        let key_byte = rk[14][out_pos];
        for x in 0usize..256 {
            fin[b][x] = SBOX[x] ^ key_byte;
        }
    }
    fin
}

// ── Public API ────────────────────────────────────────────────────────────────

/// White-box AES-256 tables.
///
/// The 256-bit customer-data key is absorbed into these tables at license
/// generation time and is never stored as a raw byte array at runtime. Any
/// number of AES-256-CTR encrypt or decrypt operations can be performed using
/// only these tables — no key material lives outside them.
pub struct WbcAes256Tables {
    /// 13 full-round T-tables: NR_FULL × BLOCK × 256 u32 entries ≈ 208 KB.
    /// Stored on mlock'd mmap pages; switched to PROT_READ after construction.
    enc_lut: crate::memguard::LockedPage<[[u32; 256]; LUT_ENTRIES]>,
    /// Final-round S-box+key tables: BLOCK × 256 u8 entries = 4 KB.
    /// Stored on mlock'd mmap pages; switched to PROT_READ after construction.
    enc_fin: crate::memguard::LockedPage<[[u8; 256]; BLOCK]>,
}

impl std::fmt::Debug for WbcAes256Tables {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WbcAes256Tables").finish_non_exhaustive()
    }
}

impl WbcAes256Tables {
    /// Generates WBC tables from a 256-bit AES key.
    ///
    /// The key is consumed into the tables and not retained anywhere in the
    /// returned struct. The caller should zeroize the key after this call.
    pub fn generate(key: &[u8; 32]) -> Self {
        let rk = key_schedule(key);
        let t0 = make_t0();
        let enc_lut = build_enc_lut(&rk, &t0);
        let enc_fin = build_enc_fin(&rk);
        let mut tables = Self { enc_lut, enc_fin };
        // Switch to PROT_READ: tables are never written after construction.
        tables.enc_lut.protect();
        tables.enc_fin.protect();
        tables
    }

    /// Encrypts a single 16-byte AES block using the embedded key (ECB mode).
    ///
    /// This is the primitive used by both `encrypt_with_nonce` and `decrypt` —
    /// CTR mode is symmetric so both directions call the forward cipher only.
    pub fn encrypt_block(&self, block: &[u8; BLOCK]) -> [u8; BLOCK] {
        let mut state = *block;

        // 13 full rounds: each state byte is looked up, its u32 contribution
        // is accumulated per output column, then the columns are written back.
        for r in 0..NR_FULL {
            let mut cols = [0u32; 4];
            #[allow(clippy::needless_range_loop)] // b used as both index and ShiftRows position
            for b in 0..BLOCK {
                let row = b % 4;
                let col = b / 4;
                let out_col = (col + 4 - row) % 4;
                cols[out_col] ^= self.enc_lut[r * BLOCK + b][state[b] as usize];
            }
            for c in 0..4 {
                state[c * 4..c * 4 + 4].copy_from_slice(&cols[c].to_le_bytes());
            }
        }

        // Final round: one input byte produces one output byte (no MixColumns).
        let mut output = [0u8; BLOCK];
        #[allow(clippy::needless_range_loop)] // b used as both index and ShiftRows position
        for b in 0..BLOCK {
            let row = b % 4;
            let col = b / 4;
            let out_col = (col + 4 - row) % 4;
            let out_pos = out_col * 4 + row;
            output[out_pos] = self.enc_fin[b][state[b] as usize];
        }
        output
    }

    /// Encrypts `plaintext` in authenticated AES-256-CTR mode (Encrypt-then-MAC).
    ///
    /// Counter blocks 0–1 supply the 32-byte HMAC-SHA-256 key; blocks 2+ encrypt.
    /// Returns `[SVMWBC02 (8)][nonce (12)][ciphertext][HMAC (32)]`.
    /// Nonce uniqueness is the caller's responsibility; `vm.rs` uses a monotonic
    /// counter.
    pub fn encrypt_with_nonce(&self, plaintext: &[u8], nonce: &[u8; 12]) -> Result<Vec<u8>> {
        let mut mac_key = derive_mac_key(self, nonce);
        let mut out = Vec::with_capacity(WBC_MAGIC.len() + 12 + plaintext.len() + HMAC_LEN);
        out.extend_from_slice(WBC_MAGIC);
        out.extend_from_slice(nonce);
        // Encrypt starting at counter block 2; blocks 0-1 are the MAC key.
        ctr_xor(self, plaintext, nonce, 2, &mut out);
        // MAC covers magic ‖ nonce ‖ ciphertext so an attacker cannot forge any field.
        let tag = compute_hmac(&mac_key, &out);
        mac_key.zeroize();
        out.extend_from_slice(&tag);
        Ok(out)
    }

    /// Decrypts a blob produced by [`encrypt_with_nonce`].
    ///
    /// Verifies the HMAC-SHA-256 tag in constant time before decrypting.
    /// Expects `[SVMWBC02 (8)][nonce (12)][ciphertext][HMAC (32)]`.
    ///
    /// # Errors
    ///
    /// Returns `InvalidPackage` if the magic bytes are wrong. Returns `Crypto`
    /// if the blob is too short or the authentication tag does not match
    /// (including bit-flip, truncation, or wrong key).
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let min_len = WBC_MAGIC.len() + 12 + HMAC_LEN;
        if ciphertext.len() < min_len {
            return Err(VmError::Crypto);
        }
        if !ciphertext.starts_with(WBC_MAGIC) {
            return Err(VmError::InvalidPackage("WBC magic mismatch".to_string()));
        }
        let nonce: &[u8; 12] = ciphertext[8..20].try_into().map_err(|_| VmError::Crypto)?;
        let mut mac_key = derive_mac_key(self, nonce);

        // Split: [magic‖nonce‖ciphertext] | [HMAC tag]
        let tag_start = ciphertext.len() - HMAC_LEN;
        let expected_tag = &ciphertext[tag_start..];
        let blob_to_mac = &ciphertext[..tag_start];

        let actual_tag = compute_hmac(&mac_key, blob_to_mac);
        mac_key.zeroize();
        // Constant-time comparison prevents timing oracles.
        if !bool::from(actual_tag.ct_eq(expected_tag)) {
            return Err(VmError::Crypto);
        }

        let ct = &ciphertext[20..tag_start];
        let mut out = Vec::with_capacity(ct.len());
        ctr_xor(self, ct, nonce, 2, &mut out);
        Ok(out)
    }

    /// Serialises the tables to a flat byte buffer.
    ///
    /// Layout: `[enc_lut entries as LE u32][enc_fin entries as raw bytes]`.
    /// Total uncompressed size ≈ 217 KB. Intended to be zlib-compressed before
    /// embedding in `license.bin`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let lut_bytes = LUT_ENTRIES * 256 * 4;
        let fin_bytes = BLOCK * 256;
        let mut out = Vec::with_capacity(lut_bytes + fin_bytes);
        for table in self.enc_lut.iter() {
            for &v in table.iter() {
                out.extend_from_slice(&v.to_le_bytes());
            }
        }
        for table in self.enc_fin.iter() {
            out.extend_from_slice(table);
        }
        out
    }

    /// Deserialises tables produced by [`to_bytes`].
    ///
    /// Returns `None` if the byte slice is not exactly the expected length
    /// (`LUT_ENTRIES * 256 * 4 + BLOCK * 256` bytes).
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        let expected = LUT_ENTRIES * 256 * 4 + BLOCK * 256;
        if data.len() != expected {
            return None;
        }

        let mut enc_lut: crate::memguard::LockedPage<[[u32; 256]; LUT_ENTRIES]> =
            unsafe { crate::memguard::LockedPage::new_zeroed() };
        let mut pos = 0usize;
        for table in enc_lut.iter_mut() {
            for v in table.iter_mut() {
                *v = u32::from_le_bytes([
                    data[pos],
                    data[pos + 1],
                    data[pos + 2],
                    data[pos + 3],
                ]);
                pos += 4;
            }
        }

        let mut enc_fin: crate::memguard::LockedPage<[[u8; 256]; BLOCK]> =
            unsafe { crate::memguard::LockedPage::new_zeroed() };
        for table in enc_fin.iter_mut() {
            table.copy_from_slice(&data[pos..pos + 256]);
            pos += 256;
        }

        let mut tables = Self { enc_lut, enc_fin };
        tables.enc_lut.protect();
        tables.enc_fin.protect();
        Some(tables)
    }
}

impl Zeroize for WbcAes256Tables {
    fn zeroize(&mut self) {
        // LockedPage::zeroize() unprotects the page before zeroing, so these
        // calls are safe even after protect() was applied post-construction.
        self.enc_lut.zeroize();
        self.enc_fin.zeroize();
    }
}

/// Magic bytes that prefix every WBC-encrypted customer-data blob (format v2).
pub(crate) const WBC_MAGIC: &[u8; 8] = b"SVMWBC02";

// ── CTR mode ──────────────────────────────────────────────────────────────────

// Counter block format: [nonce (12 bytes)][block_counter as LE u32 (4 bytes)].
// Matches the IETF AES-GCM counter layout; compatible with ChaCha20 nonces.
//
// `start_block`: the first counter value to use. Blocks 0–1 are reserved for
// MAC key derivation (see `derive_mac_key`); encryption starts at block 2.
fn ctr_xor(tables: &WbcAes256Tables, data: &[u8], nonce: &[u8; 12], start_block: u32, out: &mut Vec<u8>) {
    let mut counter_block = [0u8; BLOCK];
    counter_block[..12].copy_from_slice(nonce);

    let nblocks = data.len() / BLOCK;
    let remainder = data.len() % BLOCK;

    for i in 0..nblocks {
        counter_block[12..].copy_from_slice(&(start_block + i as u32).to_le_bytes());
        let ks = tables.encrypt_block(&counter_block);
        for k in 0..BLOCK {
            out.push(data[i * BLOCK + k] ^ ks[k]);
        }
    }
    if remainder > 0 {
        counter_block[12..].copy_from_slice(&(start_block + nblocks as u32).to_le_bytes());
        let ks = tables.encrypt_block(&counter_block);
        for k in 0..remainder {
            out.push(data[nblocks * BLOCK + k] ^ ks[k]);
        }
    }
}

// Derives a 32-byte MAC key from counter blocks 0 and 1 with the given nonce.
// These two blocks are never used for payload encryption.
fn derive_mac_key(tables: &WbcAes256Tables, nonce: &[u8; 12]) -> [u8; 32] {
    let mut counter_block = [0u8; BLOCK];
    counter_block[..12].copy_from_slice(nonce);

    counter_block[12..].copy_from_slice(&0u32.to_le_bytes());
    let b0 = tables.encrypt_block(&counter_block);
    counter_block[12..].copy_from_slice(&1u32.to_le_bytes());
    let b1 = tables.encrypt_block(&counter_block);

    let mut key = [0u8; 32];
    key[..16].copy_from_slice(&b0);
    key[16..].copy_from_slice(&b1);
    key
}

// Computes HMAC-SHA-256 over `data` with `key` and returns the 32-byte tag.
fn compute_hmac(key: &[u8; 32], data: &[u8]) -> [u8; HMAC_LEN] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // NIST SP 800-38A AES-256-CBC test vector, block 1 with IV=0.
    // CBC block 1 with all-zero IV is identical to ECB for that block.
    #[test]
    fn aes256_ecb_nist_vector() {
        let key = hex::decode(
            "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
        )
        .unwrap();
        let pt = hex::decode("6bc1bee22e409f96e93d7e117393172a").unwrap();
        let expected = hex::decode("f3eed1bdb5d2a03c064b5a7e3db181f8").unwrap();

        let key_arr: [u8; 32] = key.try_into().unwrap();
        let pt_arr: [u8; 16] = pt.try_into().unwrap();
        let tables = WbcAes256Tables::generate(&key_arr);
        let ct = tables.encrypt_block(&pt_arr);
        assert_eq!(&ct, expected.as_slice());
    }

    #[test]
    fn ctr_roundtrip() {
        let key = [0x42u8; 32];
        let nonce = [0x11u8; 12];
        let plaintext = b"the quick brown fox jumps over the lazy dog 12345678";

        let tables = WbcAes256Tables::generate(&key);
        let ct = tables.encrypt_with_nonce(plaintext, &nonce).unwrap();
        let recovered = tables.decrypt(&ct).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn hmac_authentication_rejects_tampering() {
        let key = [0x55u8; 32];
        let nonce = [0x22u8; 12];
        let plaintext = b"sensitive payload";

        let tables = WbcAes256Tables::generate(&key);
        let mut ct = tables.encrypt_with_nonce(plaintext, &nonce).unwrap();

        // Flip a byte in the ciphertext body (past magic + nonce = 20 bytes).
        ct[20] ^= 0xFF;

        assert!(
            tables.decrypt(&ct).is_err(),
            "tampered ciphertext must be rejected"
        );
    }

    #[test]
    fn hmac_authentication_rejects_tag_truncation() {
        let key = [0x55u8; 32];
        let nonce = [0x22u8; 12];
        let plaintext = b"sensitive payload";

        let tables = WbcAes256Tables::generate(&key);
        let ct = tables.encrypt_with_nonce(plaintext, &nonce).unwrap();

        // Drop the last byte of the HMAC tag — blob is too short.
        let truncated = &ct[..ct.len() - 1];
        assert!(
            tables.decrypt(truncated).is_err(),
            "truncated tag must be rejected"
        );
    }

    #[test]
    fn serialise_roundtrip() {
        let key = [0x77u8; 32];
        let tables = WbcAes256Tables::generate(&key);
        let bytes = tables.to_bytes();
        let tables2 = WbcAes256Tables::from_bytes(&bytes).unwrap();

        let block = [0xabu8; 16];
        assert_eq!(tables.encrypt_block(&block), tables2.encrypt_block(&block));
    }
}
