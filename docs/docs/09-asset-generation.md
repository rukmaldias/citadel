---
id: asset-generation
title: "Asset Generation: Step-by-Step Walkthrough"
sidebar_position: 9
---

This section is your practical guide. Follow these steps in order the first time you set up the system.

## Overview of what you will produce

*Diagram: Asset generation flow — Generate Ed25519 key pair (Step 1) → Extract signing certificate (Step 2) → Write firmware bytecode (Step 3) → Run gen_assets (Step 4) → produces licence.bin, firmware.bin, codesign.bin*

## Step 1: Generate an Ed25519 key pair

This is a one-time operation per product. Generate it on a secure machine and **never commit the private key to version control**.

```rust
// tools/keygen/src/main.rs
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

fn main() {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    // Private key: 32 bytes (64 hex chars). Store in a password manager or HSM.
    eprintln!("PRIVATE: {}", hex::encode(signing_key.to_bytes()));
    // Public key: 32 bytes (64 hex chars). Paste into src/keys.rs.
    println!("PUBLIC:  {}", hex::encode(verifying_key.to_bytes()));
}
```

:::note **Key storage best practices**

- Store the private key in a **Hardware Security Module (HSM)** for maximum security (e.g., AWS CloudHSM, Google Cloud HSM).
- As a minimum, store it in your CI provider's encrypted secret store (GitHub Secrets, GitLab Variables). These are encrypted at rest and only exposed to specific pipelines.
- **Never** put it in a `.env` file that might accidentally be committed. Add `*.env` and `*.key` to `.gitignore`.
- Consider key ceremony procedures: generate the key on an air-gapped machine, split the output between two trusted parties (Shamir's Secret Sharing), and document the process formally.

:::

## Step 2: Extract the release signing certificate

```bash
# -rfc produces PEM (base64); omit for raw DER bytes
keytool -export \
  -keystore release.keystore \
  -alias your-key-alias \
  -file release-signing-cert.der

# Check what you got:
openssl x509 -in release-signing-cert.der -inform DER -noout -subject
```

:::info

The DER bytes of your certificate are *not* secret. They are inside every APK you ship. You need them at asset-generation time so the library can compute the correct SHA-256 and derive the matching licence key.

:::

## Step 3: Write your firmware

Firmware is expressed as Rust code using the library types. The asset generator internally calls this code:

```rust
use secure_android_vm::{Instruction, OpcodeTable, Program};

// A simple example: return 1 if a >= 0, else return 0
// (imagine "a" is loaded from a register set by the Kotlin caller)
fn build_firmware(opcode_seed: &[u8; 32]) -> Vec<u8> {
    let program = Program::new(vec![
        // Push a threshold value
        Instruction::PushI64(0),
        // Load "a" from register 0 (set externally before run())
        Instruction::Load(0),
        // Stack: [0, a]. Compute a >= 0 as (NOT (a < 0))
        Instruction::Lt,        // stack: [a < 0] = 0 or 1
        // Negate: NOT(a < 0) = a >= 0
        // NOT of boolean: XOR with 1
        Instruction::PushI64(1),
        Instruction::Xor,       // stack: [a >= 0]
        Instruction::Halt,
    ]).expect("valid program");

    // Apply per-licence opcode shuffling if seed is non-zero
    let table = OpcodeTable::from_seed(opcode_seed);
    program.to_bytes_with_table(&table)
}
```

## Step 4: Prepare licensepack.json and run gen_assets

```
{
  "key":              "a3f7b2c1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1",
  "value":            "9e4d0f8a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8",
  "cert":             "308201f03082015aa003...",
  "id":               "com.yourcompany.yourapp",
  "installer_policy": "required:com.android.vending",
  "valid_until":      1893456000,
  "firmware_flags":   0
}
```

| Field | Explanation |
|---|---|
| key (32 B) | The **firmware_secret**: a 32-byte random value you generate with `openssl rand -hex 32`. This is the Argon2id input for the firmware encryption key. Keep it secret — print it to stderr in CI and store it in your secrets manager. |
| value (32 B) | The **customer_secret**: another 32-byte random value. This is the Argon2id input for the customer-data encryption key. |
| cert (hex bytes) | The DER bytes of your release signing certificate. *Not* secret; these are extracted in Step 2. They are SHA-256'd and used as the Argon2id salt for licence key derivation. |
| id | Your package identifier string, e.g., `com.yourcompany.yourapp`. Mixed into the Argon2id password so a licence for one package cannot decrypt content intended for another. |
| installer_policy | `"required:com.android.vending"` for production (Play Store only). `"any"` for development or sideload-only deployments. For `required` licences the installer name is also mixed into the Argon2id KDF (licence key derivation domain `v4`): a wrong installer at runtime produces the wrong key and AES-GCM authentication fails — no plaintext is ever produced. **Note:** `"any"` uses an empty string in the KDF, so it is compatible with sideload/unknown installers only; Play Store installs (`"com.android.vending"`) produce a non-empty installer string and will fail to decrypt an `"any"`-policy licence. Use `required` for all app-store distributions. |
| valid_until (u64) | Unix timestamp for licence expiry. `0` = never expires. For limited licences: `date -d "2030-01-01" +%s` gives you the Unix timestamp. |
| firmware_flags (u32) | Bit 0 = VM debug mode. Set to `1` during development to get per-instruction tracing in logcat. Always `0` in production. |

```bash
# Make your private key available
export CODESIGN_PRIVATE_KEY="<64-char hex from Step 1>"

# Place licensepack.json in the current directory, then:
cargo run --manifest-path tools/gen_assets/Cargo.toml

# Output to stderr (keep out of CI logs):
#   FIRMWARE_SECRET=ab4fab5e...    <- save this for patch_so
#   OPCODE_SEED=2df96741...        <- stored in licence; no action needed
#   firmware_flags=0 (release mode)
#
# Output to stdout:
#   Assets written:
#     licence.bin  (223 bytes)
#     firmware.bin  (46 bytes)
#     codesign.bin  (72 bytes)
#   Copy them to android-app/app/src/main/assets/
```

:::danger

The `FIRMWARE_SECRET` printed to stderr must be captured and stored. You will need it in Step 5 to patch the `.so` integrity slots. If you lose it, you must regenerate all assets (new licence, new firmware, new codesign files). Never let it appear in CI log output — use your CI provider's secret masking.

:::

## Step 5: Set the secrets in the .so source code

**Set the LICENSE\_EMBED\_SECRET in `src/firmware.rs`:**

```bash
openssl rand -hex 32
# e.g.: a3f712e48b92c01d...
```

```rust
// Find this in derive_license_key():
let embed: [u8; 32] = *obfstr::obfbytes!(
    // BEFORE: all zeros (placeholder, intentionally weak)
    b"\x00\x00\x00\x00\x00\x00\x00\x00\
      \x00\x00\x00\x00\x00\x00\x00\x00\
      \x00\x00\x00\x00\x00\x00\x00\x00\
      \x00\x00\x00\x00\x00\x00\x00\x00"
    // AFTER: your 32 random bytes
    // b"\xa3\xf7\x12\xe4..."
);
```

**Set the Ed25519 public key in `src/keys.rs`:**

```rust
pub(crate) fn codesign_public_key() -> [u8; 32] {
    *obfstr::obfbytes!(
        // Replace the 32 zeros with your 32-byte Ed25519 public key
        b"\x1a\x2b\x3c\x4d\x5e\x6f\x70\x81\
          \x92\xa3\xb4\xc5\xd6\xe7\xf8\x09\
          \x1a\x2b\x3c\x4d\x5e\x6f\x70\x81\
          \x92\xa3\xb4\xc5\xd6\xe7\xf8\x09"
    )
}
```

## Step 6: Compile the native library

```bash
# Standard release build:
cargo ndk \
  -t arm64-v8a -t armeabi-v7a -t x86_64 \
  -o android-app/app/src/main/jniLibs \
  build --release \
  --features jni,enforce_patch,enforce_embed_secret,enforce_codesign_key

# Output directory after build:
# android-app/app/src/main/jniLibs/
#   arm64-v8a/libsecure_android_vm.so      (876 KB typical)
#   armeabi-v7a/libsecure_android_vm.so    (680 KB typical)
#   x86_64/libsecure_android_vm.so         (1.1 MB typical)
```

## Step 7: Patch the .so integrity slots

```bash
export FIRMWARE_SECRET="<64-char hex from Step 4>"

for ABI in arm64-v8a armeabi-v7a x86_64; do
    cargo run --bin patch_so -- \
        android-app/app/src/main/jniLibs/$ABI/libsecure_android_vm.so \
        $FIRMWARE_SECRET
done

# Expected output for each ABI:
# patched: android-app/.../libsecure_android_vm.so
#   sha256: 3a9f...   (SHA-256 of ELF RX segment, with slots zeroed)
#   hmac:   b2c1...   (HMAC-SHA-256 keyed from firmware_secret)
#   rx segment: offset=0x1000 size=0x4a000
```

:::info

**Why does the HMAC cover only the RX segment and not the full file?** The ELF "read-execute" segment contains code (`.text`) and read-only data (`.rodata`). After the dynamic linker loads the `.so`, it applies "relocations" to the read-write segment (`.got`, `.bss`) to fix up addresses for the specific load address. These relocations would change the file bytes, causing the hash to fail. Covering only the RX segment avoids this problem.

:::

## Step 8: Copy assets to the Android project

```bash
cp licence.bin firmware.bin codesign.bin \
   android-app/app/src/main/assets/
```

| Asset file | Contents |
|---|---|
| `licence.bin` | Magic `SVMENC01` + 12-byte nonce + AES-GCM ciphertext |
| `firmware.bin` | Magic `SVMENC01` + 12-byte nonce + AES-GCM ciphertext |
| `codesign.bin` | Magic `SVMSIG01` + 64-byte Ed25519 signature (r\|\|s) |

:::warning **Checkpoint**

After completing Steps 1--8, you should have:

- A private key stored securely (never in the APK)
- The public key embedded in `src/keys.rs`
- The licence embed secret embedded in `src/firmware.rs`
- Three asset files in `app/src/main/assets/`
- Three patched `.so` files in `app/src/main/jniLibs/<ABI>/`

If any of these is missing, the VM will fail to start.

:::
