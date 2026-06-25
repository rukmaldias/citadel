# Secure Android VM

A Rust library that embeds a small, protected virtual machine into an Android app. The VM executes encrypted firmware that is cryptographically bound to your app's signing identity — the firmware cannot be extracted from the APK, run in a different app, or tampered with without detection.

**Full technical reference:** [`documentation`](https://rukmaldias.github.io/citadel) — covers requirements, security architecture, design, implementation, LLVM obfuscation layer, asset generation, usage, CI pipeline, and binary blob format specifications.

---

## Table of Contents

1. [How the security works](#how-the-security-works)
2. [Prerequisites](#prerequisites)
3. [Build overview](#build-overview)
4. [Step 1 — Generate an Ed25519 key pair](#step-1--generate-an-ed25519-key-pair)
5. [Step 2 — Write your firmware](#step-2--write-your-firmware)
6. [Step 3 — Get your release signing certificate](#step-3--get-your-release-signing-certificate)
7. [Step 4 — Generate the encrypted asset files](#step-4--generate-the-encrypted-asset-files)
8. [Step 5 — Build the native library](#step-5--build-the-native-library)
   - [5a — Embed the Ed25519 public key](#5a--embed-the-ed25519-public-key)
   - [5b — Set the LICENSE_EMBED_SECRET](#5b--set-the-license_embed_secret)
   - [5c — Compile and copy the .so](#5c--compile-and-copy-the-so)
   - [5d — Patch the .so integrity slots](#5d--patch-the-so-integrity-slots)
   - [5e — Obfuscated build (optional hardening)](#5e--obfuscated-build-optional-hardening)
9. [Step 6 — Set up the Android project](#step-6--set-up-the-android-project)
10. [Step 7 — Use the VM in Kotlin](#step-7--use-the-vm-in-kotlin)
11. [VM debug mode](#vm-debug-mode)
12. [Customer data encryption](#customer-data-encryption)
13. [Secure secret storage](#secure-secret-storage)
14. [Persisting secrets across launches](#persisting-secrets-across-launches)
15. [VM instruction set reference](#vm-instruction-set-reference)
16. [Security considerations](#security-considerations)
17. [Rust API notes](#rust-api-notes)

---

## How the security works

Three files live in the APK's `assets/` folder and form a strict chain of trust:

```
Your Ed25519 private key (NEVER in the APK)
        │
        ▼
codesign.bin  ──► Ed25519 signature over (app identity + license hash + firmware hash)
                           │
                           ▼  verified first; any tampering detected here
license.bin   ──► AES-256-GCM encrypted
                  Key derived via Argon2id from: SHA-256(cert) + package name + embed secret
                  Contains: identity constraints + firmware hash + 2 × 32-byte secrets
                           │
                           ▼  decrypted only if identity matches
firmware.bin  ──► AES-256-GCM encrypted
                  Key derived via Argon2id from: firmware_secret (from license) + identity
                  Contains: VM bytecode
                           │
                           ▼  decrypted only if license valid and firmware hash matches
                  VM starts — bytecode executes
```

| Attack | Why it fails |
|---|---|
| Extract `firmware.bin` and decrypt it | Key requires `firmware_secret` from inside `license.bin`, which requires the original signing cert |
| Modify `firmware.bin` | Ed25519 signature in `codesign.bin` covers the firmware hash — tampered bytes fail before decryption |
| Re-sign the APK with a different certificate | License key derivation uses `SHA-256(cert)` — different cert → different key → decryption fails |
| Sideload the APK | `InstallerPolicy::Required("com.android.vending")` in the license rejects other install sources |
| Attach a debugger | Six independent checks (TracerPid, wchan, process status, maps patterns, LD_PRELOAD, emulator fingerprints) block startup; all detection strings are obfuscated |
| Compute the license key offline | A 32-byte vendor secret (`LICENSE_EMBED_SECRET`, XOR-obfuscated in the `.so`) is appended to the Argon2id password — the attacker must reverse-engineer the binary first |
| Patch the `.so` binary | SHA-256 + HMAC-SHA-256 slots (embedded by `patch_so`) cover the ELF RX segment; HMAC is keyed from `firmware_secret` and cannot be forged without the license |

---

## Prerequisites

| Tool | Version | Purpose |
|---|---|---|
| [Rust](https://rustup.rs) stable | ≥ 1.75 | Build the library, gen_assets, patch_so |
| Rust nightly | ≥ 1.79 | Obfuscated build only (`-Z llvm-plugins`) |
| Android NDK | r25+ (r27 recommended) | C toolchain for cross-compilation |
| [`cargo-ndk`](https://github.com/bbqsrc/cargo-ndk) | latest | Handles NDK paths automatically |
| Android Studio | any | Build and sign the Android app |
| LLVM dev headers | matches rustc's LLVM | Build the obfuscator plugin (obfuscated build only) |

```sh
# Add Android targets (stable)
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android

# Add Android targets (nightly, for obfuscated builds)
rustup toolchain install nightly
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android \
    --toolchain nightly

# Install cargo-ndk
cargo install cargo-ndk
```

---

## Build overview

```
[Build machine / CI]                          [Android device]

Generate Ed25519 key pair
        │
        ├─ private key → store securely (never in APK)
        └─ public key  → paste into src/keys.rs (compiled into .so)

Prepare licensepack.json
(key, value, cert, id, installer_policy, valid_until, firmware_flags)
        │
        ▼
cargo run --manifest-path tools/gen_assets/Cargo.toml
        │
        ├─ license.bin  ──┐
        ├─ firmware.bin ──┼──► copy to app/src/main/assets/
        └─ codesign.bin ──┘
        │
        ▼
cargo ndk ... build --release --features jni
        │
        └──► libsecure_android_vm.so (one per ABI)
        │
        ▼
cargo run --bin patch_so -- <path/to/.so> <firmware_secret>
        │
        └──► patched .so  ──► copy to app/src/main/jniLibs/<ABI>/
        │
        ▼
Build & sign APK ─────────────────────────────► Install & run
                                                 VM verifies assets at startup
```

---

## Step 1 — Generate an Ed25519 key pair

The Ed25519 private key signs the asset bundle at build time. It must never be in the APK — only the 32-byte public key is compiled into the `.so`.

```rust
// keygen/src/main.rs  (standalone binary outside this crate)
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

fn main() {
    let signing_key = SigningKey::generate(&mut OsRng);
    println!("Private: {}", hex::encode(signing_key.to_bytes()));
    println!("Public:  {}", hex::encode(signing_key.verifying_key().to_bytes()));
}
```

Store the private key in a secrets manager or HSM. Note the public key hex — you will embed it in `src/keys.rs` in [Step 5a](#5a--embed-the-ed25519-public-key).

> **Security:** Treat the Ed25519 private key with the same care as your Android release signing keystore. Anyone who holds it can produce firmware your app will accept.

---

## Step 2 — Write your firmware

Firmware is a `Program` — a sequence of `Instruction` values. The VM is a stack machine; all values are `i64`. The top-of-stack value when `Halt` executes is returned as the result.

```rust
use secure_android_vm::{Instruction, Program};

let firmware_bytes = Program::new(vec![
    Instruction::PushI64(40),
    Instruction::PushI64(2),
    Instruction::Add,
    Instruction::Halt,           // result = 42
])?
.to_bytes();
```

For a per-license opcode remapping table (see [VM instruction set reference](#vm-instruction-set-reference)):

```rust
let table = OpcodeTable::from_seed(&opcode_seed);
let firmware_bytes = program.to_bytes_with_table(&table);
```

Maximum program size: `MAX_PROGRAM_LEN = 1_000_000` instructions.

---

## Step 3 — Get your release signing certificate

```sh
keytool -export \
  -keystore release.keystore \
  -alias your-key-alias \
  -file release-signing-cert.der
```

The certificate is not secret (it is inside every signed APK), but you need the raw DER bytes at asset-generation time so the license key derivation uses the correct salt.

> **Always use the release certificate.** Assets generated with a debug certificate will not work with a release-signed APK.

---

## Step 4 — Generate the encrypted asset files

### 4a — Create `licensepack.json`

| Field | Type | Description |
|---|---|---|
| `key` | 64 hex chars | **`firmware_secret`** — Argon2id input for the AES-256 firmware key |
| `value` | 64 hex chars | **`customer_secret`** — Argon2id input for the customer data key |
| `cert` | hex bytes | DER-encoded signing certificate bytes (SHA-256'd as the Argon2id salt) |
| `id` | string | Package/customer identifier mixed into the Argon2id password |
| `installer_policy` | string | `"required:com.android.vending"` (production) or `"any"` (dev) |
| `valid_until` | u64 | Unix timestamp expiry (0 = never expires) |
| `firmware_flags` | u32 | Behaviour flags: bit 0 = VM debug mode (0 = production) |

Production example:

```json
{
  "key":              "a3f7b2c1d4e5f6...",
  "value":            "9e4d0f8a1b2c3d...",
  "cert":             "308201...",
  "id":               "com.yourcompany.yourapp",
  "installer_policy": "required:com.android.vending",
  "valid_until":      1893456000,
  "firmware_flags":   0
}
```

Generate the 32-byte secrets: `openssl rand -hex 32`

> **Never commit `licensepack.json` with real values to version control.**

### 4b — Run the asset generator

```sh
export CODESIGN_PRIVATE_KEY="<64-char hex from Step 1>"
cargo run --manifest-path tools/gen_assets/Cargo.toml
```

Output to **stderr** (keep out of CI logs):
```
FIRMWARE_SECRET=ab4fab5e...    <- pass to patch_so in Step 5d
OPCODE_SEED=2df96741...        <- stored inside the encrypted license
firmware_flags=0 (release mode)
```

Copy the three binary files to your Android project:
```sh
cp license.bin firmware.bin codesign.bin android-app/app/src/main/assets/
```

> Regenerate all three files whenever you update firmware logic, rotate the signing key, change the package name, change the installer policy, or upgrade to a library version that bumps the KDF domain (e.g. `v3` → `v4`). Files from different generations are cryptographically incompatible and cannot be mixed.

---

## Step 5 — Build the native library

### 5a — Embed the Ed25519 public key

Open `src/keys.rs` and replace the placeholder bytes with the 32-byte public key from Step 1:

```rust
pub(crate) fn codesign_public_key() -> [u8; 32] {
    *obfstr::obfbytes!(
        b"\x1a\x2b\x3c\x4d..."  // your 32 bytes here
    )
}
```

The key is XOR-obfuscated at compile time by `obfstr::obfbytes!` — no raw key bytes appear in `.rodata`.

### 5b — Set the `LICENSE_EMBED_SECRET`

Generate 32 random bytes and embed them in `src/firmware.rs` inside `derive_license_key()`:

```sh
openssl rand -hex 32   # → a3f712e4...
```

```rust
let embed: [u8; 32] = *obfstr::obfbytes!(
    b"\xa3\xf7\x12\xe4..."  // your 32 bytes as \xNN escapes
);
```

This secret is appended to the Argon2id password, preventing offline license-key computation from APK-observable inputs alone. Enable `enforce_embed_secret` to get a runtime error if the all-zero placeholder is still present.

> **Never commit the real secret to version control.** Store it as a CI secret.

### 5c — Compile and copy the `.so`

```sh
cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 \
  -o android-app/app/src/main/jniLibs \
  build --release \
  --features jni,enforce_patch,enforce_embed_secret,enforce_codesign_key
```

The four production features:
- `jni` — exports all JNI entry points and Keystore integration
- `enforce_patch` — makes an unpatched `.so` fail at startup (not silently pass)
- `enforce_embed_secret` — runtime error if `LICENSE_EMBED_SECRET` is still all-zero placeholder
- `enforce_codesign_key` — runtime error if Ed25519 public key is still all-zero placeholder

### 5d — Patch the `.so` integrity slots

After every build, run `patch_so` for each ABI to embed the self-integrity digests:

```sh
export FIRMWARE_SECRET="<64-char hex from Step 4>"

for ABI in arm64-v8a armeabi-v7a x86_64; do
    cargo run --bin patch_so -- \
        android-app/app/src/main/jniLibs/$ABI/libsecure_android_vm.so \
        $FIRMWARE_SECRET
done
```

The tool embeds two 32-byte slots into the ELF RX segment:
- **SHA-256 slot** (`SVMHASH\x00`): hash of the RX segment with both slots zeroed — checked before any Argon2id work
- **HMAC-SHA-256 slot** (`SVMHMAC\x00`): keyed from `firmware_secret` — cryptographically binding; cannot be forged without the license

> Run `patch_so` after **every** rebuild. With `enforce_patch` enabled the VM will refuse to start if the slots are all-zero.

### 5e — Obfuscated build (optional hardening)

The obfuscated build applies two LLVM IR transformation passes to every compiled function:

- **Control Flow Flattening (CFF)**: replaces structured control flow (loops, conditionals) with a flat dispatcher switch, hiding the true execution path from static analysis
- **Instruction Substitution (SUB)**: replaces arithmetic and bitwise operations with logically equivalent but less recognisable sequences (`a + b` → `a - (~b) - 1`, etc.)

```sh
# One-time: build the LLVM plugin (matches rustc's LLVM version automatically)
bash scripts/build_obfuscator.sh

# Build each ABI with CFF + SUB applied:
ANDROID_NDK_HOME=/path/to/ndk \
    bash scripts/build_android_obfuscated.sh arm64-v8a 26

ANDROID_NDK_HOME=/path/to/ndk \
    bash scripts/build_android_obfuscated.sh armeabi-v7a 26

ANDROID_NDK_HOME=/path/to/ndk \
    bash scripts/build_android_obfuscated.sh x86_64 26
```

The obfuscated build uses the `release-obfuscated` Cargo profile (`codegen-units = 1`, `lto = thin`) and requires Rust nightly (`-Z llvm-plugins` is a nightly-only flag). The CI `android-obfuscated` job automates this on every push to `main`.

After the obfuscated build, run `patch_so` exactly as in Step 5d (the slots are in the same positions regardless of whether CFF/SUB was applied).

---

## Step 6 — Set up the Android project

Copy the Kotlin wrapper and update the package declaration:

```sh
cp android/SecureVm.kt \
   android-app/app/src/main/java/com/yourcompany/yourapp/SecureVm.kt
```

Update the first line: `package com.yourcompany.yourapp`

Also update the JNI export names in `src/jni_api.rs` (every function prefixed `Java_com_example_securevm_SecureVm_`) to match your package, then rebuild the `.so`.

Expected project structure after Steps 4–6:

```
android-app/app/src/main/
├── assets/
│   ├── license.bin       ← Step 4
│   ├── firmware.bin      ← Step 4
│   └── codesign.bin      ← Step 4
├── jniLibs/
│   ├── arm64-v8a/
│   │   └── libsecure_android_vm.so   ← Steps 5c–5d (or 5e)
│   ├── armeabi-v7a/
│   │   └── libsecure_android_vm.so
│   └── x86_64/
│       └── libsecure_android_vm.so
└── java/com/yourcompany/yourapp/
    └── SecureVm.kt       ← Step 6
```

---

## Step 7 — Use the VM in Kotlin

```kotlin
import com.yourcompany.yourapp.SecureVm

fun runSecureVm(context: Context) {
    SecureVm().use { vm ->
        when (vm.startFromAssets(context)) {
            SecureVm.START_OK          -> { /* proceed */ }
            SecureVm.ERROR_ENVIRONMENT -> throw SecurityException("Hostile environment")
            SecureVm.ERROR_INTEGRITY   -> throw SecurityException("Asset tampered")
            SecureVm.ERROR_LICENSE     -> throw SecurityException("License invalid")
            SecureVm.ERROR_FIRMWARE    -> throw SecurityException("Firmware corrupt")
            else                       -> throw SecurityException("VM failed to start")
        }

        val result: Long = vm.run()   // throws RuntimeException on VM error
        Log.d("VM", "Firmware result: $result")

        vm.stop()
    }
    // close() called automatically; all secrets zeroized
}
```

| Constant | Value | Meaning |
|---|---|---|
| `START_OK` | 0 | All checks passed; VM is running |
| `ERROR_INVALID_INPUT` | 1 | A required argument was null or empty |
| `ERROR_INTEGRITY` | 2 | Ed25519 signature failed, or wrong magic/GCM tag |
| `ERROR_LICENSE` | 3 | License valid but identity mismatch (cert, package, installer) |
| `ERROR_FIRMWARE` | 4 | Firmware decrypted but unparseable |
| `ERROR_ENVIRONMENT` | 5 | Debugger, root, or emulator detected |
| `ERROR_UNKNOWN` | 99 | Unexpected internal error |

---

## VM debug mode

Set `firmware_flags: 1` in `licensepack.json` to enable per-instruction tracing. Every instruction emits a `[SVM-DEBUG]` line to **stderr** (desktop) or **logcat** (Android):

```
[SVM-DEBUG] step=     1 pc=    0 instr=PushI64(42)  stack_depth=0
[SVM-DEBUG]        => TOS=42
[SVM-DEBUG] step=     2 pc=    1 instr=Halt  stack_depth=1
[SVM-DEBUG] HALT  result=42 steps=2
```

The flag is embedded inside the encrypted license at asset-generation time — it cannot be set at runtime without re-issuing the license. `stop()` clears it, so a subsequent `startFromAssets` with a non-debug license starts clean.

> **Never ship production assets with `firmware_flags: 1`.** The trace exposes every intermediate computation value to logcat and slows execution.

---

## Customer data encryption

After `startFromAssets` returns `START_OK`, the VM holds a session-scoped AES-256-GCM key. Encrypt preference values or database columns without the key ever appearing in Kotlin:

```kotlin
SecureVm().use { vm ->
    vm.startFromAssets(context)

    val ciphertext: ByteArray = vm.encryptData("my-secret-value".toByteArray())
        ?: throw SecurityException("Encryption failed")

    val plaintext: ByteArray = vm.decryptData(ciphertext)
        ?: throw SecurityException("Decryption failed")

    vm.stop()
}
```

- Store only the ciphertext. Never store the key — it is re-derived on every successful `startFromAssets`.
- `encryptData`/`decryptData` return `null` if the VM is not in the `Running` state.
- The key is cleared from memory when `stop()` or `close()` is called.

The key is stored in the most secure form the device supports: Android Keystore (StrongBox → TEE) when available, falling back to white-box AES-256 T-tables (see [security considerations](#security-considerations) for the BGE attack caveat).

---

## Secure secret storage

```kotlin
val passphrase = derivePassphraseFromKeystore()

vm.storeSecret("api_token", tokenBytes, passphrase)

val token: ByteArray = vm.loadSecret("api_token", passphrase)
    ?: throw SecurityException("Secret not found or wrong passphrase")
```

Key names are never stored in plaintext. Each name is hashed to a 32-byte HMAC-SHA-256 key ID (`HMAC(key_id_salt, "SVM-STORE-KEY-V1" || name)`) before storage — an attacker who reads the blob learns only ciphertext sizes and count.

> In production, derive the passphrase through the Android Keystore so it is hardware-backed and never appears as a plain string in source code.

---

## Persisting secrets across launches

```kotlin
// In onStop() / onPause() — export BEFORE calling vm.stop()
val storeBlob: ByteArray = vm.exportStore()
    ?: throw RuntimeException("Failed to export store")
prefs.edit()
    .putString("secure_store", Base64.encodeToString(storeBlob, Base64.NO_WRAP))
    .apply()
vm.stop()

// On next launch — import AFTER startFromAssets() succeeds
val encoded = prefs.getString("secure_store", null)
if (encoded != null) {
    vm.importStore(Base64.decode(encoded, Base64.NO_WRAP))
}
```

The exported blob contains only ciphertext, salts, nonces, and HMAC-derived key IDs — **no plaintext key names or values**. Safe to write to `SharedPreferences` or a database column.

---

## VM instruction set reference

The VM is a **stack machine** with 16 `i64` registers (indices 0–15). All arithmetic uses checked operations — overflow and divide-by-zero return errors rather than wrapping or panicking.

**Arithmetic**

| Instruction | Opcode | Stack effect | Description |
|---|---|---|---|
| `PushI64(n)` | `0x01` | `→ n` | Push 64-bit signed literal |
| `Add` | `0x02` | `a b → a+b` | Checked addition |
| `Sub` | `0x03` | `a b → a-b` | Checked subtraction |
| `Mul` | `0x04` | `a b → a×b` | Checked multiplication |
| `Div` | `0x05` | `a b → a÷b` | Checked division; errors on zero |
| `Mod` | `0x08` | `a b → a%b` | Remainder; errors on zero |

**Registers**

| Instruction | Opcode | Stack effect | Description |
|---|---|---|---|
| `Store(r)` | `0x06` | `v →` | Pop and write to register `r` (0–15) |
| `Load(r)` | `0x07` | `→ v` | Push register `r` value |

**Comparison** — push `1` (true) or `0` (false)

| Instruction | Opcode | Stack effect |
|---|---|---|
| `Eq` | `0x09` | `a b → (a==b)` |
| `Lt` | `0x0A` | `a b → (a<b)` |
| `Gt` | `0x0B` | `a b → (a>b)` |

**Bitwise**

| Instruction | Opcode | Stack effect |
|---|---|---|
| `And` | `0x0C` | `a b → (a&b)` |
| `Or` | `0x0D` | `a b → (a\|b)` |
| `Xor` | `0x0E` | `a b → (a^b)` |
| `Shl` | `0x0F` | `v n → (v<<n)` — `n` must be 0–63 |
| `Shr` | `0x10` | `v n → (v>>n)` — arithmetic; `n` must be 0–63 |
| `Not` | `0x11` | `v → (~v)` |

**Stack manipulation**

| Instruction | Opcode | Stack effect |
|---|---|---|
| `Dup` | `0x12` | `v → v v` |
| `Pop` | `0x13` | `v →` |

**Control flow** — target is a `u32` LE absolute instruction index

| Instruction | Opcode | Stack effect | Description |
|---|---|---|---|
| `Jmp(t)` | `0x20` | — | Unconditional jump |
| `JmpIf(t)` | `0x21` | `cond →` | Jump if `cond != 0` |
| `JmpIfNot(t)` | `0x22` | `cond →` | Jump if `cond == 0` |
| `Call(t)` | `0x23` | — | Push return address; jump to `t`. Max depth: 256 |
| `Ret` | `0x24` | — | Pop call stack; return to caller |

**Termination**

| Instruction | Opcode | Description |
|---|---|---|
| `Halt` | `0xFF` | Stop; return top-of-stack (or 0 if empty) |

**Execution limits:**
- Steps per `run()`: 100,000 (configurable via `set_max_steps`)
- Evaluation stack depth: 1,024 values (~8 KiB)
- Call stack depth: 256 frames
- Program size: 1,000,000 instructions maximum

**Example — compute `(10 - 3) * 6`:**

```rust
Program::new(vec![
    Instruction::PushI64(10),
    Instruction::PushI64(3),
    Instruction::Sub,        // stack: [7]
    Instruction::PushI64(6),
    Instruction::Mul,        // stack: [42]
    Instruction::Store(0),   // register[0] = 42, stack: []
    Instruction::Load(0),    // stack: [42]
    Instruction::Halt,       // result = 42
])
```

**Per-license opcode bijection:** Each license may carry a 32-byte `opcode_seed`. A non-zero seed generates a Fisher-Yates shuffle of the 25 opcode bytes, so one customer's `firmware.bin` cannot be parsed with another customer's VM. The seed lives inside the encrypted license and is never exposed to Kotlin.

---

## Security considerations

### What this library protects

- Firmware bytecode from extraction and reverse engineering
- The firmware decryption key — requires `firmware_secret` from inside the encrypted license
- The license from being used with a re-signed or sideloaded APK
- The license key from offline computation — a vendor-held 32-byte `LICENSE_EMBED_SECRET` (XOR-obfuscated in the `.so`) must be extracted before the key can be computed
- The `.so` from byte-level patching — SHA-256 + HMAC-SHA-256 integrity slots cover the ELF RX segment; the HMAC cannot be forged without the license

### White-box AES and the BGE attack (known limitation)

When the device has no hardware Keystore (StrongBox or TEE), the customer-data key is stored inside Chow-style AES-256 T-tables. The **Billet-Gilbert-Ech-Chatbi (BGE) 2004 attack** can recover the embedded key from the table bytes in approximately 2³² offline operations — no running process is required.

| Device class | Customer-data key protection |
|---|---|
| Android with StrongBox (Pixel 3+, Galaxy S10+) | Key never leaves secure hardware — BGE irrelevant |
| Android with TEE only (most devices, Android 6+) | Key never leaves TrustZone — BGE irrelevant |
| Devices where both Keystore paths fail (rare) | White-box AES used — BGE applies |

The white-box path is a defence-in-depth fallback. For high-value use cases combine this library with the Play Integrity API and server-side key issuance.

### What this library does not protect

- **The Ed25519 private key** — if this leaks, an attacker can produce firmware your app will accept
- **A rooted device** — root access allows process-memory dumps after startup
- **The firmware result** — `vm.run()` returns a plain `Long`; the result is not encrypted
- **The customer-data key on devices without hardware Keystore** — see BGE section above

### Recommended complementary measures

| Measure | Benefit |
|---|---|
| [Play Integrity API](https://developer.android.com/google/play/integrity) | Server-side attestation that the APK is genuine and the device is not compromised |
| Android Keystore (StrongBox) | Hardware-backed key storage for the `storeSecret` passphrase |
| Server-issued licenses | Rotate licenses without a new APK; revoke licenses for compromised installations |
| `valid_until` in `licensepack.json` | Limit how long a captured `license.bin` remains useful |

### Key rotation

If you rotate your Android release signing key:
1. Re-generate all three asset files using the **new** signing certificate (Step 4).
2. Re-issue any licenses bound to the old certificate.
3. Re-encrypt any existing customer data before rotation (it was encrypted under the old key's derived session key and becomes unreadable after rotation).

---

## Rust API notes

### `encrypt_customer_data` requires `&mut self`

The nonce counter is stored inside `SecureVm`. As a result `encrypt_customer_data` takes `&mut self` and cannot be called through a shared reference. The JNI layer handles this automatically via `Mutex<SecureVm>`.

### Nonce counter exhaustion

Each session allows up to `u32::MAX` (~4.3 × 10⁹) calls to `encrypt_customer_data`. The counter resets to zero and the 8-byte session prefix rotates on every `stop()` call, preventing cross-session nonce reuse.

### `compress_customer_data_tables`

If you pre-generate white-box AES-256 table blobs as part of a build-time workflow, use:

```rust
use secure_android_vm::{compress_customer_data_tables, WbcAes256Tables};

let tables: WbcAes256Tables = /* ... */;
let blob: Vec<u8> = compress_customer_data_tables(&tables)?;
// Embed blob in license via FirmwareLicense::with_wbc_tables
```

### Secure store key-name privacy

`SecureStore` serializes HMAC-derived key IDs, not key names. The blob starts with `SVMSTORE03` (default Argon2id cost) or `SVMSTORE04` (`store_strong_kdf` feature, 128 MB / 4 iterations). Older `SVMSTORE01`/`SVMSTORE02` blobs (which stored plaintext key names) are not readable by this version.

### License format versioning

The license binary starts with magic `SVMLIC04`. Assets must be regenerated with `tools/gen_assets` whenever the library version changes the magic. Prior versions `SVMLIC01`–`SVMLIC03` are incompatible.
