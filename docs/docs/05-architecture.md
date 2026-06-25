---
id: architecture
title: "System Architecture: The Three-Asset Chain of Trust"
sidebar_position: 5
---

## The core idea: a chain you cannot break in the middle

Security systems are only as strong as their weakest link. A naive approach might be to just encrypt the firmware and put the key somewhere in the app. But then an attacker who can read the app's memory (on a rooted phone) simply grabs the key and decrypts the firmware.

This library uses a different approach: a **chain of trust** where each asset is protected by information that only exists inside the previous asset. Breaking the chain at any point — modifying a file, using a different certificate, running on a different device configuration — causes the entire chain to fail.

*Diagram: Three-asset chain of trust — codesign.bin → licence.bin → firmware.bin → VM starts*

**codesign.bin** (72 bytes)

Contains: an Ed25519 *signature* over the SHA-256 hashes of both other files, plus the expected app identity (package name + cert hash). Protected by: the vendor's Ed25519 *private key* (never in the APK). Verified first — cheap, no KDF, catches all tampering before any expensive work.

**licence.bin** (≈ 223 bytes, encrypted)

Contains: identity constraints, firmware hash, `firmware_secret`, `customer_secret`, opcode seed, expiry, debug flags. Protected by: Argon2id key derived from SHA-256(cert) + package name + `LICENCE_EMBED_SECRET`. Only decryptable by the exact app it was issued for.

**firmware.bin** (variable, encrypted)

Contains: VM bytecode (your business logic). Protected by: Argon2id key derived from `firmware_secret` (from licence) + app identity. Useless without the licence; also hash-verified after decryption.

**VM starts executing**

Customer-data key is available. Firmware bytecode runs. Results returned to Kotlin.

## Why this order matters

The verification steps are ordered by computational cost:

1. **Ed25519 signature** (cheap, ≈ 0.1 ms): catches all tampering immediately. If the files were modified or a different certificate is being used, this step fails before any expensive work begins.
2. **Argon2id KDF for licence** (expensive, ≈ 200 ms): only runs after the signature is verified. Derives the licence key from the app's identity.
3. **AES-GCM decrypt licence** (fast): decrypts the licence blob and reads the identity constraints.
4. **Identity validation**: compares the runtime certificate hash and package name against what is stored in the licence.
5. **Argon2id KDF for firmware** (expensive): derives the firmware key from `firmware_secret` inside the now-decrypted licence.
6. **AES-GCM decrypt firmware + SHA-256 verify**: decrypts and verifies.

:::note **Defence in depth**

"Defence in depth" is a security principle: never rely on a single layer of protection. Each layer in this chain catches a different class of attack. The signature catches file tampering. The identity binding catches certificate substitution. The licence embed secret catches offline key computation. The HMAC slot catches binary patching. None of these alone is sufficient; together they form a robust multi-layer defence.

:::

## Attack scenario walkthrough

Let us trace through three common attacks to see exactly which step defeats each one.

### Attack 1: Extract and decrypt firmware offline

An attacker downloads the APK, extracts `firmware.bin`, and tries to decrypt it.

1. To decrypt firmware, they need the firmware key.
2. The firmware key is derived via Argon2id from `firmware_secret`.
3. `firmware_secret` is inside `licence.bin`.
4. To decrypt the licence, they need the licence key.
5. The licence key is derived via Argon2id from SHA-256(cert) + package name + `LICENCE_EMBED_SECRET`.
6. SHA-256(cert) and package name are in the APK. But `LICENCE_EMBED_SECRET` is a 32-byte secret compiled into the `.so` via XOR obfuscation.
7. To obtain `LICENCE_EMBED_SECRET`, the attacker must reverse-engineer the stripped, release-optimised, CFF-obfuscated AArch64 assembly — a highly skilled and time-consuming task.

**Result:** Attack fails unless the attacker invests significant reverse-engineering effort.

### Attack 2: Repackage the APK with a different signing certificate

An attacker repackages the APK with their own signing certificate to bypass Play Store restrictions or licensing checks.

1. The attacker re-signs the APK. The new cert has a different DER encoding.
2. At runtime, the library hashes the actual signing cert: SHA-256(attacker cert) ≠ SHA-256(original cert).
3. The Argon2id computation uses the wrong salt.
4. The derived licence key is completely wrong (a single-bit change in the salt produces a completely different Argon2id output).
5. AES-GCM decryption of the licence fails (wrong key).
6. The library returns `ERROR_INTEGRITY`.

**Result:** Attack fails at step 3.

### Attack 3: Attach a debugger after startup

An attacker starts the app normally, waits for it to initialise (passing all startup checks), then attaches a debugger to dump the decrypted firmware.

1. The VM checks for debuggers at startup AND every 10,000 executed instructions.
2. On Android, `/proc/self/status` exposes a `TracerPid` field that is non-zero when a debugger is attached.
3. Detecting a non-zero `TracerPid`, the VM immediately calls `stop()`, which zeroes all secrets (including the decrypted firmware bytes) and clears the customer-data key.
4. The attacker's debugger is attached to a process that holds no useful secrets.

**Result:** Attack is significantly harder; the attacker must defeat the periodic checks (e.g., by patching the `.so` to skip them — but that would break the HMAC self-integrity check).

## Module architecture

The library is divided into focused modules. Here is what each file does and why that separation exists:

| Module | What it does and why it is separate |
|---|---|
| `src/vm.rs` | The main `SecureVm` type. Controls the lifecycle (start/run/stop), holds the encrypted firmware, dispatches instructions, and coordinates all other modules. Separation: the VM logic should not know how cryptography works, only that it gets a decrypted firmware from `firmware.rs`. |
| `src/firmware.rs` | All asset types and all encryption/decryption. The three Argon2id KDFs live here. Separation: cryptographic logic is isolated so it can be audited independently. A bug in the VM dispatch loop cannot corrupt the KDF; they live in separate modules. |
| `src/bytecode.rs` | Defines the instruction set and serialises/deserialises bytecode. Also implements the per-licence opcode bijection (Fisher-Yates shuffle). Separation: the binary format is defined in one place; changes to the format do not scatter through the codebase. |
| `src/integrity.rs` | SHA-256 and HMAC self-integrity checks on the `.so`. Also contains the ELF parser that finds the RX segment. Separation: security checks that depend on the binary's own content are isolated from the rest. |
| `src/environment.rs` | Anti-analysis: debugger detection, root detection, emulator detection. Separation: all strings used for detection are obfuscated. Keeping them in one place means the obfuscation strategy is consistent. |
| `src/storage.rs` | The `SecureStore` key-value store. Separate from the VM so that the store can be used without starting the VM. |
| `src/wbc.rs` | White-box AES-256 T-table construction and encryption/decryption. Separate so that the complex table-generation code can be replaced without touching the VM. |
| `src/apk.rs` | Reads the APK identity (package name, signing certificate) from native system files instead of using potentially hookable Android APIs. The installer package is read from `PackageManager` in Kotlin and passed to this layer; for `Required`-policy licences it is also mixed into the Argon2id KDF so it is cryptographically binding, not just a policy check. |
| `src/keystore.rs` | Android Keystore JNI calls (key generation, encrypt, decrypt). Separate because Keystore is Android-only and not needed in host tests. |
| `src/jni_api.rs` | All JNI entry points that Kotlin calls. The "bridge" layer that translates between Java types and Rust types. |
