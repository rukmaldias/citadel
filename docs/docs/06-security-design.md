---
id: security-design
title: Security Design Decisions
sidebar_position: 6
---

This section explains not just *what* the design is, but *why* each choice was made.

## Why AES-GCM instead of AES-CBC?

AES-CBC (Cipher Block Chaining) is an older encryption mode. It provides confidentiality but not integrity: an attacker can flip bits in the ciphertext and the decryption will succeed (producing corrupted plaintext) without any error.

AES-GCM (Galois/Counter Mode) is an *authenticated* mode. The 16-byte authentication tag mathematically covers every byte of the ciphertext. Changing even one bit of the ciphertext causes the tag check to fail, and decryption is rejected before any output is produced.

:::tip **Voting booth vs sealed ballot box**

AES-CBC is like a voting booth: people can submit votes, but someone with access could change them after the fact. AES-GCM is like a sealed ballot box with a tamper indicator: if anyone touches the box after sealing, the seal is broken and the box is rejected. In security terms, always prefer *authenticated encryption*.

:::

## Why Argon2id and not SHA-256 for key derivation?

A common beginner mistake is to derive a key by doing `SHA-256(password)`. This is fast — which is the problem. SHA-256 can be computed billions of times per second on a modern GPU. An attacker who knows the format of the password can try every possibility in seconds.

Argon2id intentionally uses 64 MB of RAM and takes 0.2 seconds per attempt. On a GPU with 4 GB of VRAM shared across 3,000 cores, each core gets only ≈ 1.3 MB — not enough to even run Argon2id with our parameters. This limits an attacker to the speed of a CPU, not a GPU, effectively removing the GPU advantage.

## The nonce design: prefix + counter

A nonce must never be reused with the same key. Two approaches:

- **Fully random nonce** (12 bytes from OsRng each time): simple but has a "birthday bound" problem. With enough encryptions, two random nonces will eventually collide. The probability reaches 1% after about 2^47 encryptions (≈ 140 trillion) — far beyond any realistic session, but mathematically non-zero.
- **Monotonic counter** (12 bytes that increment each time): no birthday bound, but resets to zero when the counter wraps. If the counter wraps and the key is reused, nonces repeat.
- **Prefix + counter** (this library's approach): 8 random bytes generated once per session (the prefix), plus a 4-byte counter. The prefix eliminates cross-session reuse (it rotates on every `stop()`), the counter eliminates within-session birthday collisions. The counter saturates at `u32::MAX` (≈ 4.3 × 10^9) and returns an error rather than wrapping.

## The licence embed secret: defeating offline key computation

The inputs to the licence KDF are:

- SHA-256(signing certificate) — in every APK
- Package name — in the `AndroidManifest.xml` of every APK

Both are public. An attacker who knows them can run Argon2id themselves and derive the same licence key in 0.2 seconds. The licence embed secret addresses this:

```rust
// embed is 32 secret bytes compiled into the .so via XOR-obfuscation.
// An attacker needs to reverse-engineer the binary to find them.
let password = format!("SVM-LICENSE-KEY-V1:{}:{}", pkg_id, embed_hex);
let key = Argon2id::hash_password_into(&password, &sha256_cert_salt);
```

This forces the attacker to first reverse-engineer the stripped, obfuscated, release-optimised AArch64 binary to find the 32 secret bytes before they can even start the Argon2id computation.

## Domain separation: why every key has a prefix

If multiple HMAC or Argon2id calls used the same inputs, an attacker could take output from one context and use it in another. Domain separation prevents this by mixing a unique label into every derivation:

| Label | Used for |
|---|---|
| `SVM-LICENSE-KEY-V1` | Licence key derivation |
| `SVM-FIRMWARE-KEY-V1` | Firmware key derivation |
| `SVM-CUSTOMER-KEY-V1` | Customer-data key derivation |
| `SVM-SO-INTEGRITY-V1` | HMAC slot key derivation |
| `SVM-STORE-KEY-V1` | SecureStore key-ID derivation |
| `SVM-CODESIGN-PAYLOAD-V1` | Ed25519 signed payload prefix |

Because each label is unique, the output from one context cannot be substituted into another. This is a standard practice in cryptographic protocol design (see NIST SP 800-108).

## Customer-data key storage: hardware first

The 32-byte customer-data key is stored differently depending on device hardware:

*Diagram: Key storage hierarchy — StrongBox (1st choice) → TEE/TrustZone (2nd choice) → White-box AES-256 (Fallback)*

**StrongBox** — Dedicated security chip (Pixel 3+, Galaxy S10+). Key *never* leaves the chip.

**TEE (TrustZone)** — Isolated hardware execution environment. Key never leaves TrustZone. Available on most Android 6+ devices.

**White-box AES-256** — Key absorbed into T-tables in heap memory. Software fallback; see BGE attack caveat below.

:::info **White-Box Cryptography**

In normal cryptography, the key and the algorithm are separate. In white-box cryptography, the key is *embedded* into the algorithm tables so that the key cannot be easily read out of memory. The "white-box" name comes from the assumption that the attacker can see all memory (a fully open or "white" box). The construction used here (Chow-style T-tables) absorbs a 32-byte AES key into a set of lookup tables. An attacker who dumps memory sees the tables, not a 32-byte key.

:::

:::danger

**Known limitation: The BGE (Billet-Gilbert-Ech-Chatbi) attack** from 2004 can recover the embedded AES key from Chow-style T-tables in approximately 2^32 offline operations — roughly 30--60 minutes on a modern workstation. This is a known, published limitation of the construction. The hardware Keystore path (StrongBox or TEE) is completely immune to this attack because the key never leaves hardware. The white-box path is a defence-in-depth fallback, not a primary protection. On the vast majority of devices (Android 6+), the hardware path is used.

:::
