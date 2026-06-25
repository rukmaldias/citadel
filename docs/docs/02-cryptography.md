---
id: cryptography
title: Cryptography Foundations
sidebar_position: 2
---

You do not need to be a mathematician to understand this library. But you do need to understand what each cryptographic building block *does* — even if you do not understand the mathematics behind it. This section gives you exactly that.

## Hash functions — digital fingerprints

:::info **Hash Function (SHA-256)**

A hash function takes data of any size and produces a fixed-size "fingerprint" called a *digest*. SHA-256 always produces exactly 32 bytes. Two key properties:

1. **Deterministic**: the same input always produces the same output.
2. **One-way**: given the output, you cannot recover the input.
3. **Collision-resistant**: it is practically impossible to find two different inputs that produce the same output.

:::

:::tip **Fingerprint at a crime scene**

A fingerprint uniquely identifies a person, but you cannot reconstruct the person from the fingerprint. A hash is the same: it uniquely identifies a file, but you cannot reconstruct the file from the hash. Change even one byte in the file and the hash changes completely.

:::

**How this library uses SHA-256:**

- The SHA-256 of your Android signing certificate is used as input to key derivation (so the key is tied to your specific certificate).
- The SHA-256 of the encrypted firmware bytes is stored in the licence so any modification to the firmware is detected.
- A SHA-256 of the compiled `.so` file is embedded by the `patch_so` tool to detect binary tampering.

## Symmetric encryption — AES-256-GCM

:::info **Symmetric Encryption**

Symmetric encryption uses the same key to both encrypt and decrypt. "AES-256" means the Advanced Encryption Standard with a 256-bit (32-byte) key. "GCM" is an authenticated mode that simultaneously encrypts the data AND produces an authentication tag (16 bytes). If even one bit of the ciphertext is modified, the tag check fails and decryption is rejected.

:::

:::tip **A safe with a combination AND a tamper-evident seal**

AES-256 alone is like a safe: only someone with the combination can open it. GCM adds a tamper-evident seal on the safe door. If anyone has touched the safe since it was last locked, the seal is broken and you know before you even try the combination. This is called *authenticated encryption*: it provides both *confidentiality* (nobody can read the contents) and *integrity* (nobody can modify the contents undetected).

:::

A **nonce** ("number used once") is a random 12-byte value that is included alongside each encryption operation. It ensures that encrypting the same plaintext twice (with the same key) produces different ciphertexts. Reusing a nonce with the same key completely breaks GCM security, so the library goes to great lengths to prevent this.

## Key derivation — Argon2id

:::info **Key Derivation Function (Argon2id)**

A key derivation function (KDF) takes a *password* (arbitrary bytes) and a *salt* (random bytes) and produces a fixed-length key. The important property: it is deliberately *slow* and *memory-intensive*, making brute-force attacks impractical. Argon2id specifically resists both GPU acceleration and side-channel timing attacks by requiring a configurable amount of RAM.

:::

:::tip **A combination lock with a 10-second delay**

An ordinary combination lock can be tried thousands of times per second. An Argon2id-derived key is like a lock that makes you wait 10 seconds between attempts, and also requires a specific amount of physical space to operate. Even if an attacker knows the format of the password, trying all possibilities takes centuries.

:::

This library runs Argon2id three independent times, each producing a different key:

1. A **licence key**: to encrypt/decrypt `licence.bin`.
2. A **firmware key**: to encrypt/decrypt `firmware.bin`.
3. A **customer-data key**: used for encrypting your app's runtime data.

**Parameters used:** m = 65,536 KB of RAM, t = 3 iterations (approximately 0.2 seconds on a modern phone). This makes each key-derivation attempt cost 64 MB of RAM and 0.2 seconds, making brute-force attacks take millions of years.

## Digital signatures — Ed25519

:::info **Digital Signature (Ed25519)**

A digital signature uses a *key pair*: a private key (kept secret by the signer) and a public key (shared freely). The signer uses the private key to produce a 64-byte *signature* over any data. Anyone with the public key can verify that the signature came from the holder of the private key, and that the data has not been modified since signing.

:::

:::tip **A notary stamp**

A notary has a unique stamp that nobody else can replicate. They stamp a document to certify that it is authentic. Anyone can verify that the stamp is genuine (the public key), but only the notary can create the stamp (the private key). If the document is modified after stamping, the verification fails.

:::

Ed25519 specifically uses Curve25519 elliptic curve mathematics. It produces 64-byte signatures, has a 32-byte public key, and is extremely fast to verify. The public key is compiled directly into the `.so` file, so the app can verify signatures without any network call.

## Message authentication codes — HMAC-SHA-256

:::info **HMAC (Hash-based Message Authentication Code)**

An HMAC is like a hash, but with a secret key mixed in. Only someone who knows the key can compute the correct HMAC. It provides *message authentication*: you can verify that a message came from someone who knew the key AND that the message was not modified in transit.

:::

**How this library uses HMAC-SHA-256:**

- An HMAC slot embedded in the `.so` binary is keyed from a `firmware_secret` that only exists inside the encrypted licence. An attacker who patches the binary cannot compute a valid HMAC without first extracting the licence — which requires the original signing cert.
- Key names in the `SecureStore` are replaced with their HMAC values, hiding what data is stored.

## Why these specific primitives?

| Primitive | Why this one |
|---|---|
| AES-256-GCM | The global standard for authenticated symmetric encryption. Hardware acceleration is available on all modern ARM processors via the AES instruction set, so encryption is fast on Android devices. 256-bit key provides post-quantum security margin (Grover's algorithm halves effective key length to 128 bits — still considered secure). |
| Argon2id | Winner of the 2015 Password Hashing Competition. The `id` variant combines Argon2i (data-independent, resists side-channel) and Argon2d (data-dependent, resists GPU). Memory-hardness (configurable RAM requirement) defeats GPU farms which have lots of fast cores but limited RAM per thread. |
| Ed25519 | Designed by Daniel Bernstein (djb), widely reviewed, extremely fast to verify on mobile CPUs. 32-byte public key fits comfortably inside the `.so`. Resistant to common implementation pitfalls like timing attacks and weak RNG. |
| SHA-256 | Part of the SHA-2 family (NIST standard). Used for fingerprinting because it is fast, widely implemented, and considered collision-resistant. |
| HMAC-SHA-256 | HMAC is a well-understood MAC construction that reuses any hash function. HMAC-SHA-256 is standardised (RFC 2104 + FIPS 198), constant-time safe, and available in every crypto library. |

:::warning **Checkpoint**

Before continuing, you should be able to explain in plain words:

- What a hash function does and why modifying data changes the hash
- Why AES-GCM detects tampering even though it is an encryption algorithm
- Why Argon2id is slow on purpose
- The difference between a symmetric key (one key for both parties) and an asymmetric key pair (private key for signing, public key for verification)
- What an HMAC provides that a plain hash does not

:::
