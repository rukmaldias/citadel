---
id: ci-practices
title: Modern Security Practices and CI/CD
sidebar_position: 11
---

## Continuous Integration pipeline

The project ships with a complete GitHub Actions pipeline in `.github/workflows/ci.yml` that enforces quality on every commit. Understanding each job helps you adapt it to your project.

| Job | What it verifies |
|---|---|
| test (host) | Runs 36 tests without the Android-specific code (`--no-default-features`). Also runs Clippy (Rust's linter with all warnings as errors) and verifies the code compiles with all features. Fast — runs in under 2 minutes. |
| android-build | Cross-compiles for all three ABIs, runs `patch_so`, and verifies the integrity slots are non-zero. Proves the full build pipeline works. |
| android-obfuscated | Same as android-build but with CFF+SUB applied. Runs only on `main` pushes (not PRs) to avoid slowing development feedback. |
| gen-assets-check | Checks that the asset generator still compiles. Catches API changes that break the build tool before they reach production. |
| fuzz-check | Compiles all fuzz targets. Ensures they remain buildable as the code evolves. Actual fuzzing happens in separate scheduled runs. |
| supply-chain | Audits dependencies for known CVEs (RustSec database) and enforces the licence allow-list, source policy, and duplicate-crate ban. |

## Supply-chain security: why it matters

Modern software uses many open-source dependencies. A vulnerability in any dependency becomes a vulnerability in your app. This is called a "supply-chain attack". The project uses two tools:

:::info **cargo-deny**

cargo-deny scans your `Cargo.lock` (which pins every dependency to an exact version) and checks:

- **Licence compliance**: are all dependency licences on the allow-list? (e.g., MIT, Apache 2.0 are allowed; GPL is not)
- **Source policy**: are all dependencies from `crates.io`? No unknown git repos?
- **Duplicate versions**: does the same crate appear twice at different versions? This can cause silent incompatibilities and bloat.

:::

:::info **rustsec/audit-check**

The RustSec Advisory Database (similar to CVE/NVD but Rust-specific) tracks known security vulnerabilities in Rust crates. `audit-check` compares your `Cargo.lock` against the database and fails CI if any dependency has an unpatched vulnerability.

:::

:::note **Dependency hygiene**

- Use `Cargo.lock` in version control for binaries and apps (but not for libraries). This ensures reproducible builds.
- Run `cargo update` periodically and review the diff before merging.
- Use `cargo audit` locally before submitting a PR.
- Configure Dependabot or Renovate to automatically open PRs for dependency updates — this keeps the attack surface small.

:::

## SLSA provenance: what it is and why it matters

SLSA (Supply-chain Levels for Software Artifacts, pronounced "salsa") is a framework for ensuring that build artifacts are produced from the source code you think they are, by the process you think they used.

:::info **SLSA Build Level 2**

At Build Level 2, a trusted build service (here: GitHub Actions) generates a *provenance attestation* — a signed statement that records:

- Which source code commit was built
- Which workflow file ran the build
- What the SHA-256 of the output artifact is

This attestation is signed by the build service using OIDC (not by you), making it unforgeable. Anyone who receives the `.so` artifact can verify that it really was produced from the expected commit by the expected pipeline.

:::

The CI pipeline uses `actions/attest-build-provenance` to attach a SLSA Level 2 attestation to every `.so` artifact on pushes to `main`.

## Key rotation procedures

### Rotating the Ed25519 signing key

1. Generate a new key pair (Step 1 of asset generation).
2. Replace the public key in `src/keys.rs`.
3. Re-generate all three asset files with the new private key.
4. Build and release a new APK version. The new assets will work with the new key. Users on the old APK version will fail to start the VM once the old key's assets expire or are revoked.

### Rotating the Android signing key

1. Extract the DER certificate from the new keystore.
2. Re-generate all three asset files using the new certificate.
3. Re-sign the APK with the new key (using v3 key rotation if your minSdkVersion is ≥ 28, so older users still pass v2 verification).
4. Existing customer data encrypted under the old key's derived session key will be unreadable after key rotation. Decrypt and re-encrypt it (using the old VM session) before rotating if you need to preserve it.

### Rotating the `LICENCE_EMBED_SECRET`

If you suspect the secret has been extracted (e.g., the binary was reverse-engineered), generate a new one and rebuild. All existing licences become invalid (the licence key derivation changes), so you must re-issue licences and push a new APK version.

## Post-quantum readiness note

The **Ed25519** signature algorithm, while widely used and very fast, is vulnerable to Shor's algorithm on a sufficiently powerful quantum computer. The timeline for practical quantum attacks on 128-bit elliptic curves is uncertain (estimates range from 10 to 30+ years), but planning now is prudent.

:::note **Future migration path**

- The Ed25519 call sites are isolated to three files: `firmware.rs::sign_code_assets`, `verify_code_signature`, and `keys.rs::codesign_public_key`.
- When **ML-DSA** (FIPS 204, formerly Dilithium) becomes widely available in Rust crypto libraries, replacing Ed25519 requires touching only these three places.
- The symmetric layer (AES-256-GCM, Argon2id, HMAC-SHA-256) is considered quantum-safe at current key sizes (Grover's algorithm halves effective key length: AES-256 remains at 128 bits effective — still secure).
- No action is required now. Revisit when evaluating deployments with key lifetimes of 10+ years.

:::
