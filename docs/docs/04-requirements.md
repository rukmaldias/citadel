---
id: requirements
title: Requirements
sidebar_position: 4
---

## Build-time requirements

These are the tools you need on your development machine (or in CI) to build and deploy the library.

| Requirement | Why it is needed |
|---|---|
| Rust stable (≥ 1.75) | The programming language the library is written in. 2021 edition features are used. Install via `rustup.rs`. |
| Rust nightly (≥ 1.79) | Required only for the obfuscated build. The `-Z llvm-plugins` flag (which loads the CFF/SUB obfuscation pass into the compiler) is only available in the unstable nightly channel. Install alongside stable: `rustup toolchain install nightly`. |
| Android NDK r25+ | The "Native Development Kit" provides the C toolchain for cross-compiling Rust code that targets Android. Without the NDK, the Rust compiler cannot produce `.so` files for Android. Download via Android Studio's SDK Manager or `sdkmanager "ndk;27.0.12077973"`. |
| `cargo-ndk` | A Cargo (Rust's build tool) plugin that wraps the NDK configuration, automatically setting the correct linker and sysroot for each ABI. Without it, you must manually configure many environment variables. Install: `cargo install cargo-ndk`. |
| Android Rust targets | Rust needs pre-compiled standard library components for each CPU architecture you want to target. Install all three: `rustup target add aarch64-linux-android` `armv7-linux-androideabi x86_64-linux-android`. |
| LLVM dev headers | Required only for building the obfuscation plugin from source. Must match the LLVM major version bundled with your `rustc`. The build script detects and installs this automatically on Ubuntu/Debian. |
| `pdflatex` | Only needed to re-generate this document or the technical reference. |

## Understanding CPU architectures (ABIs)

Android devices use different CPU types. You must build the library for each one:

| ABI | Rust target | Device type |
|---|---|---|
| `arm64-v8a` | `aarch64-linux-android` | Modern phones (2014+) |
| `armeabi-v7a` | `armv7-linux-androideabi` | Older 32-bit ARM phones |
| `x86_64` | `x86_64-linux-android` | Android emulator |

:::note **Multi-ABI builds**

Always build all three ABIs. Shipping only `arm64-v8a` leaves out users on older devices. Shipping only `armeabi-v7a` means your 64-bit users get the slower 32-bit library. The build tools support building all three in one command.

:::

## Runtime requirements

| Requirement | Detail |
|---|---|
| Android 7.0+ (API 24) | Minimum version to guarantee APK Signature Scheme v2 (required for certificate extraction). Android 9+ enables v3 (key rotation support), probed first at runtime. |
| `jni` feature flag | The library is designed to also work in non-Android Rust environments (for testing). The JNI entry points (the functions Kotlin can call) are only compiled when the `jni` Cargo feature is enabled. Android builds always enable it. |
| Three asset files | `licence.bin`, `firmware.bin`, `codesign.bin` must be present in the APK's `assets/` directory. |
| Android Keystore (optional) | The customer-data AES-256 key is stored in hardware (StrongBox or TEE) if available. The white-box AES-256 fallback is used otherwise. Hardware Keystore is available on almost all Android devices manufactured since 2016. |

## Cargo feature flags explained

Cargo (Rust's package manager) has a feature flag system that lets you conditionally compile different code. This library uses feature flags as an extra layer of defence:

| Feature | What it does and why you want it in production |
|---|---|
| `jni` | Enables all JNI entry points. Must be enabled for Android builds. Without it, the `.so` exports no symbols that Kotlin can call. |
| `enforce_patch` | Makes the SHA-256 self-integrity check *fail loudly* if the all-zero placeholder is still there. Without `enforce_patch`, an unpatched `.so` (where `patch_so` was never run) silently passes. This is a safety net against forgetting to run `patch_so` in CI. |
| `enforce_embed_secret` | Makes key derivation return an error if `LICENSE_EMBED_SECRET` is still the all-zero placeholder. Forces you to replace the placeholder before shipping. |
| `enforce_codesign_key` | Returns an error at startup if the Ed25519 public key in `src/keys.rs` is still the all-zero placeholder. |
| `store_strong_kdf` | Doubles the Argon2id cost for `SecureStore`: 128 MB RAM / 4 iterations instead of 64 MB / 3. Makes brute-force even harder, at the cost of slightly longer unlock time (≈ 0.4s vs 0.2s on a mid-range phone). |

:::danger

Always build production releases with **all four enforce flags**: `--features jni,enforce_patch,enforce_embed_secret,enforce_codesign_key`. These flags are off by default because they would fail on the placeholder values shipped in the repository. When you install real secrets and keys, turn them all on.

:::
