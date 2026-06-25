---
id: android-security
title: Android Security Basics
sidebar_position: 3
---

## The APK file format

An Android Package (APK) is a ZIP archive. Inside it you will find:

```
MyApp.apk/
  AndroidManifest.xml    <- app metadata (package name, permissions, ...)
  classes.dex            <- compiled Kotlin/Java bytecode (DEX format)
  lib/
    arm64-v8a/
      libmyapp.so        <- native C/C++/Rust code compiled for ARM64
  assets/
    myfile.bin           <- any arbitrary files bundled with the app
  META-INF/
    CERT.RSA             <- signing certificate
    CERT.SF              <- manifest of signed file hashes
```

:::info **DEX (Dalvik Executable)**

DEX is the bytecode format Android uses for Kotlin and Java code. Unlike compiled machine code for a specific CPU, DEX runs on the Android Runtime (ART), which is itself a VM. This is why Kotlin/Java apps are easier to decompile than native code — DEX is designed to be portable and carries structural information.

:::

## Android code signing

Every APK must be signed with a developer's private key before it can be installed. The signing certificate (containing the corresponding public key) is embedded in the APK's `META-INF/` directory. Android verifies this signature on install.

**APK Signature Scheme versions:**

- **v1** (JAR signing): Signs individual files. Can be bypassed with the "master key" attack (now patched). Still present for compatibility.
- **v2** (APK Signing Block): Signs the entire APK as a byte stream. Stronger than v1. Required for Android 7+.
- **v3** (APK Signing Block with key rotation): Adds support for rotating the signing key while maintaining continuity. Available on Android 9+.

This library reads the signing certificate from the APK at runtime (not from the system's PackageManager API, which could be intercepted) and uses its SHA-256 hash as input to the licence key derivation. This means the licence key is mathematically tied to the signing certificate: re-signing the APK with a different key produces a different hash, which produces a completely different Argon2id input, which produces a completely different key, which fails to decrypt the licence.

## Native libraries and JNI

:::info **JNI (Java Native Interface)**

JNI is the mechanism that lets Kotlin/Java code call functions written in C, C++, or Rust that have been compiled to native machine code (`.so` files). Native code runs directly on the CPU, not through the ART VM, making it significantly harder to decompile. However, it can still be analysed with binary analysis tools.

:::

The security library is written in **Rust** and compiled to a native `.so` file. Rust was chosen over C/C++ for several reasons:

- **Memory safety**: Rust's ownership system prevents entire classes of vulnerabilities (buffer overflows, use-after-free, double-free) at compile time. Security code must not have memory vulnerabilities.
- **No null pointer dereferences**: Rust has no null pointers; it uses `Option<T>` for optional values.
- **No undefined behaviour**: Unlike C, Rust code behaves deterministically.
- **Excellent crypto ecosystem**: The `RustCrypto` project provides high-quality, audited implementations of all primitives used here.
- **Zeroize support**: Rust's trait system allows secret bytes to be reliably zeroed from memory when they are no longer needed.

:::note **Choosing Rust for Security Libraries**

Modern security engineering strongly favours memory-safe languages for sensitive code. The NSA, CISA, and major tech companies have all issued guidance recommending memory-safe languages (Rust, Go, Swift) over C/C++ for security-critical components. Rust is the leading choice for high-performance security code because it achieves C-level performance without C's memory safety pitfalls.

:::
