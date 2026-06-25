---
id: glossary
title: Glossary
sidebar_position: 13
---

## AES-256-GCM

Advanced Encryption Standard with a 256-bit key in Galois/Counter Mode. Provides both confidentiality (nobody can read the data without the key) and integrity (any modification is detected via the 16-byte auth tag).

## Argon2id

A memory-hard key derivation function. Uses a configurable amount of RAM and CPU time to compute, making brute-force attacks impractical even with GPU farms. Winner of the 2015 Password Hashing Competition.

## ABI (Application Binary Interface)

Defines the calling conventions and binary format for a specific CPU architecture. Android uses three main ABIs: arm64-v8a, armeabi-v7a, x86_64.

## APK

Android Package. A ZIP file containing the compiled app code, resources, native libraries, and signing certificate.

## Bytecode

A sequence of bytes that represents a program for a virtual machine. Not native machine code (which runs directly on a CPU) but an intermediate format that the VM interprets.

## Chain of trust

A sequence of verifications where each step unlocks the next. Breaking any link in the chain prevents progress.

## Ciphertext

Encrypted data. Looks like random bytes without the decryption key.

## CFF (Control Flow Flattening)

An LLVM IR pass that replaces structured control flow (loops, if-else) with a flat dispatcher switch, making the function's logic harder to understand with a decompiler.

## Core dump

A file containing the full memory contents of a process at the moment it crashed. Attackers can obtain and analyse core dumps to extract secrets. `madvise(MADV_DONTDUMP)` excludes sensitive pages from core dumps.

## Digest

The fixed-size output of a hash function. Also called a "fingerprint" or "hash value".

## Domain separation

The practice of mixing a unique label into each cryptographic operation so that keys or outputs from one context cannot be substituted into another.

## Ed25519

A digital signature algorithm based on Curve25519 elliptic curve cryptography. Fast, secure, 32-byte public key, 64-byte signatures.

## ELF

Executable and Linkable Format. The binary file format used by Linux and Android for executables and shared libraries (`.so` files).

## Firmware

In this context: the protected business logic expressed as VM bytecode. Named "firmware" because it is compiled into the app's assets like firmware is compiled into a hardware device.

## Fisher-Yates shuffle

A well-known algorithm for generating a uniformly random permutation of a list. Used here to shuffle the opcode table given a seed.

## GCM (Galois/Counter Mode)

An authenticated encryption mode for block ciphers. Combines CTR-mode encryption with a polynomial authentication tag (GHASH).

## Hardware Security Module (HSM)

A physical device that manages cryptographic keys and performs crypto operations inside tamper-resistant hardware. Keys cannot be extracted.

## HMAC (Hash-based MAC)

A message authentication code constructed from a hash function and a secret key. Provides integrity and authenticity.

## IR (Intermediate Representation)

In LLVM, the representation of a program between source code and machine code. LLVM passes (like CFF and SUB) operate on IR.

## JNI (Java Native Interface)

The mechanism for Kotlin/Java code to call functions compiled to native machine code in `.so` shared libraries.

## KDF (Key Derivation Function)

A function that derives one or more keys from a password or secret value. A good KDF is slow to compute (to resist brute-force).

## `LockedPage`

A memory page allocated and protected with `mlock` (no swap) and `madvise(MADV_DONTDUMP)` (excluded from core dumps). Used for the program key and other highly sensitive values.

## LLVM

A compiler infrastructure project. rustc uses LLVM to generate machine code from Rust programs. The obfuscation plugin hooks into LLVM's optimisation pipeline.

## `mlock`

A Linux system call that pins a memory page in RAM, preventing the kernel from swapping it to disk.

## NDK (Native Development Kit)

Google's toolkit for compiling C, C++, and Rust code that targets Android. Provides the cross-compilation toolchain and sysroot.

## Nonce

"Number used once". A random or sequential value that must be unique for each encryption operation with the same key. Reusing a nonce with the same key in AES-GCM completely breaks security.

## obfstr

A Rust crate that XOR-encrypts string and byte constants at compile time. The encrypted value is decrypted at runtime just before use, so the plaintext never appears in `.rodata`.

## Opcode

A byte value that identifies a specific instruction in a bytecode format. The per-licence opcode bijection shuffles which byte means which instruction.

## Plaintext

Unencrypted data. The original readable content before encryption.

## Post-quantum cryptography

Cryptographic algorithms designed to remain secure even against quantum computers. AES-256, HMAC-SHA-256, and Argon2id are considered post-quantum safe. Ed25519 is not.

## RX segment

The "read-execute" ELF program segment containing code (`.text`) and read-only data (`.rodata`). The integrity slots cover this segment.

## Salt

Random bytes added to a hash or KDF input to ensure that the same password produces different outputs each time. Prevents precomputed rainbow table attacks.

## SLSA

Supply-chain Levels for Software Artifacts. A framework for ensuring build artifacts come from the expected source code via the expected build process.

## Stack machine

A virtual machine design where instructions operate on a stack (last-in, first-out list) rather than named registers.

## StrongBox

A physically separate, tamper-resistant security processor present in some Android devices (Pixel 3+, Galaxy S10+). Keys stored in StrongBox never leave the chip — not even to the main ARM processor.

## SUB (Instruction Substitution)

An LLVM IR pass that replaces arithmetic/bitwise instructions with logically equivalent but less recognisable sequences, confusing decompiler heuristics.

## TrustZone (TEE)

ARM's hardware mechanism for creating a "Trusted Execution Environment" on the main CPU. The TEE runs isolated from the normal operating system. Android Keystore uses TrustZone on most devices.

## White-box cryptography

A technique that embeds a cryptographic key into the algorithm's tables so that the key cannot be easily read from memory — the "white box" assumption being that the attacker can see all of memory.

## Zeroize

The practice of overwriting sensitive memory with zeros before freeing it. Must use volatile writes so the compiler cannot elide them as "dead writes".
