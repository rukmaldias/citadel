---
id: implementation
title: "Implementation: How the Library Works Internally"
sidebar_position: 8
---

## The VM lifecycle

*Diagram: VM state machine — Stopped ↔ Running, transitions via startFromAssets() and stop()/close()*

The VM has two states:

- **Stopped**: No firmware loaded, no keys in memory.
- **Running**: Firmware loaded, keys available. `run()` can be called repeatedly.

`startFromAssets()` triggers the 10-step pipeline to transition from Stopped to Running. `stop()` / `close()` zeroes all secrets and returns to Stopped.

The 10-step startup pipeline in `start_with_verified_assets()`:

**Step 1.** **Environment check.** Reject if debugger detected, device rooted, or emulator. This runs *before* any expensive cryptography to fail fast.

**Step 2.** **SHA-256 self-integrity check.** Verify the `.so`'s own hash slot.

**Step 3.** **Build CodeIdentity.** Read the package name from `/proc/self/cmdline` and the signing certificate from the APK binary.

**Step 4.** **Ed25519 signature verification.** Confirm the asset bundle is authentic and unmodified.

**Step 5.** **Licence decryption.** Argon2id KDF (200 ms) + AES-GCM decrypt.

**Step 6.** **Identity validation.** Compare cert hash, package name, installer, and expiry against licence fields.

**Step 7.** **HMAC self-integrity check.** The second (cryptographically binding) integrity check, now possible because `firmware_secret` is available.

**Step 8.** **Firmware decryption.** Argon2id KDF + AES-GCM decrypt.

**Step 9.** **Firmware hash verification.** SHA-256 of decrypted bytes must match the hash stored in the licence.

**Step 10.** **Bytecode parsing + re-encryption.** Parse the instruction stream with the per-licence opcode table; re-encrypt under a session-ephemeral key; store the customer-data key in hardware Keystore or white-box tables.

## Firmware at-rest re-encryption

A key design decision: decrypted firmware is *never* held as a plain `Vec<Instruction>` between `run()` calls.

*Diagram: Firmware re-encryption flow — Decrypt from firmware.bin → Re-encrypt with session-ephemeral key → Drop plaintext → Store only encrypted_program → Decrypt to Zeroizing buffer on each run() → Zero buffer after execution*

**Why this matters:** An attacker who dumps process memory between `run()` calls does not see plaintext firmware bytes. They only see an AES-256-GCM ciphertext encrypted with a key that lives in a `LockedPage` (excluded from core dumps via `madvise(MADV_DONTDUMP)`).

## Memory protection: Zeroize and LockedPage

When sensitive data is no longer needed, simply assigning `0` to it is not enough — the compiler is allowed to optimise away "dead" writes if the value is not read afterwards. The **zeroize** crate solves this by using *volatile writes*, which the compiler cannot elide.

```rust
use zeroize::Zeroizing;

{
    // Zeroizing<Vec<u8>> is zeroed when the variable goes out of scope.
    // Even if the compiler can prove the Vec is "dead" before this point,
    // the volatile write still happens.
    let aes_key: Zeroizing<Vec<u8>> = Zeroizing::new(derive_key(...)?);

    let ciphertext = encrypt_data(&aes_key, plaintext)?;
    // aes_key is zeroed here when it goes out of scope
}
// No trace of aes_key remains in memory
```

**LockedPage** goes further for the most sensitive fields:

- `mlock`: tells the OS "do not swap this page to disk". Without this, the OS could write the key to the swap partition, where it persists after the app exits.
- `madvise(MADV_DONTDUMP)`: tells the OS "exclude this page from core dumps". Even if the process crashes and a core dump is generated, the key is not in the dump file.

## The per-licence opcode bijection

Each licence carries a 32-byte `opcode_seed`. When this seed is non-zero, the 25 opcode byte values are shuffled using a Fisher-Yates algorithm seeded with **ChaCha20Rng**:

```rust
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

fn from_seed(seed: &[u8; 32]) -> OpcodeTable {
    // If seed is all zeros, return the identity table (no remapping).
    if seed.iter().all(|&b| b == 0) {
        return OpcodeTable::identity();
    }
    // Otherwise, seed a deterministic RNG and shuffle the opcode bytes.
    // ChaCha20Rng is used (not StdRng) because its output is
    // algorithm-stable across Rust and rand crate versions.
    let mut rng = ChaCha20Rng::from_seed(*seed);
    let mut table: Vec<u8> = CANONICAL_OPCODES.to_vec();
    table.shuffle(&mut rng);   // Fisher-Yates
    OpcodeTable::new(table)
}
```

**Effect:** Customer A's `firmware.bin` might encode `Add` as `0xA7` while Customer B's encodes it as `0x3C`. An attacker who decrypts Customer A's firmware sees scrambled bytes unless they also know Customer A's `opcode_seed`, which lives only inside Customer A's encrypted licence.

:::note **Algorithm-stable RNGs in production systems**

When code must produce the same output from the same seed across different compiler versions, operating systems, and library releases, use a *fully-specified* RNG algorithm like ChaCha20. Rust's `StdRng` is explicitly documented as *not* algorithm-stable: its output can change between releases. Using `StdRng` here would cause firmware encoded on one machine to be unreadable on another.

:::

## Anti-analysis: what is checked and why

The library runs several checks to detect hostile analysis environments. All detection strings (file paths, property names, JVM class names) are XOR-obfuscated via `obfstr::obfbytes!` so they cannot be found by searching the `.so` for plaintext strings.

| Check | Why |
|---|---|
| TracerPid ≠ 0 | `/proc/self/status` exposes a `TracerPid` field. Linux sets this to the PID of the process tracing us when a debugger is attached (via `ptrace`). This is the most reliable debugger check on Linux/Android. |
| `wchan` contains suspicious strings | `/proc/self/wchan` shows what kernel function a process is blocked in. A tracee waiting for the tracer shows "ptrace_stop". |
| Process state = 't' | `/proc/self/stat` field 3 is the process state. 't' means "stopped (by signal or tracing)". |
| `LD_PRELOAD` set | Frida and many hooking frameworks inject a shared library by setting `LD_PRELOAD`. Checking this environment variable catches these tools. |
| Emulator build props | Android emulators set specific system properties (e.g., `ro.product.model` starts with "sdk"). The library reads these via `__system_property_get`. |
| Known root paths | Root tools (Magisk, SuperSU) install binaries in paths like `/sbin/.magisk` or `/system/xbin/su`. Presence of these files indicates a rooted device. |
| `/proc/self/maps` | Scans the memory map for patterns associated with Frida agent shared libraries. Frida injects a `frida-agent` library that appears in the maps file. |

## The LLVM obfuscation passes

Beyond runtime obfuscation, the release-obfuscated build applies two LLVM IR transformation passes at compile time, making the compiled machine code harder to analyse statically.

### Control Flow Flattening (CFF)

Normal code has an obvious structure when viewed in a decompiler:

```rust
fn compute(x: i64) -> i64 {
    if x > 10 {
        x * 2
    } else {
        x + 1
    }
}
```

After CFF, the code looks like a flat switch with a state variable:

```rust
fn compute(x: i64) -> i64 {
    let mut state = 0;
    loop {
        match state {
            0 => { /* evaluate condition */ state = if x > 10 { 1 } else { 2 }; }
            1 => { return x * 2; }
            2 => { return x + 1; }
            _ => unreachable!(),
        }
    }
}
```

A decompiler cannot tell which cases are reachable without running the code.

### Instruction Substitution (SUB)

SUB replaces simple operations with equivalent but less recognisable ones:

| What the source says | What the binary contains |
|---|---|
| a + b | a - (~b) - 1 |
| a - b | a + ~b + 1 |
| a & b | ~(~a \| ~b) (De Morgan's law) |
| a ⊕ b | (a \| b) & ~(a & b) |

These are mathematically identical but confuse decompiler pattern-matching.
