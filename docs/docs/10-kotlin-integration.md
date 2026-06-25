---
id: kotlin-integration
title: Using the VM in Your Android App
sidebar_position: 10
---

## Set up the Kotlin wrapper

`SecureVm.kt` **must** live in the `com.example.securevm` package (or whatever package the `.so` was compiled for). The JNI function names inside the native library are hardcoded as `Java_com_example_securevm_SecureVm_*` — if the Kotlin class is in a different package, the JNI linkage fails at runtime with `UnsatisfiedLinkError`.

**Option A — keep the default package (quickest):**

Copy the wrapper into your project keeping its original package path:

```bash
cp android/SecureVm.kt \
   app/src/main/java/com/example/securevm/SecureVm.kt
```

Your own Activity lives alongside it in your own package:

```
java/
├── com/example/securevm/
│   └── SecureVm.kt          ← must match the .so's JNI export prefix
└── com/yourcompany/yourapp/
    └── MainActivity.kt      ← your app code
```

**Option B — rename to your own package (recommended for production):**

1. Edit every `Java_com_example_securevm_SecureVm_` prefix in `src/jni_api.rs` to match your package (e.g. `Java_com_yourcompany_yourapp_SecureVm_`).
2. Rebuild the `.so` files with `cargo ndk`.
3. Copy `SecureVm.kt` to your chosen path and update its `package` declaration to match.
4. Update the `-keep class` rule in `proguard-rules.pro` to the new class name.

:::danger
Do not copy `SecureVm.kt` to a different package without also recompiling the `.so`. The copy will compile, but every JNI call will throw `UnsatisfiedLinkError` at runtime.
:::

## Starting the VM: basic pattern

```kotlin
import com.yourcompany.yourapp.SecureVm
import android.util.Log

fun runSecureLogic(context: Context): Long {
    // SecureVm implements Closeable, so `use` automatically calls close()
    // even if an exception is thrown. close() zeroes all secrets.
    return SecureVm().use { vm ->

        // startFromAssets() reads the three files from assets/,
        // runs all 10 verification steps, and returns a start code.
        when (val startCode = vm.startFromAssets(context)) {
            SecureVm.START_OK -> {
                Log.d("SecureVM", "Started successfully")
            }
            SecureVm.ERROR_ENVIRONMENT -> {
                // Debugger, root, or emulator detected.
                // Log minimally; do not reveal which check failed.
                Log.w("SecureVM", "Security environment check failed")
                throw SecurityException("Environment check failed: $startCode")
            }
            SecureVm.ERROR_INTEGRITY -> {
                Log.e("SecureVM", "Asset integrity check failed")
                throw SecurityException("Integrity failed: $startCode")
            }
            SecureVm.ERROR_LICENSE -> {
                Log.e("SecureVM", "License check failed")
                throw SecurityException("License failed: $startCode")
            }
            else -> {
                Log.e("SecureVM", "Unexpected start code: $startCode")
                throw SecurityException("VM start failed: $startCode")
            }
        }

        // run() executes the firmware. Returns the top-of-stack value
        // when Halt is reached, or throws RuntimeException on error.
        val result: Long = vm.run()
        Log.d("SecureVM", "Firmware result: $result")

        // Always call stop() when done with this computation.
        // stop() zeroes all cryptographic secrets in memory.
        vm.stop()

        result
    }
    // close() is called here automatically by `use`.
    // If stop() was already called, close() is a no-op.
}
```

## Start code meanings

| Constant | Value | Meaning and recommended response |
|---|---|---|
| `START_OK` | 0 | Success. VM is running. |
| `ERROR_INVALID_INPUT` | 1 | A required argument was null or empty (e.g., context was null). |
| `ERROR_INTEGRITY` | 2 | Ed25519 signature verification failed, or a blob had the wrong GCM authentication tag. The asset files may have been tampered with, or they were generated for a different `.so` version. |
| `ERROR_LICENSE` | 3 | Licence decrypted successfully, but the runtime identity does not match. The signing certificate, package name, or installer is wrong. |
| `ERROR_FIRMWARE` | 4 | Firmware decrypted and hash matched, but the bytes could not be parsed as valid VM bytecode. |
| `ERROR_ENVIRONMENT` | 5 | A debugger, root access, or emulator was detected. |
| `ERROR_UNKNOWN` | 99 | An unexpected internal error. Check logcat for details. |

:::note **Logging error details**

In production, log the start code at the WARN level but do not include details in the message that would help an attacker understand which specific check failed. "Security check failed" is better than "TracerPid=1234: debugger detected". Detailed error logging helps attackers tune their bypass attempts.

:::

## Customer data encryption

After `startFromAssets` returns `START_OK`, the VM holds a session-scoped AES-256-GCM key. This key is never exposed to Kotlin — it lives only inside the native library.

```kotlin
SecureVm().use { vm ->
    vm.startFromAssets(context)

    // Encrypt before writing to database or SharedPreferences
    val plaintext = "sensitive_api_token".toByteArray(Charsets.UTF_8)
    val ciphertext: ByteArray = vm.encryptData(plaintext)
        ?: throw SecurityException("Encryption failed (VM not running?)")

    // Store ciphertext somewhere persistent (DB, file, SharedPreferences)
    // The nonce is prepended to the ciphertext in the SVMDAT01 format.
    saveToDisk(ciphertext)

    // Later: decrypt when you need the value
    val storedCiphertext: ByteArray = loadFromDisk()
    val decrypted: ByteArray = vm.decryptData(storedCiphertext)
        ?: throw SecurityException("Decryption failed")
    val token = String(decrypted, Charsets.UTF_8)

    vm.stop()
}
```

:::danger

**Store only the ciphertext.** Never store the plaintext or the key. The key is re-derived automatically on every successful `startFromAssets` call. If `stop()` or `close()` is called, the key is zeroed from memory. Call `startFromAssets` again to re-derive it.

:::

## Secure secret storage (the SecureStore)

The SecureStore is a passphrase-protected, per-record encrypted key-value store. Unlike customer data encryption (which uses a session key), the SecureStore persists secrets across process restarts when you export and import the blob.

```kotlin
// Derive or unwrap the passphrase from Android Keystore (see below)
val passphrase: ByteArray = derivePassphraseFromHardwareKey()

// Store a secret
vm.storeSecret("api_token", tokenBytes, passphrase)

// Retrieve a secret
val token: ByteArray = vm.loadSecret("api_token", passphrase)
    ?: throw SecurityException("Secret not found or wrong passphrase")

// Check existence without decrypting
val exists: Boolean = vm.containsSecret("api_token")
```

**How to derive a passphrase from hardware (recommended):**

```kotlin
// Generate or retrieve a hardware-backed AES key in Android Keystore.
// This key never leaves the hardware.
val keyGen = KeyGenerator.getInstance(
    KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
keyGen.init(
    KeyGenParameterSpec.Builder(
        "MyAppVmPassphraseKey",
        KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
    )
    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
    .setKeySize(256)
    .build()
)
val key = keyGen.generateKey()  // or KeyStore.getInstance("AndroidKeyStore").getKey(...)

// Use the hardware key to encrypt a 32-byte random passphrase.
// Store the wrapped (encrypted) passphrase on disk.
// On each app launch, unwrap it using the hardware key.
// The passphrase itself is only in memory; the hardware key never leaves hardware.
```

## Persisting the SecureStore across launches

The SecureStore lives in Rust memory. Export it to bytes before the app goes to the background:

```kotlin
// In Activity.onStop() or ViewModel.onCleared() -- BEFORE vm.stop()
val storeBlob: ByteArray = vm.exportStore()
    ?: throw RuntimeException("Failed to export store")

// Save the encrypted blob. It is safe to write to SharedPreferences
// because it contains only ciphertext, salts, nonces, and HMAC-derived key IDs.
prefs.edit()
    .putString("secure_store", Base64.encodeToString(storeBlob, Base64.NO_WRAP))
    .apply()

vm.stop()

// On next launch, after startFromAssets() succeeds:
val encoded = prefs.getString("secure_store", null)
if (encoded != null) {
    val blob = Base64.decode(encoded, Base64.NO_WRAP)
    vm.importStore(blob)
    // Store is now loaded; vm.loadSecret() will work.
}
```

## VM debug mode

During development, set `"firmware_flags": 1` in `licensepack.json`. Every instruction will log a trace to logcat:

```
[SVM-DEBUG] step=     1 pc=    0 instr=PushI64(40)   stack_depth=0
[SVM-DEBUG]        => TOS=40
[SVM-DEBUG] step=     2 pc=    1 instr=PushI64(2)    stack_depth=1
[SVM-DEBUG]        => TOS=2
[SVM-DEBUG] step=     3 pc=    2 instr=Add            stack_depth=2
[SVM-DEBUG]        => TOS=42
[SVM-DEBUG] step=     4 pc=    3 instr=Halt           stack_depth=1
[SVM-DEBUG] HALT  result=42 steps=4
```

The flag is embedded inside the *encrypted* licence. You cannot enable it at runtime without re-issuing the licence. `stop()` resets it to false.

:::danger

Never ship production assets with `firmware_flags: 1`. The trace is readable by anyone with `adb logcat` access and reveals every computation value and branch outcome, including intermediate results that might be sensitive.

:::
