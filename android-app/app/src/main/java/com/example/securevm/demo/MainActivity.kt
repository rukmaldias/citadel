package com.example.securevm.demo

// ══════════════════════════════════════════════════════════════════════════════
//  MainActivity.kt — Secure VM Integration Demo
// ══════════════════════════════════════════════════════════════════════════════
//
//  This file is the primary integration reference for the SecureVm library.
//  Every feature is demonstrated with comments explaining WHY, not just HOW.
//
//  READ ORDER:
//    1.  DemoApplication   (Application subclass — loads the .so once)
//    2.  onCreate          (initial UI setup, store reload)
//    3.  onRunClicked      (the full VM startup + execution flow)
//    4.  onEncryptClicked  (customer-data AES-256-GCM encryption)
//    5.  onStoreClicked    (SecureStore: hardware-passphrase-backed KV store)
//    6.  onPause / onStop  (zeroize secrets when backgrounded)
//    7.  Helper functions  (error messages, passphrase derivation)
//
// ══════════════════════════════════════════════════════════════════════════════

import android.os.Bundle
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import android.widget.Button
import android.widget.ScrollView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import com.example.securevm.SecureVm
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec

// ── TAG for logcat filtering ────────────────────────────────────────────────
private const val TAG = "SecureVmDemo"

// ── Android Keystore alias for the passphrase-wrapping key ──────────────────
//
// INTEGRATION NOTE: choose a name unique to your app.  This key is used to
// wrap (encrypt) a random 32-byte passphrase that unlocks the SecureStore.
// The wrapping key never leaves the hardware Keystore; only the wrapped
// (AES-GCM encrypted) passphrase is stored on disk.
private const val KEYSTORE_ALIAS = "SecureVmDemoPassphraseKey"

// ── SharedPreferences key for the persisted SecureStore blob ─────────────────
private const val PREF_STORE_BLOB    = "secure_store_blob"
// ── SharedPreferences key for the wrapped passphrase ─────────────────────────
private const val PREF_WRAPPED_PASS  = "secure_store_wrapped_pass"
// ── SharedPreferences key for the GCM nonce used to wrap the passphrase ──────
private const val PREF_WRAP_NONCE    = "secure_store_wrap_nonce"

class MainActivity : AppCompatActivity() {

    // ── UI references ────────────────────────────────────────────────────────
    private lateinit var statusText: TextView
    private lateinit var btnRun: Button
    private lateinit var btnEncrypt: Button
    private lateinit var btnStore: Button

    // ── Shared SecureVm instance ─────────────────────────────────────────────
    //
    // INTEGRATION NOTE: there are two valid patterns:
    //
    //   Pattern A — single long-lived instance (used here):
    //     Keep one SecureVm across the Activity's lifecycle. Start on resume,
    //     stop on pause.  Simpler, but secrets live in RAM between operations.
    //
    //   Pattern B — short-lived per-operation instances:
    //     Create a new SecureVm inside a `use {}` block for each discrete
    //     operation.  Secrets exist in RAM for the minimum possible time.
    //     More expensive (Argon2id KDF runs every call ≈ 200 ms) but safest.
    //
    // For an activity that performs multiple operations in quick succession,
    // Pattern A is the right balance.  For a background service that runs
    // once per session, prefer Pattern B.
    private var vm: SecureVm? = null

    // ── Last ciphertext produced by onEncryptClicked, used by decrypt demo ───
    private var lastCiphertext: ByteArray? = null

    // ── Whether the SecureStore has been loaded from SharedPreferences ───────
    private var storeLoaded = false

    // ══════════════════════════════════════════════════════════════════════════
    //  onCreate
    // ══════════════════════════════════════════════════════════════════════════
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        statusText = findViewById(R.id.tvStatus)
        btnRun     = findViewById(R.id.btnRun)
        btnEncrypt = findViewById(R.id.btnEncrypt)
        btnStore   = findViewById(R.id.btnStore)

        btnRun.setOnClickListener     { onRunClicked() }
        btnEncrypt.setOnClickListener { onEncryptClicked() }
        btnStore.setOnClickListener   { onStoreClicked() }

        appendStatus("SecureVm demo ready.\nTap 'Run Firmware' to begin.")
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  onResume — start the VM when the activity becomes visible
    // ══════════════════════════════════════════════════════════════════════════
    override fun onResume() {
        super.onResume()
        // Start the VM on every resume so secrets are not left in RAM while
        // the app is in the background (they are cleared in onPause below).
        startVm()
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  onPause — export the SecureStore and zeroize secrets
    // ══════════════════════════════════════════════════════════════════════════
    override fun onPause() {
        super.onPause()

        val currentVm = vm ?: return

        // 1. Export the SecureStore to an encrypted blob BEFORE stop().
        //    stop() clears the store's in-memory key, after which exportStore()
        //    returns null.  Always export first.
        val blob = currentVm.exportStore()
        if (blob != null) {
            saveStoreBlob(blob)
            Log.d(TAG, "SecureStore exported (${blob.size} bytes)")
        }

        // 2. stop() zeroes:
        //      • the firmware session key (re-encrypts firmware bytes)
        //      • the customer-data AES key
        //      • the SecureStore in-memory key
        //    After stop(), encryptData() / decryptData() / loadSecret() fail
        //    until the next successful startFromAssets() call.
        currentVm.stop()
        Log.d(TAG, "VM stopped; secrets cleared from RAM")

        storeLoaded = false
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  onDestroy — release the native heap allocation
    // ══════════════════════════════════════════════════════════════════════════
    override fun onDestroy() {
        super.onDestroy()
        // close() calls stop() if the VM is still running, then frees the Rust
        // heap allocation (Box<Mutex<SecureVm>>) via JNI.
        vm?.close()
        vm = null
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  startVm — the main startup sequence (called from onResume)
    // ══════════════════════════════════════════════════════════════════════════
    private fun startVm() {
        // Allocate a new native VM instance.
        // The native heap allocation happens here; nothing else does yet.
        val newVm = SecureVm()
        vm = newVm

        // ── startFromAssets() — the full 10-step verification pipeline ───────
        //
        //  Step 1a: Root / emulator / .so integrity checks (always enforced)
        //  Step 1b: Debugger check (skipped when licence bit 1 = ALLOW_DEBUGGER)
        //           Generate a dev licence with firmware_flags: 3 to allow the
        //           Android Studio debugger to attach during development. See the
        //           "VM debug mode" section of the developer docs.
        //  Step 2: SHA-256 self-integrity of the .so ELF RX segment
        //  Step 3: Build CodeIdentity (package name + cert + installer)
        //  Step 4: Ed25519 signature over both asset hashes + identity
        //  Step 5: Argon2id KDF (≈ 200 ms) → AES-256-GCM decrypt licence
        //  Step 6: Identity validation (package, cert hash, installer, expiry)
        //  Step 7: HMAC self-integrity keyed by firmware_secret
        //  Step 8: Argon2id KDF (≈ 200 ms) → AES-256-GCM decrypt firmware
        //  Step 9: SHA-256 verify decrypted firmware bytes
        //  Step 10: Parse bytecode; re-encrypt under session-ephemeral key;
        //           initialise customer-data key in Keystore or WBC tables
        //
        // PERFORMANCE NOTE: the two Argon2id KDFs run serially (≈ 400 ms total
        // on a mid-range phone).  Call startFromAssets() from a background
        // coroutine or WorkManager task — never on the main thread.
        //
        // INTEGRATION NOTE: asset file names default to "license.bin",
        // "firmware.bin", "codesign.bin".  Pass custom names if you renamed them.
        val startCode = newVm.startFromAssets(this)

        when (startCode) {
            SecureVm.START_OK -> {
                appendStatus("✓ VM started successfully")
                Log.i(TAG, "SecureVm started OK")

                // Reload the persisted SecureStore blob from the previous session.
                // Must be done AFTER startFromAssets() because the store's AES
                // key is derived from the licence's customer_secret.
                reloadStore(newVm)
            }

            SecureVm.ERROR_ENVIRONMENT -> {
                // The VM detected a hostile environment.  Do NOT reveal which
                // specific check failed — that information helps attackers tune
                // their bypass tooling.  Log minimally.
                appendStatus("✗ Security environment check failed ($startCode)")
                Log.w(TAG, "startFromAssets: environment check failed, code=$startCode")
                // In production: show a generic "device not supported" message
                // and optionally report to your crash analytics with a non-
                // revealing event name (e.g. "vm_env_rejected").
            }

            SecureVm.ERROR_INTEGRITY -> {
                // Ed25519 signature failed OR AES-GCM authentication tag mismatch.
                // The asset files were tampered with, are from the wrong build, or
                // the .so was patched without updating the integrity slots.
                appendStatus("✗ Asset integrity check failed ($startCode)")
                Log.e(TAG, "startFromAssets: integrity check failed, code=$startCode")
            }

            SecureVm.ERROR_LICENSE -> {
                // The licence decrypted correctly (correct cert + installer KDF)
                // but the runtime identity fields do not match.  Most likely
                // causes: wrong package name, expired licence (valid_until
                // exceeded), or installer policy mismatch (sideload vs Play Store).
                appendStatus("✗ Licence validation failed ($startCode)")
                Log.e(TAG, "startFromAssets: licence mismatch, code=$startCode")
            }

            SecureVm.ERROR_FIRMWARE -> {
                // Firmware decrypted and hash-verified, but the bytecode stream
                // could not be parsed.  Regenerate assets with gen_assets.
                appendStatus("✗ Firmware parse error ($startCode)")
                Log.e(TAG, "startFromAssets: firmware parse failed, code=$startCode")
            }

            else -> {
                appendStatus("✗ Unexpected start code: $startCode")
                Log.e(TAG, "startFromAssets: unexpected code=$startCode")
            }
        }
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  onRunClicked — execute the firmware and display the result
    // ══════════════════════════════════════════════════════════════════════════
    private fun onRunClicked() {
        val currentVm = vm ?: return appendStatus("VM not initialised")

        try {
            // run() executes the firmware bytecode from the current program
            // counter until a Halt instruction is reached (or the step limit).
            //
            // Returns: the value at the top of the VM stack when Halt executes,
            //          or 0 if the stack was empty.
            //
            // Throws:  RuntimeException wrapping a VmError if:
            //            • The VM was not started (call startFromAssets first)
            //            • A checked arithmetic overflow / divide-by-zero
            //            • The step limit was reached (default 100,000 steps)
            //            • A debugger was detected mid-execution
            //            • The call stack overflowed (> 256 frames)
            val result: Long = currentVm.run()
            appendStatus("Firmware result: $result")
            Log.i(TAG, "run() returned $result")

        } catch (e: RuntimeException) {
            // In production, treat any VM exception as a security event and
            // log it without the exception message (which may reveal VM state).
            appendStatus("✗ VM execution failed: ${e.message}")
            Log.e(TAG, "run() threw: ${e.message}")
        }
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  onEncryptClicked — demonstrate customer-data AES-256-GCM encryption
    // ══════════════════════════════════════════════════════════════════════════
    private fun onEncryptClicked() {
        val currentVm = vm ?: return appendStatus("VM not started")

        // ── Encrypt ──────────────────────────────────────────────────────────
        //
        // encryptData() uses the session-scoped AES-256-GCM key that was derived
        // from customer_secret during startFromAssets().  The key is held in
        // Rust memory (LockedPage, excluded from swap and core dumps); Kotlin
        // never sees the key bytes.
        //
        // The ciphertext format is:  SVMDAT01 (8 bytes)
        //                          | nonce    (12 bytes, random)
        //                          | AES-GCM ciphertext + auth tag (16 bytes)
        //
        // INTEGRATION: store the returned ByteArray in your database, encrypted
        // SharedPreferences, or internal files.  Never store the plaintext.
        val plaintext = "Hello, SecureVm! This is sensitive data.".toByteArray(Charsets.UTF_8)
        val ciphertext: ByteArray? = currentVm.encryptData(plaintext)

        if (ciphertext == null) {
            appendStatus("✗ Encryption failed (VM not running?)")
            return
        }

        lastCiphertext = ciphertext
        appendStatus("Encrypted ${plaintext.size} B → ${ciphertext.size} B ciphertext")

        // ── Decrypt (round-trip demo) ─────────────────────────────────────────
        //
        // decryptData() verifies the GCM authentication tag before producing any
        // output.  If the ciphertext was modified in any way, or if the VM was
        // started with a different certificate (different customer_secret →
        // different AES key), this returns null — no partial plaintext is ever
        // produced.
        val decrypted: ByteArray? = currentVm.decryptData(ciphertext)
        if (decrypted == null) {
            appendStatus("✗ Decryption failed — authentication tag mismatch")
            return
        }

        val recovered = String(decrypted, Charsets.UTF_8)
        appendStatus("Decrypted: \"$recovered\"")
        Log.i(TAG, "Customer-data round-trip OK")
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  onStoreClicked — demonstrate SecureStore (hardware-passphrase-backed KV)
    // ══════════════════════════════════════════════════════════════════════════
    private fun onStoreClicked() {
        val currentVm = vm ?: return appendStatus("VM not started")

        // ── Derive a passphrase from Android Keystore ─────────────────────────
        //
        // The SecureStore is passphrase-protected. The passphrase is a 32-byte
        // random value that is:
        //   1. Generated once and encrypted (wrapped) with a hardware-backed AES
        //      key stored in Android Keystore under KEYSTORE_ALIAS.
        //   2. The wrapped passphrase + GCM nonce are stored in SharedPreferences.
        //   3. On each launch, the wrapped passphrase is unwrapped using the
        //      Keystore key (which never leaves hardware).
        //
        // WHY NOT just use a user PIN?  Because:
        //   • A hardware-backed key cannot be extracted even on a rooted device
        //     (StrongBox/TrustZone keeps it in hardware).
        //   • The Keystore key can be flagged REQUIRE_USER_AUTHENTICATION so it
        //     is only available after biometric unlock — add that spec if needed.
        //   • A PIN requires UX and can be brute-forced offline; a hardware-
        //     backed random key cannot be brute-forced at all.
        val passphrase: ByteArray = unwrapOrCreatePassphrase()

        try {
            // ── Write a secret ────────────────────────────────────────────────
            //
            // storeSecret(key, value, passphrase):
            //   • Derives a per-record AES-256-GCM key via Argon2id from the
            //     passphrase and a fresh random salt.
            //   • Encrypts the value.
            //   • Replaces the key string with HMAC-SHA-256(key, passphrase) so
            //     the store blob reveals no key names — even if an attacker dumps
            //     SharedPreferences, they cannot tell WHAT is stored.
            val secretValue = "sk_live_supersecretapitoken_1234".toByteArray(Charsets.UTF_8)
            val stored = currentVm.storeSecret("api_token", secretValue, passphrase)
            if (!stored) {
                appendStatus("✗ storeSecret failed")
                return
            }
            appendStatus("Stored 'api_token' in SecureStore")

            // ── Read it back ──────────────────────────────────────────────────
            //
            // loadSecret(key, passphrase):
            //   • Recomputes HMAC of the key to find the record.
            //   • Re-derives the record key via Argon2id from the salt + passphrase.
            //   • Decrypts and verifies the GCM tag.
            //   • Returns null if the key is not found OR the passphrase is wrong.
            val loaded: ByteArray? = currentVm.loadSecret("api_token", passphrase)
            if (loaded == null) {
                appendStatus("✗ loadSecret returned null")
                return
            }
            val recovered = String(loaded, Charsets.UTF_8)
            appendStatus("Loaded 'api_token': \"$recovered\"")
            Log.i(TAG, "SecureStore round-trip OK")

            // ── Persist the store for next launch ─────────────────────────────
            //
            // The SecureStore is in-memory only.  Export it as an opaque blob
            // and persist it (e.g. in SharedPreferences or a file).  The blob
            // is already encrypted — safe to write anywhere the app can write.
            //
            // Call exportStore() BEFORE stop() because stop() clears the in-
            // memory key needed for re-encryption of the export.
            val blob = currentVm.exportStore()
            if (blob != null) {
                saveStoreBlob(blob)
                appendStatus("SecureStore persisted (${blob.size} bytes)")
            }

        } finally {
            // Zero the passphrase immediately after use — do not hold it in a
            // field or pass it to coroutines without explicit zeroing.
            passphrase.fill(0)
        }
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  reloadStore — import the persisted store after VM start
    // ══════════════════════════════════════════════════════════════════════════
    private fun reloadStore(currentVm: SecureVm) {
        if (storeLoaded) return

        val encoded = getSharedPreferences("svm_demo", MODE_PRIVATE)
            .getString(PREF_STORE_BLOB, null) ?: return

        val blob = Base64.decode(encoded, Base64.NO_WRAP)
        val ok = currentVm.importStore(blob)
        storeLoaded = ok
        if (ok) {
            appendStatus("SecureStore restored from previous session")
            Log.d(TAG, "importStore OK, ${blob.size} bytes")
        } else {
            Log.w(TAG, "importStore failed — store may be from a different .so build")
        }
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  saveStoreBlob — persist the SecureStore export to SharedPreferences
    // ══════════════════════════════════════════════════════════════════════════
    private fun saveStoreBlob(blob: ByteArray) {
        getSharedPreferences("svm_demo", MODE_PRIVATE).edit()
            .putString(PREF_STORE_BLOB, Base64.encodeToString(blob, Base64.NO_WRAP))
            .apply()
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  unwrapOrCreatePassphrase
    //
    //  Returns a 32-byte passphrase for SecureStore, backed by Android Keystore.
    //
    //  Security properties:
    //    • The passphrase itself is random and never stored in plaintext.
    //    • It is wrapped (encrypted) with a hardware AES key that never leaves
    //      the Keystore.  On StrongBox devices, the key lives in a dedicated
    //      security chip; extraction is physically prevented.
    //    • The Keystore key is PURPOSE_ENCRYPT | PURPOSE_DECRYPT, AES-256-GCM.
    //    • Add setUserAuthenticationRequired(true) to require biometric unlock
    //      before the key is available (recommended for high-security apps).
    //
    //  INTEGRATION: call this method exactly once per onStoreClicked() / session,
    //  hold the result only for the duration of the SecureStore operation, then
    //  fill it with zeros immediately (see onStoreClicked's `finally` block).
    // ══════════════════════════════════════════════════════════════════════════
    private fun unwrapOrCreatePassphrase(): ByteArray {
        val prefs = getSharedPreferences("svm_demo", MODE_PRIVATE)
        val keyStore = java.security.KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)

        // ── Ensure the wrapping key exists ────────────────────────────────────
        if (!keyStore.containsAlias(KEYSTORE_ALIAS)) {
            val keyGen = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore"
            )
            keyGen.init(
                KeyGenParameterSpec.Builder(
                    KEYSTORE_ALIAS,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
                )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                // Uncomment to gate on biometric authentication:
                // .setUserAuthenticationRequired(true)
                // .setUserAuthenticationValidityDurationSeconds(-1) // require every use
                .build()
            )
            keyGen.generateKey()
            Log.d(TAG, "Keystore wrapping key created: $KEYSTORE_ALIAS")
        }

        val key = keyStore.getKey(KEYSTORE_ALIAS, null) as javax.crypto.SecretKey

        // ── If a wrapped passphrase is already stored, unwrap it ──────────────
        val wrappedB64  = prefs.getString(PREF_WRAPPED_PASS, null)
        val nonceB64    = prefs.getString(PREF_WRAP_NONCE, null)
        if (wrappedB64 != null && nonceB64 != null) {
            val wrapped = Base64.decode(wrappedB64, Base64.NO_WRAP)
            val nonce   = Base64.decode(nonceB64,   Base64.NO_WRAP)
            val cipher  = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, nonce))
            return cipher.doFinal(wrapped)   // 32 plaintext bytes
        }

        // ── First run: generate a fresh random 32-byte passphrase and wrap it ─
        val passphrase = ByteArray(32).also {
            java.security.SecureRandom().nextBytes(it)
        }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        val wrapped = cipher.doFinal(passphrase)
        val nonce   = cipher.iv

        prefs.edit()
            .putString(PREF_WRAPPED_PASS, Base64.encodeToString(wrapped, Base64.NO_WRAP))
            .putString(PREF_WRAP_NONCE,   Base64.encodeToString(nonce,   Base64.NO_WRAP))
            .apply()

        Log.d(TAG, "Passphrase generated and wrapped")
        return passphrase
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  appendStatus — thread-safe UI helper
    // ══════════════════════════════════════════════════════════════════════════
    private fun appendStatus(msg: String) {
        runOnUiThread {
            statusText.append("\n$msg")
            // Auto-scroll to the bottom so the latest message is always visible.
            val scrollView = statusText.parent as? ScrollView
            scrollView?.post { scrollView.fullScroll(ScrollView.FOCUS_DOWN) }
        }
    }
}

// ══════════════════════════════════════════════════════════════════════════════
//  DemoApplication
//
//  INTEGRATION NOTE: the native .so must be loaded ONCE before any SecureVm
//  instance is created.  The Application subclass is the correct place — it
//  runs before any Activity, Service, or BroadcastReceiver.
//
//  The library name "secure_android_vm" corresponds to the filename
//  libsecure_android_vm.so placed in app/src/main/jniLibs/<ABI>/.
//  Android's class loader maps "secure_android_vm" → "libsecure_android_vm.so"
//  automatically.
//
//  JNI_OnLoad (in src/jni_api.rs) fires here and calls:
//    • prctl(PR_SET_DUMPABLE, 0) — disables core dumps for this process
//    • Any global Rust state initialisation
// ══════════════════════════════════════════════════════════════════════════════
class DemoApplication : android.app.Application() {
    override fun onCreate() {
        super.onCreate()
        // Load the native library. This must happen before any SecureVm() call.
        // If the .so is missing from jniLibs/<ABI>/, this throws UnsatisfiedLinkError.
        System.loadLibrary("secure_android_vm")
    }
}
