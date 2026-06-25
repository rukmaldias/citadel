package com.example.securevm

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build

/**
 * Kotlin wrapper around the Rust secure VM shared library.
 *
 * This class is the primary API surface for Android developers. It owns a
 * native handle to a `Mutex<SecureVm>` allocated in Rust and exposes the
 * VM's capabilities through straightforward Kotlin functions.
 *
 * ## Lifecycle
 *
 * `SecureVm` implements [AutoCloseable], so you should use it inside a `use {}`
 * block or call [close] explicitly when you are done:
 *
 * ```kotlin
 * SecureVm().use { vm ->
 *     val code = vm.startFromAssets(context)
 *     if (code != SecureVm.START_OK) return
 *     val result = vm.run()
 * }
 * // close() is called automatically here, clearing secrets from memory
 * ```
 *
 * **Always call [stop] (or let `use {}` call [close]) when the app moves to the
 * background.** This clears the customer-data key from memory so it does not sit
 * in RAM while the process is paused and potentially visible to a memory dump.
 *
 * ## Security model
 *
 * The Rust layer enforces all cryptographic checks. The Kotlin layer is
 * responsible for reading the three asset files (`license.bin`, `firmware.bin`,
 * `codesign.bin`) from the APK and supplying the runtime app identity to the
 * native layer. Package name and signing certificate are read natively (not
 * hookable via Java instrumentation). The installer package is read from
 * `PackageManager` and is also cryptographically bound: for
 * `InstallerPolicy::Required` licences it is mixed into the Argon2id KDF, so
 * a wrong installer produces the wrong decryption key and AES-GCM fails.
 */
class SecureVm : AutoCloseable {
    /**
     * Opaque handle to the Rust `Mutex<SecureVm>` on the heap.
     *
     * This is a raw pointer cast to `Long`. It is initialised in the constructor
     * by [nativeCreate] and zeroed in [close] after [nativeDestroy] has been
     * called. The zero value is used as the "not created / already destroyed"
     * sentinel — all JNI functions check for zero before dereferencing.
     */
    private var handle: Long = nativeCreate()

    /**
     * Transitions the VM to the `Running` state without any asset verification.
     *
     * Use this only during development or testing when you are loading bytecode
     * manually via [loadProgram]. In production, always use [startFromAssets]
     * to ensure the firmware and license are cryptographically verified before
     * execution.
     *
     * @return `true` if the VM was successfully started, `false` if it was
     *   already running.
     */
    fun start(): Boolean = nativeStart(handle)

    /**
     * The main secure startup path — reads the encrypted assets from the APK,
     * verifies them, and starts the VM.
     *
     * This function performs the full verification chain:
     * 1. Reads `license.bin`, `firmware.bin`, and `codesign.bin` from the APK
     *    assets directory.
     * 2. Reads the runtime app identity natively: package name from
     *    `/proc/self/cmdline` and signing certificate from `META-INF/*.RSA`
     *    inside the APK ZIP — no `PackageManager` hook point. Only the
     *    installer package name is still read from `PackageManager`.
     * 3. Passes all assets and identity information to the Rust layer, which
     *    verifies the Ed25519 signature, decrypts the license, validates the
     *    identity, decrypts the firmware, verifies the firmware hash, and
     *    parses the bytecode.
     * 4. On success, the VM enters the `Running` state with the firmware loaded
     *    and the customer-data key available in memory.
     *
     * The Ed25519 public key used to verify the codesign signature is compiled
     * directly into the native `.so` (see `src/keys.rs`). It is never passed
     * from Kotlin — this prevents an attacker from substituting their own key
     * at runtime via instrumentation.
     *
     * @param context The Android `Context` used to read assets and the package
     *   manager. Any `Context` works (application, activity, service).
     * @param licenseAssetName Name of the license asset in `assets/`. Defaults
     *   to `"license.bin"`.
     * @param firmwareAssetName Name of the firmware asset in `assets/`. Defaults
     *   to `"firmware.bin"`.
     * @param codesignAssetName Name of the codesign asset in `assets/`. Defaults
     *   to `"codesign.bin"`.
     *
     * @return An integer start code. Compare against the companion object
     *   constants:
     *   - [START_OK]: success — VM is running, firmware is loaded.
     *   - [ERROR_INVALID_INPUT]: a required argument was empty or malformed.
     *   - [ERROR_INTEGRITY]: the Ed25519 signature failed or an asset blob
     *     had the wrong magic / authentication tag — the assets were tampered
     *     with or built against a different `.so`.
     *   - [ERROR_LICENSE]: the license was valid but does not match the
     *     runtime app identity (wrong package name, signing cert, or installer).
     *   - [ERROR_FIRMWARE]: the firmware decrypted successfully but could not
     *     be parsed as valid VM bytecode.
     *   - [ERROR_ENVIRONMENT]: a debugger or instrumentation framework was
     *     detected — the VM refuses to start.
     *   - [ERROR_UNKNOWN]: an unexpected internal error.
     */
    fun startFromAssets(
        context: Context,
        licenseAssetName: String = "license.bin",
        firmwareAssetName: String = "firmware.bin",
        codesignAssetName: String = "codesign.bin",
    ): Int {
        val encryptedLicense = context.assets.open(licenseAssetName).use { it.readBytes() }
        val encryptedFirmware = context.assets.open(firmwareAssetName).use { it.readBytes() }
        val codesign = context.assets.open(codesignAssetName).use { it.readBytes() }
        // Installer is read here (PackageManager); package name and signing
        // certificate are read natively from /proc/self/cmdline and META-INF/.
        // For Required-installer licences the installer is also mixed into the
        // Argon2id KDF, so a spoofed value produces the wrong key and decryption
        // fails cryptographically — not just a policy check.
        val installerPackage = readInstallerPackage(context) ?: ""

        return nativeStartWithAssets(
            handle,
            installerPackage,
            encryptedLicense,
            encryptedFirmware,
            codesign,
        )
    }

    /**
     * Stops the VM and clears the customer-data key from memory.
     *
     * After this call, [encryptData] and [decryptData] will fail until the next
     * successful [startFromAssets]. The encrypted [SecureStore] (accessible via
     * [storeSecret] / [loadSecret]) is not affected — it persists across
     * stop/start cycles because it never holds plaintext.
     *
     * Call this when the app moves to the background (`onStop` / `onPause`) so
     * the session key is not sitting in memory while the process is paused.
     *
     * @return `true` if the VM was stopped successfully.
     */
    fun stop(): Boolean = nativeStop(handle)

    /**
     * Loads raw bytecode bytes into the VM, bypassing the secure asset
     * verification path.
     *
     * For development and testing only. In production, bytecode arrives through
     * [startFromAssets], which verifies the signature and license before loading.
     *
     * @param bytecode Raw VM bytecode in the format produced by
     *   `Program::to_bytes()` on the Rust side.
     * @return `true` if the bytecode was successfully parsed and loaded.
     */
    fun loadProgram(bytecode: ByteArray): Boolean = nativeLoadProgram(handle, bytecode)

    /**
     * Executes the loaded firmware and returns the top-of-stack result.
     *
     * The VM must be in the `Running` state and a program must be loaded before
     * calling this. Each call to `run()` starts with a fresh evaluation stack
     * so previous runs do not affect the result.
     *
     * The integer result is the value on top of the VM's evaluation stack when
     * the firmware's `Halt` instruction is reached (or 0 if the stack was
     * empty). How to interpret this value is defined by the firmware protocol.
     *
     * @return The top-of-stack value after execution completes.
     * @throws RuntimeException if execution fails for any reason (VM not
     *   started, no program loaded, stack underflow, execution limit exceeded,
     *   debugger detected, etc.). The message is intentionally generic —
     *   internal error details are not exposed across the JNI boundary to avoid
     *   aiding an attacker. A return value of 0L is always a legitimate
     *   computed value; do not use it as an error sentinel.
     */
    @Throws(RuntimeException::class)
    fun run(): Long = nativeRun(handle)

    /**
     * Encrypts `plaintext` with the customer-data key and returns the ciphertext.
     *
     * The customer-data key is derived from the license during [startFromAssets]
     * and lives in memory only for the duration of the session. This function
     * **only works after a successful [startFromAssets] call**. Calling it
     * before that, or after [stop], returns `null`.
     *
     * Persist only the ciphertext — never the key. The key is re-derived
     * automatically from the license on the next [startFromAssets] call, so the
     * same ciphertext can always be decrypted on future launches as long as the
     * license is valid.
     *
     * @param plaintext The data to encrypt.
     * @return The AES-256-GCM ciphertext, or `null` if the VM has not been
     *   started with verified assets or if encryption fails.
     */
    fun encryptData(plaintext: ByteArray): ByteArray? = nativeEncryptData(handle, plaintext)

    /**
     * Decrypts `ciphertext` previously produced by [encryptData].
     *
     * Requires a prior successful [startFromAssets] call to derive the
     * customer-data key. The same license that encrypted the data will always
     * produce the same decryption key, so data encrypted on one launch can be
     * decrypted on a future launch.
     *
     * @param ciphertext Data previously returned by [encryptData].
     * @return The decrypted plaintext, or `null` if the VM has not been started
     *   with verified assets, the key is absent, or AES-GCM authentication
     *   fails (wrong key or corrupted ciphertext).
     */
    fun decryptData(ciphertext: ByteArray): ByteArray? = nativeDecryptData(handle, ciphertext)

    /**
     * Encrypts `value` with a passphrase-derived key and stores it under `key`
     * in the VM's encrypted key-value store.
     *
     * The store is independent of the firmware lifecycle — you can call this
     * whether the VM is running or stopped. The passphrase is never stored; it
     * must be supplied again when reading with [loadSecret].
     *
     * In production, derive the passphrase from an Android Keystore-backed key
     * rather than from a user-typed string, so the passphrase is bound to
     * hardware.
     *
     * @param key The string key that identifies this secret.
     * @param value The raw bytes to encrypt and store.
     * @param passphrase Raw bytes used as the Argon2id password for key
     *   derivation. Must be at least 12 bytes. Pass as `ByteArray` (not
     *   `String`) to avoid charset encoding ambiguity between store and load
     *   calls.
     * @return `true` if the secret was stored successfully.
     */
    fun storeSecret(key: String, value: ByteArray, passphrase: ByteArray): Boolean =
        nativeStoreSecret(handle, key, value, passphrase)

    /**
     * Decrypts and returns the secret stored under `key`.
     *
     * @param key The string key used in [storeSecret].
     * @param passphrase The same passphrase bytes used in [storeSecret]. If the
     *   passphrase is wrong, AES-GCM authentication will fail and `null` is
     *   returned (indistinguishable from a missing key to prevent oracle attacks).
     * @return The decrypted bytes, or `null` if the key does not exist or
     *   decryption fails.
     */
    fun loadSecret(key: String, passphrase: ByteArray): ByteArray? =
        nativeLoadSecret(handle, key, passphrase)

    /**
     * Serializes all encrypted store records to a portable byte blob.
     *
     * The blob contains only ciphertext, salts, and nonces — **no plaintext**.
     * It is safe to write to `SharedPreferences` or a database.
     *
     * Persistence pattern:
     * - `onStop` / `onPause`: call [exportStore] and save the blob.
     * - Next launch, after [startFromAssets] succeeds: call [importStore] with
     *   the saved blob to restore the secrets.
     *
     * @return A byte blob, or `null` if serialisation fails.
     */
    fun exportStore(): ByteArray? = nativeExportStore(handle)

    /**
     * Replaces the current store with records from a blob produced by
     * [exportStore].
     *
     * Call this after a successful [startFromAssets] on the next launch to
     * restore previously stored secrets.
     *
     * @param blob A byte array previously returned by [exportStore].
     * @return `true` if the store was successfully restored.
     */
    fun importStore(blob: ByteArray): Boolean = nativeImportStore(handle, blob)

    /**
     * Destroys the native VM and frees its heap memory.
     *
     * After this call, all other methods on this instance will silently fail
     * (the Rust side checks for a zero handle). The `handle` field is set to
     * zero before calling [nativeDestroy] to prevent a double-free if [close]
     * is called more than once.
     *
     * If you use `SecureVm` inside a `use {}` block, this is called
     * automatically at the end of the block.
     */
    override fun close() {
        if (handle != 0L) {
            nativeDestroy(handle)
            handle = 0
        }
    }

    private external fun nativeCreate(): Long
    private external fun nativeDestroy(handle: Long)
    private external fun nativeStart(handle: Long): Boolean
    private external fun nativeStartWithAssets(
        handle: Long,
        installerPackage: String,
        encryptedLicense: ByteArray,
        encryptedFirmware: ByteArray,
        codesign: ByteArray,
    ): Int
    private external fun nativeStop(handle: Long): Boolean
    private external fun nativeLoadProgram(handle: Long, bytecode: ByteArray): Boolean
    private external fun nativeRun(handle: Long): Long
    private external fun nativeEncryptData(handle: Long, plaintext: ByteArray): ByteArray?
    private external fun nativeDecryptData(handle: Long, ciphertext: ByteArray): ByteArray?
    private external fun nativeStoreSecret(
        handle: Long,
        key: String,
        value: ByteArray,
        passphrase: ByteArray,
    ): Boolean
    private external fun nativeLoadSecret(
        handle: Long,
        key: String,
        passphrase: ByteArray,
    ): ByteArray?
    private external fun nativeExportStore(handle: Long): ByteArray?
    private external fun nativeImportStore(handle: Long, blob: ByteArray): Boolean

    companion object {
        /**
         * [startFromAssets] return code: all checks passed and the VM is running.
         * The firmware is loaded and [encryptData] / [decryptData] are available.
         */
        const val START_OK = 0

        /**
         * [startFromAssets] return code: a required argument was missing, empty,
         * or structurally invalid (e.g. the codesign public key was not 32 bytes,
         * the signing certificate was empty, or the VM was already running).
         */
        const val ERROR_INVALID_INPUT = 1

        /**
         * [startFromAssets] return code: the Ed25519 signature verification
         * failed, or an asset blob had wrong magic bytes or a bad AES-GCM
         * authentication tag. The assets were tampered with or the wrong
         * codesign public key was used.
         */
        const val ERROR_INTEGRITY = 2

        /**
         * [startFromAssets] return code: the license decrypted successfully but
         * its identity fields (package name, signing certificate hash, or
         * installer) do not match the runtime app identity. The license was
         * issued for a different app or distribution channel.
         */
        const val ERROR_LICENSE = 3

        /**
         * [startFromAssets] return code: the firmware decrypted successfully but
         * could not be parsed as valid VM bytecode. The firmware asset is corrupt
         * or was built for a different VM version.
         */
        const val ERROR_FIRMWARE = 4

        /**
         * [startFromAssets] return code: a debugger or dynamic instrumentation
         * framework (Frida, Xposed, etc.) was detected. The VM refuses to start
         * in a monitored environment to protect firmware secrets.
         */
        const val ERROR_ENVIRONMENT = 5

        /**
         * [startFromAssets] return code: an unexpected internal error occurred.
         * This should not happen in practice; if it does, file a bug.
         */
        const val ERROR_UNKNOWN = 99

        init {
            System.loadLibrary("secure_android_vm")
        }

        /**
         * Reads the package name of the app that installed this APK.
         *
         * For `InstallerPolicy::Required` licences the returned value is mixed
         * directly into the Argon2id KDF (licence key derivation). A mismatch
         * — e.g. a sideloaded APK where this returns `null` while the licence
         * was issued for `"com.android.vending"` — causes the KDF to produce
         * the wrong key and AES-GCM decryption fails. This is a cryptographic
         * rejection, not merely a policy check, so hooking this method to
         * return the expected installer name is not sufficient to bypass it
         * without also defeating the root/Frida detection that runs earlier.
         *
         * **API 30+ (Android 11)**: uses `getInstallSourceInfo` (non-deprecated).
         * **API < 30**: uses the deprecated `getInstallerPackageName`.
         *
         * Returns `null` for sideloaded APKs (`adb install`). The caller
         * converts `null` to `""` before passing to the JNI layer.
         */
        private fun readInstallerPackage(context: Context): String? {
            val packageManager = context.packageManager
            return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                packageManager.getInstallSourceInfo(context.packageName).installingPackageName
            } else {
                @Suppress("DEPRECATION")
                packageManager.getInstallerPackageName(context.packageName)
            }
        }
    }
}
