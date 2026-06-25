//! JNI (Java Native Interface) entry points for Android.
//!
//! ## What is JNI?
//!
//! JNI is the standard bridge that lets Kotlin and Java code call functions
//! written in a native language (here, Rust). The Android runtime loads the
//! compiled Rust code as a shared library (`libsecure_android_vm.so`) and
//! calls the functions whose names match the `Java_<package>_<class>_<method>`
//! convention.
//!
//! ## The handle pattern
//!
//! Kotlin cannot hold a Rust object directly. Instead, `nativeCreate` allocates
//! a `Mutex<SecureVm>` on the heap, leaks it out of Rust's ownership system
//! with `Box::into_raw`, and returns the raw pointer as a `Long`. Kotlin stores
//! this `Long` in the `handle` field of `SecureVm.kt`. Every subsequent JNI
//! call passes `handle` back and the Rust side casts it to
//! `*mut Mutex<SecureVm>` to recover the object.
//!
//! Wrapping the VM in a `Mutex` ensures that concurrent calls from multiple
//! threads (rare but possible on Android) do not race on the same VM state.
//!
//! The `handle` is zeroed in `close()` on the Kotlin side to prevent
//! double-free. `nativeDestroy` checks for zero before dereferencing.

use std::{ptr, sync::Mutex};

use jni::{
    objects::{JByteArray, JClass, JObject, JString},
    sys::{jboolean, jbyteArray, jint, jlong},
    JNIEnv,
};

use crate::{SecureVm, StartCode};

// Boolean constants that match Java's `JNI_TRUE` and `JNI_FALSE`. Returned
// from JNI functions where Kotlin expects a `Boolean`.
const JNI_TRUE: jboolean = 1;
const JNI_FALSE: jboolean = 0;

/// Allocates a new `SecureVm` on the heap and returns a handle to it.
///
/// `Box::new(Mutex::new(SecureVm::new()))` allocates the VM in a heap box,
/// then `Box::into_raw` converts it to a raw pointer that will not be freed
/// by Rust automatically. The pointer is cast to `jlong` (a 64-bit integer)
/// and returned to Kotlin, where it is stored as `handle: Long`.
///
/// The `Mutex` wrapper makes the VM safe to call from multiple threads —
/// each JNI function acquires the lock before touching the VM.
///
/// Called from Kotlin: `private external fun nativeCreate(): Long`
#[no_mangle]
pub extern "system" fn Java_com_example_securevm_SecureVm_nativeCreate(
    _env: JNIEnv,
    _class: JClass,
) -> jlong {
    Box::into_raw(Box::new(Mutex::new(SecureVm::new()))) as jlong
}

/// Destroys the VM and frees the heap memory.
///
/// The `handle` is cast back to `*mut Mutex<SecureVm>` — the exact same type
/// that `nativeCreate` produced. Using the wrong type would be undefined
/// behaviour. `Box::from_raw` reconstructs the owning `Box`, and `drop` at the
/// end of the function frees the memory.
///
/// The guard `if handle != 0` matches the zeroing that `close()` does in
/// Kotlin, preventing a double-free if `nativeDestroy` is called twice.
///
/// # Safety
///
/// `handle` must be a value previously returned by `nativeCreate` and not yet
/// destroyed. The Kotlin `close()` method guarantees this by zeroing the handle
/// immediately after calling `nativeDestroy`.
///
/// Called from Kotlin: `private external fun nativeDestroy(handle: Long)`
#[no_mangle]
pub unsafe extern "system" fn Java_com_example_securevm_SecureVm_nativeDestroy(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) {
    if handle != 0 {
        drop(Box::from_raw(handle as *mut Mutex<SecureVm>));
    }
}

/// Starts the VM without asset verification (simple start).
///
/// Converts the bool result of `SecureVm::start()` to a `jboolean`.
/// Returns `JNI_FALSE` if the handle is invalid (zero) or the VM is already
/// running.
///
/// Called from Kotlin: `private external fun nativeStart(handle: Long): Boolean`
///
/// # Safety
///
/// `handle` must be a valid, non-destroyed handle. See `with_vm` for details.
#[no_mangle]
pub unsafe extern "system" fn Java_com_example_securevm_SecureVm_nativeStart(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jboolean {
    with_vm(handle, |vm| vm.start().is_ok()).unwrap_or(false) as jboolean
}

/// Runs the full firmware verification and startup pipeline.
///
/// All three identity inputs are read natively — no Kotlin intermediary exists
/// for an attacker to hook:
///
/// - **`package_id`**: read from `/proc/self/cmdline` (kernel memory).
/// - **`signing_certificate`**: read from `META-INF/*.RSA` in the APK ZIP.
/// - **`installer_package`**: obtained by calling
///   `PackageManager.getInstallerPackageName` directly from JNI using the
///   `context` parameter. The Kotlin caller passes `applicationContext` and
///   does **not** call PackageManager itself — so a Kotlin-layer hook cannot
///   substitute a different installer string.
///
/// The codesign public key is compiled into the `.so` via `src/keys.rs` and is
/// never accepted from the Kotlin caller. The key bytes are XOR-obfuscated with
/// `obfstr::obfbytes!` so no raw constant appears in `.rodata`.
///
/// Returns a `jint` mapping to `StartCode` (0 = OK, 1 = InvalidInput, etc.).
///
/// Kotlin declaration:
/// `private external fun nativeStartWithAssets(handle: Long, context: Context, ...): Int`
///
/// # Safety
///
/// See `with_vm`.
#[no_mangle]
pub unsafe extern "system" fn Java_com_example_securevm_SecureVm_nativeStartWithAssets(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
    context: JObject,         // android.content.Context — installer package is read from here
    encrypted_license: JByteArray,
    encrypted_firmware: JByteArray,
    codesign: JByteArray,
) -> jint {
    // Read package id and signing cert from kernel / APK ZIP — not hookable.
    let package_id = match crate::apk::read_package_id() {
        Ok(id) => id,
        Err(_) => return StartCode::InvalidInput as jint,
    };
    let signing_certificate = match crate::apk::read_signing_certificate() {
        Ok(cert) => cert,
        Err(_) => return StartCode::InvalidInput as jint,
    };

    // Read installer package name via direct JNI call — no Kotlin hook point.
    let installer_package = crate::apk::read_installer_package(&mut env, &context);
    let installer_package = installer_package.as_deref();

    let Ok(encrypted_license) = env.convert_byte_array(encrypted_license) else {
        return StartCode::InvalidInput as jint;
    };
    let Ok(encrypted_firmware) = env.convert_byte_array(encrypted_firmware) else {
        return StartCode::InvalidInput as jint;
    };
    let Ok(codesign) = env.convert_byte_array(codesign) else {
        return StartCode::InvalidInput as jint;
    };

    with_vm(handle, |vm| {
        vm.start_with_verified_assets(
            &package_id,
            installer_package,
            &signing_certificate,
            &encrypted_license,
            &encrypted_firmware,
            &codesign,
            &crate::keys::codesign_public_key(),
        ) as jint
    })
    .unwrap_or(StartCode::InvalidInput as jint)
}

/// Stops the VM and clears the customer-data key from memory.
///
/// Returns `JNI_TRUE` if the VM transitioned to stopped successfully.
///
/// Called from Kotlin: `private external fun nativeStop(handle: Long): Boolean`
///
/// # Safety
///
/// See `with_vm`.
#[no_mangle]
pub unsafe extern "system" fn Java_com_example_securevm_SecureVm_nativeStop(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jboolean {
    with_vm(handle, |vm| vm.stop().is_ok()).unwrap_or(false) as jboolean
}

/// Loads raw bytecode bytes into the VM (bypasses secure asset verification).
///
/// This is the manual / development path — use `nativeStartWithAssets` in
/// production. Returns `JNI_TRUE` if the bytecode was parsed and loaded
/// successfully.
///
/// Called from Kotlin: `private external fun nativeLoadProgram(handle: Long, bytecode: ByteArray): Boolean`
///
/// # Safety
///
/// See `with_vm`.
#[no_mangle]
pub unsafe extern "system" fn Java_com_example_securevm_SecureVm_nativeLoadProgram(
    env: JNIEnv,
    _class: JClass,
    handle: jlong,
    bytecode: JByteArray,
) -> jboolean {
    let Ok(bytes) = env.convert_byte_array(bytecode) else {
        return JNI_FALSE;
    };

    if with_vm(handle, |vm| vm.load_program_bytes(&bytes).is_ok()).unwrap_or(false) {
        JNI_TRUE
    } else {
        JNI_FALSE
    }
}

/// Executes the loaded firmware and returns the top-of-stack result.
///
/// On failure, throws a `java.lang.RuntimeException` on the JNI environment
/// and returns 0. The exception message is intentionally generic
/// (`"VM execution failed"`) — leaking the internal `VmError` message across
/// the JNI boundary could help an attacker understand what failed and why.
/// Android developers should catch the `RuntimeException` in Kotlin (see the
/// `@Throws` annotation on `SecureVm.run()`).
///
/// Returns the `i64` result as a `jlong`. A returned value of 0 may mean
/// either success-with-zero or failure (check for the exception), so always
/// wrap this call in try/catch in Kotlin.
///
/// Called from Kotlin: `private external fun nativeRun(handle: Long): Long`
///
/// # Safety
///
/// See `with_vm`.
#[no_mangle]
pub unsafe extern "system" fn Java_com_example_securevm_SecureVm_nativeRun(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jlong {
    match with_vm(handle, |vm| vm.run()) {
        Some(Ok(report)) => report.result,
        _ => {
            // Throw a RuntimeException. The `let _ =` discards the Result
            // from throw_new because there is nothing meaningful we can do
            // if throwing itself fails (we're already in an error path).
            let _ = env.throw_new("java/lang/RuntimeException", "VM execution failed");
            0
        }
    }
}

/// Encrypts `plaintext` with the customer-data key and returns the ciphertext.
///
/// Returns `null` (`ptr::null_mut()`) on any failure — null is used instead
/// of throwing an exception to keep the API opaque. The caller cannot
/// distinguish "VM not started" from "AES encryption failed", which is
/// intentional: exposing the reason for failure could help an attacker probe
/// the system state.
///
/// Only works after a successful `nativeStartWithAssets`. If called before
/// that, the customer-data key is absent and null is returned.
///
/// Called from Kotlin: `private external fun nativeEncryptData(handle: Long, plaintext: ByteArray): ByteArray?`
///
/// # Safety
///
/// See `with_vm`.
#[no_mangle]
pub unsafe extern "system" fn Java_com_example_securevm_SecureVm_nativeEncryptData(
    env: JNIEnv,
    _class: JClass,
    handle: jlong,
    plaintext: JByteArray,
) -> jbyteArray {
    let Ok(plaintext) = env.convert_byte_array(plaintext) else {
        return ptr::null_mut();
    };

    let Some(Ok(ciphertext)) = with_vm(handle, |vm| vm.encrypt_customer_data(&plaintext)) else {
        return ptr::null_mut();
    };

    env.byte_array_from_slice(&ciphertext)
        .map(|array| array.into_raw())
        .unwrap_or(ptr::null_mut())
}

/// Decrypts `ciphertext` with the customer-data key and returns the plaintext.
///
/// Returns `null` on any failure. The null return is deliberately opaque for
/// the same reason as `nativeEncryptData`.
///
/// Called from Kotlin: `private external fun nativeDecryptData(handle: Long, ciphertext: ByteArray): ByteArray?`
///
/// # Safety
///
/// See `with_vm`.
#[no_mangle]
pub unsafe extern "system" fn Java_com_example_securevm_SecureVm_nativeDecryptData(
    env: JNIEnv,
    _class: JClass,
    handle: jlong,
    ciphertext: JByteArray,
) -> jbyteArray {
    let Ok(ciphertext) = env.convert_byte_array(ciphertext) else {
        return ptr::null_mut();
    };

    let Some(Ok(plaintext)) = with_vm(handle, |vm| vm.decrypt_customer_data(&ciphertext)) else {
        return ptr::null_mut();
    };

    env.byte_array_from_slice(&plaintext)
        .map(|array| array.into_raw())
        .unwrap_or(ptr::null_mut())
}

/// Encrypts `value` with a passphrase-derived key and stores it under `key`
/// in the VM's encrypted key-value store.
///
/// The `passphrase` parameter is a `ByteArray` (not a `String`) because passing
/// raw bytes avoids charset encoding ambiguity — Kotlin's `String` is always
/// UTF-16, but if the passphrase were converted to a `String` and then back to
/// bytes, charset mismatch bugs could cause the passphrase to differ between
/// store and load calls. In production, derive the passphrase bytes from the
/// Android Keystore rather than a user-typed string.
///
/// Returns `JNI_TRUE` on success.
///
/// Called from Kotlin:
/// `private external fun nativeStoreSecret(handle: Long, key: String, value: ByteArray, passphrase: ByteArray): Boolean`
///
/// # Safety
///
/// See `with_vm`.
#[no_mangle]
pub unsafe extern "system" fn Java_com_example_securevm_SecureVm_nativeStoreSecret(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
    key: JString,
    value: JByteArray,
    passphrase: JByteArray,
) -> jboolean {
    let Ok(key) = env
        .get_string(&key)
        .map(|value| value.to_string_lossy().into_owned())
    else {
        return JNI_FALSE;
    };
    let Ok(value) = env.convert_byte_array(value) else {
        return JNI_FALSE;
    };
    let Ok(passphrase) = env.convert_byte_array(passphrase) else {
        return JNI_FALSE;
    };

    if with_vm(handle, |vm| {
        vm.store_secret(key, &value, &passphrase).is_ok()
    })
    .unwrap_or(false)
    {
        JNI_TRUE
    } else {
        JNI_FALSE
    }
}

/// Decrypts and returns the secret stored under `key`.
///
/// Returns `null` if the key does not exist or decryption fails (wrong
/// passphrase, corrupted record, or handle invalid). The null-on-failure
/// convention keeps the API simple while avoiding leaking error details.
///
/// The passphrase is passed as a `ByteArray` for the same reason as in
/// `nativeStoreSecret` — byte-for-byte identity with the value used at store
/// time.
///
/// Called from Kotlin:
/// `private external fun nativeLoadSecret(handle: Long, key: String, passphrase: ByteArray): ByteArray?`
///
/// # Safety
///
/// See `with_vm`.
#[no_mangle]
pub unsafe extern "system" fn Java_com_example_securevm_SecureVm_nativeLoadSecret(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
    key: JString,
    passphrase: JByteArray,
) -> jbyteArray {
    let Ok(key) = env
        .get_string(&key)
        .map(|value| value.to_string_lossy().into_owned())
    else {
        return ptr::null_mut();
    };
    let Ok(passphrase) = env.convert_byte_array(passphrase) else {
        return ptr::null_mut();
    };

    let Some(Ok(secret)) = with_vm(handle, |vm| vm.load_secret(&key, &passphrase)) else {
        return ptr::null_mut();
    };

    env.byte_array_from_slice(&secret)
        .map(|array| array.into_raw())
        .unwrap_or(ptr::null_mut())
}

/// Serializes all encrypted store records to a byte array that can be persisted
/// by the Kotlin caller.
///
/// Returns `null` if the handle is invalid or serialisation fails. The returned
/// blob contains only ciphertext — safe to write to `SharedPreferences` or a
/// database column. Restore it with `nativeImportStore` on the next launch.
///
/// Called from Kotlin: `private external fun nativeExportStore(handle: Long): ByteArray?`
///
/// # Safety
///
/// See `with_vm`.
#[no_mangle]
pub unsafe extern "system" fn Java_com_example_securevm_SecureVm_nativeExportStore(
    env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jbyteArray {
    let Some(Ok(blob)) = with_vm(handle, |vm| vm.export_store()) else {
        return ptr::null_mut();
    };

    env.byte_array_from_slice(&blob)
        .map(|array| array.into_raw())
        .unwrap_or(ptr::null_mut())
}

/// Replaces the current store with records from a blob produced by
/// `nativeExportStore`.
///
/// Returns `JNI_TRUE` on success. Idempotent in the sense that importing the
/// same blob twice replaces the store with itself.
///
/// Called from Kotlin: `private external fun nativeImportStore(handle: Long, blob: ByteArray): Boolean`
///
/// # Safety
///
/// See `with_vm`.
#[no_mangle]
pub unsafe extern "system" fn Java_com_example_securevm_SecureVm_nativeImportStore(
    env: JNIEnv,
    _class: JClass,
    handle: jlong,
    blob: JByteArray,
) -> jboolean {
    let Ok(bytes) = env.convert_byte_array(blob) else {
        return JNI_FALSE;
    };

    if with_vm(handle, |vm| vm.import_store(&bytes).is_ok()).unwrap_or(false) {
        JNI_TRUE
    } else {
        JNI_FALSE
    }
}

/// Called once by the Android runtime when `System.loadLibrary` loads the `.so`.
///
/// Captures the `JavaVM` pointer so Android Keystore operations — which run
/// outside any JNI entry-point context (e.g. from a background thread) — can
/// attach to the JVM on demand via `keystore::store_java_vm`.
///
/// Returns `JNI_VERSION_1_6` to tell the runtime which JNI version this
/// library was built against. The runtime aborts the load if the returned
/// version is not supported.
///
/// # Safety
///
/// `raw_vm` is the `JavaVM*` supplied by the Android runtime. It is guaranteed
/// to be valid for the entire process lifetime after this call returns.
#[no_mangle]
#[cfg(target_os = "android")]
pub unsafe extern "system" fn JNI_OnLoad(
    raw_vm: *mut jni::sys::JavaVM,
    _reserved: *mut std::ffi::c_void,
) -> jni::sys::jint {
    // Prevent core dumps and /proc/pid/mem reads. Must be the first call so
    // that no secrets are in memory before this protection is in place.
    libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
    if let Ok(vm) = jni::JavaVM::from_raw(raw_vm) {
        crate::keystore::store_java_vm(vm);
    }
    jni::sys::JNI_VERSION_1_6
}

/// Locks the VM mutex and runs `f` with a mutable reference to the VM.
///
/// Returns `None` if `handle` is zero (the Kotlin side zeroes the handle in
/// `close()` before calling `nativeDestroy`, so a zero handle means the VM
/// has already been destroyed). Otherwise acquires the `Mutex`, runs `f`, and
/// returns `Some(result)`.
///
/// ## Why `unsafe`?
///
/// This function dereferences `handle` as a raw pointer. This is safe
/// *provided the invariant holds*: every handle is a value previously returned
/// by `nativeCreate` that has not yet been passed to `nativeDestroy`. The
/// Kotlin `SecureVm` class enforces this:
/// - The handle is set only in the constructor (`nativeCreate`) and nowhere
///   else.
/// - `close()` zeroes the field *before* calling `nativeDestroy`, so the
///   zero-check here prevents use-after-free.
/// - The `private` visibility on the field prevents callers from supplying an
///   arbitrary value.
///
/// ## Mutex poison recovery
///
/// `Mutex::lock()` returns `Err(PoisonError)` only if a previous holder
/// panicked while holding the lock. Because all VM errors are returned as
/// `Result` (no panics in normal operation), this path should never be taken.
/// If it is, `into_inner()` recovers the guard — the VM's state invariants
/// still hold because any incomplete mutation would have been rolled back by
/// `stop()` before the panic propagated.
unsafe fn with_vm<T>(handle: jlong, f: impl FnOnce(&mut SecureVm) -> T) -> Option<T> {
    if handle == 0 {
        return None;
    }

    let mutex = &*(handle as *mut Mutex<SecureVm>);
    // lock() returns Err only if a previous holder panicked. Recovering the
    // guard via into_inner() is still safe because the VM's invariants hold
    // at all acquire/release points — they just weren't released cleanly.
    let mut guard = mutex.lock().unwrap_or_else(|e| e.into_inner());
    Some(f(&mut guard))
}
