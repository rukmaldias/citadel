//! Android Keystore integration for hardware-backed AES-256-GCM encryption.
//!
//! The customer data key never appears in Rust memory. Instead, an AES-256 key
//! is generated inside the device's secure hardware and all AES-GCM operations
//! happen inside that boundary. The hierarchy is:
//!
//! ```text
//! StrongBox  — dedicated secure microprocessor (e.g. Google Titan M, Samsung SE)
//! TEE        — ARM TrustZone isolated execution, same SoC as main CPU
//! (software) — software Keystore; no hardware isolation; handled by vm.rs fallback
//! ```
//!
//! `use_or_generate_key` tries StrongBox first. If the device does not have a
//! StrongBox (`StrongBoxUnavailableException`), it falls back to TEE. If both
//! fail (very old or very cheap devices), it returns `None` and `vm.rs` falls
//! back to the XOR-masked software path.
//!
//! ## Key alias
//!
//! The Keystore entry's alias is `"svm_" + hex(sha256(customer_key))` (full
//! 32-byte hash, 64 hex chars). This is deterministic per license so the same
//! hardware key is found on every subsequent launch without re-generating. The
//! alias is a hash — it does not reveal the customer key.
//!
//! ## Blob format
//!
//! Encryption returns `[12-byte GCM IV][ciphertext + 16-byte GCM tag]`, which is
//! identical to the software-path blob produced by `firmware::encrypt_customer_data`.
//! The caller does not need to know which path was used.
//!
//! ## JVM availability
//!
//! `JNI_OnLoad` (in `jni_api.rs`) stores the `JavaVM` pointer in `JAVA_VM` when
//! Android first loads the `.so`. All Keystore operations require this pointer.
//! If `JNI_OnLoad` has not yet been called (or was never called), every function
//! here returns `None`/`false`.

use std::sync::OnceLock;

use jni::{
    objects::{JByteArray, JObject, JValue},
    JNIEnv, JavaVM,
};
use sha2::{Digest, Sha256};

/// Stored by `JNI_OnLoad`; used to obtain a `JNIEnv` whenever Keystore calls
/// are needed outside of a JNI entry-point context.
static JAVA_VM: OnceLock<JavaVM> = OnceLock::new();

/// Called once from `JNI_OnLoad` to make the JVM available for Keystore ops.
pub(crate) fn store_java_vm(vm: JavaVM) {
    JAVA_VM.set(vm).ok();
}

/// Derives the AndroidKeyStore alias for a customer data key.
///
/// The alias is `"svm_"` followed by the full 32-byte `sha256(key)` in
/// lowercase hex (64 hex chars total). Deterministic per key; doesn't reveal
/// the key material.
pub(crate) fn derive_alias(customer_key: &[u8; 32]) -> String {
    let hash = Sha256::digest(customer_key);
    let mut alias = String::with_capacity(4 + 64);
    alias.push_str("svm_");
    for b in &hash[..] {
        alias.push_str(&format!("{b:02x}"));
    }
    alias
}

/// Ensures the AES-256 Keystore key for `alias` exists, generating it if not.
///
/// Returns `Some(())` when the key is ready (existing or newly generated).
/// Returns `None` if both StrongBox and TEE generation fail, signalling that
/// the caller should fall back to the software XOR-mask path.
pub(crate) fn use_or_generate_key(alias: &str) -> Option<()> {
    // Fast path: same license used previously; the key already exists.
    if with_env(|env| key_exists_jni(env, alias)) == Some(true) {
        return Some(());
    }
    // Try StrongBox (Titan M / Samsung SE chip). Clears StrongBoxUnavailableException
    // on failure so the next JNI call can proceed cleanly.
    if with_env(|env| {
        let r = generate_key_jni(env, alias, true);
        if r.is_err() {
            let _ = env.exception_clear();
        }
        r
    })
    .is_some()
    {
        return Some(());
    }
    // Fall back to TEE (ARM TrustZone).
    with_env(|env| generate_key_jni(env, alias, false)).map(|_| ())
}

/// Encrypts `plaintext` with the AES-256-GCM key in AndroidKeyStore.
///
/// Returns `[12-byte IV][ciphertext + 16-byte tag]` or `None` on any failure.
pub(crate) fn ks_encrypt(alias: &str, plaintext: &[u8]) -> Option<Vec<u8>> {
    with_env(|env| encrypt_jni(env, alias, plaintext))
}

/// Decrypts a blob produced by `ks_encrypt`. Returns `None` on any failure
/// (short blob, bad tag, missing key, …).
pub(crate) fn ks_decrypt(alias: &str, blob: &[u8]) -> Option<Vec<u8>> {
    if blob.len() < 12 {
        return None;
    }
    with_env(|env| decrypt_jni(env, alias, blob))
}

// ── Internal: JVM attachment ──────────────────────────────────────────────────

fn with_env<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&mut JNIEnv<'_>) -> jni::errors::Result<R>,
{
    let vm = JAVA_VM.get()?;
    let mut guard = vm.attach_current_thread().ok()?;
    f(&mut guard).ok()
}

// ── Internal: JNI implementations ────────────────────────────────────────────

/// Returns `true` if `alias` is present in the AndroidKeyStore.
fn key_exists_jni(env: &mut JNIEnv<'_>, alias: &str) -> jni::errors::Result<bool> {
    let ks = open_keystore(env)?;
    let j_alias = env.new_string(alias)?;
    env.call_method(
        &ks,
        "containsAlias",
        "(Ljava/lang/String;)Z",
        &[JValue::Object(j_alias.as_ref())],
    )?
    .z()
}

/// Generates an AES-256/GCM key in the AndroidKeyStore.
///
/// If `strongbox` is `true`, `setIsStrongBoxBacked(true)` is set on the spec.
/// Android throws `StrongBoxUnavailableException` at runtime if the device does
/// not have a StrongBox. The caller (`use_or_generate_key`) clears that
/// exception and retries without StrongBox.
fn generate_key_jni(
    env: &mut JNIEnv<'_>,
    alias: &str,
    strongbox: bool,
) -> jni::errors::Result<()> {
    // KeyGenerator.getInstance("AES", "AndroidKeyStore")
    let kg_class = env.find_class("javax/crypto/KeyGenerator")?;
    let j_aes = env.new_string("AES")?;
    let j_aks = env.new_string("AndroidKeyStore")?;
    let key_gen = env
        .call_static_method(
            &kg_class,
            "getInstance",
            "(Ljava/lang/String;Ljava/lang/String;)Ljavax/crypto/KeyGenerator;",
            &[JValue::Object(j_aes.as_ref()), JValue::Object(j_aks.as_ref())],
        )?
        .l()?;

    // new KeyGenParameterSpec.Builder(alias, PURPOSE_ENCRYPT | PURPOSE_DECRYPT)
    let builder_class =
        env.find_class("android/security/keystore/KeyGenParameterSpec$Builder")?;
    let j_alias = env.new_string(alias)?;
    let builder = env.new_object(
        &builder_class,
        "(Ljava/lang/String;I)V",
        &[JValue::Object(j_alias.as_ref()), JValue::Int(3)], // 1|2 = ENCRYPT|DECRYPT
    )?;

    // .setBlockModes(new String[]{"GCM"})
    let j_str_class = env.find_class("java/lang/String")?;
    let j_gcm = env.new_string("GCM")?;
    let j_gcm_obj: &JObject<'_> = j_gcm.as_ref();
    let block_modes = env.new_object_array(1, &j_str_class, j_gcm_obj)?;
    env.call_method(
        &builder,
        "setBlockModes",
        "([Ljava/lang/String;)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
        &[JValue::Object(block_modes.as_ref())],
    )?;

    // .setEncryptionPaddings(new String[]{"NoPadding"})
    let j_nopad = env.new_string("NoPadding")?;
    let j_nopad_obj: &JObject<'_> = j_nopad.as_ref();
    let enc_pads = env.new_object_array(1, &j_str_class, j_nopad_obj)?;
    env.call_method(
        &builder,
        "setEncryptionPaddings",
        "([Ljava/lang/String;)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
        &[JValue::Object(enc_pads.as_ref())],
    )?;

    // .setKeySize(256)
    env.call_method(
        &builder,
        "setKeySize",
        "(I)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
        &[JValue::Int(256)],
    )?;

    // .setIsStrongBoxBacked(true)  — only when requesting StrongBox
    if strongbox {
        env.call_method(
            &builder,
            "setIsStrongBoxBacked",
            "(Z)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
            &[JValue::Bool(1)], // JNI_TRUE
        )?;
    }

    // spec = builder.build()
    let spec = env
        .call_method(
            &builder,
            "build",
            "()Landroid/security/keystore/KeyGenParameterSpec;",
            &[],
        )?
        .l()?;

    // keyGen.init(spec); keyGen.generateKey();
    env.call_method(
        &key_gen,
        "init",
        "(Ljava/security/spec/AlgorithmParameterSpec;)V",
        &[JValue::Object(spec.as_ref())],
    )?;
    env.call_method(&key_gen, "generateKey", "()Ljavax/crypto/SecretKey;", &[])?;
    Ok(())
}

fn encrypt_jni(
    env: &mut JNIEnv<'_>,
    alias: &str,
    plaintext: &[u8],
) -> jni::errors::Result<Vec<u8>> {
    let key = get_key(env, alias)?;

    // Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding")
    let cipher = aes_gcm_cipher(env)?;

    // cipher.init(ENCRYPT_MODE=1, key)  — Android auto-generates the 12-byte IV
    env.call_method(
        &cipher,
        "init",
        "(ILjava/security/Key;)V",
        &[JValue::Int(1), JValue::Object(key.as_ref())],
    )?;

    // iv = cipher.getIV()  — 12 bytes
    let iv_obj = env.call_method(&cipher, "getIV", "()[B", &[])?.l()?;
    let iv = env.convert_byte_array(&JByteArray::from(iv_obj))?;

    // ct_with_tag = cipher.doFinal(plaintext)
    let j_pt = env.byte_array_from_slice(plaintext)?;
    let ct_obj = env
        .call_method(
            &cipher,
            "doFinal",
            "([B)[B",
            &[JValue::Object(j_pt.as_ref())],
        )?
        .l()?;
    let ct = env.convert_byte_array(&JByteArray::from(ct_obj))?;

    // blob = [iv || ciphertext+tag]  — same layout as firmware::encrypt_customer_data
    let mut blob = Vec::with_capacity(iv.len() + ct.len());
    blob.extend_from_slice(&iv);
    blob.extend_from_slice(&ct);
    Ok(blob)
}

fn decrypt_jni(
    env: &mut JNIEnv<'_>,
    alias: &str,
    blob: &[u8],
) -> jni::errors::Result<Vec<u8>> {
    let (iv, ct) = blob.split_at(12);

    // GCMParameterSpec spec = new GCMParameterSpec(128, iv)
    let j_iv = env.byte_array_from_slice(iv)?;
    let spec_class = env.find_class("javax/crypto/spec/GCMParameterSpec")?;
    let spec = env.new_object(
        &spec_class,
        "(I[B)V",
        &[JValue::Int(128), JValue::Object(j_iv.as_ref())],
    )?;

    let key = get_key(env, alias)?;
    let cipher = aes_gcm_cipher(env)?;

    // cipher.init(DECRYPT_MODE=2, key, spec)
    env.call_method(
        &cipher,
        "init",
        "(ILjava/security/Key;Ljava/security/spec/AlgorithmParameterSpec;)V",
        &[
            JValue::Int(2),
            JValue::Object(key.as_ref()),
            JValue::Object(spec.as_ref()),
        ],
    )?;

    // plaintext = cipher.doFinal(ciphertext+tag)
    let j_ct = env.byte_array_from_slice(ct)?;
    let pt_obj = env
        .call_method(
            &cipher,
            "doFinal",
            "([B)[B",
            &[JValue::Object(j_ct.as_ref())],
        )?
        .l()?;
    env.convert_byte_array(&JByteArray::from(pt_obj))
}

// ── Shared helpers ────────────────────────────────────────────────────────────

/// Opens the AndroidKeyStore provider and calls `load(null)`.
fn open_keystore<'local>(env: &mut JNIEnv<'local>) -> jni::errors::Result<JObject<'local>> {
    let ks_class = env.find_class("java/security/KeyStore")?;
    let j_aks = env.new_string("AndroidKeyStore")?;
    let ks = env
        .call_static_method(
            &ks_class,
            "getInstance",
            "(Ljava/lang/String;)Ljava/security/KeyStore;",
            &[JValue::Object(j_aks.as_ref())],
        )?
        .l()?;
    let null = JObject::null();
    env.call_method(
        &ks,
        "load",
        "(Ljava/security/KeyStore$LoadStoreParameter;)V",
        &[JValue::Object(null.as_ref())],
    )?;
    Ok(ks)
}

/// Retrieves `ks.getKey(alias, null)` from AndroidKeyStore.
fn get_key<'local>(env: &mut JNIEnv<'local>, alias: &str) -> jni::errors::Result<JObject<'local>> {
    let ks = open_keystore(env)?;
    let j_alias = env.new_string(alias)?;
    let null = JObject::null();
    env.call_method(
        &ks,
        "getKey",
        "(Ljava/lang/String;[C)Ljava/security/Key;",
        &[JValue::Object(j_alias.as_ref()), JValue::Object(null.as_ref())],
    )?
    .l()
}

/// Returns `Cipher.getInstance("AES/GCM/NoPadding")`.
fn aes_gcm_cipher<'local>(env: &mut JNIEnv<'local>) -> jni::errors::Result<JObject<'local>> {
    let cipher_class = env.find_class("javax/crypto/Cipher")?;
    let j_algo = env.new_string("AES/GCM/NoPadding")?;
    env.call_static_method(
        &cipher_class,
        "getInstance",
        "(Ljava/lang/String;)Ljavax/crypto/Cipher;",
        &[JValue::Object(j_algo.as_ref())],
    )?
    .l()
}
