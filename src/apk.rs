/// Native APK identity reading — no Java/Kotlin hook points.
///
/// All three functions bypass Kotlin entirely:
/// - `read_package_id`: reads `/proc/self/cmdline` directly.
/// - `read_signing_certificate`: probes v3 → v2 → v1 signing certificates
///   directly from the APK binary, bypassing any Kotlin/PackageManager path.
/// - `read_installer_package`: calls `PackageManager.getInstallerPackageName`
///   from within JNI, so no Kotlin method exists for an attacker to hook.
///
/// All paths and method names are obfuscated with `obfstr!` so they do not
/// appear as readable strings in `.rodata`.
use std::io::Read;

use obfstr::obfstr;

use crate::{Result, VmError};

/// APK Signing Block magic that appears immediately before the ZIP Central Directory.
const APK_SIG_BLOCK_MAGIC: &[u8; 16] = b"APK Sig Block 42";

/// Block-type ID for the APK Signature Scheme v2 payload.
const V2_SIGNATURE_SCHEME_ID: u32 = 0x7109_871a;

/// Block-type ID for the APK Signature Scheme v3 payload.
const V3_SIGNATURE_SCHEME_ID: u32 = 0xf053_68c0;

/// ZIP End-of-Central-Directory record signature (little-endian 0x06054b50).
const EOCD_SIGNATURE: &[u8; 4] = &[0x50, 0x4b, 0x05, 0x06];

/// Fixed size of a ZIP EOCD record before the variable-length comment field.
const EOCD_FIXED_SIZE: usize = 22;

/// Reads the package name from `/proc/self/cmdline`.
///
/// On Android every app process is named after its package. The kernel writes
/// the process name into `/proc/self/cmdline` as a null-terminated string,
/// optionally followed by a `:process` suffix for named service processes
/// (e.g. `com.example.app:sync`). We strip the suffix and return the base
/// package name.
pub(crate) fn read_package_id() -> Result<String> {
    let path = obfstr!("/proc/self/cmdline").to_owned();
    let raw = std::fs::read(&*path)
        .map_err(|_| VmError::InvalidInput("cannot read cmdline".into()))?;

    // Split on null bytes (argument separator) and colons (process suffix).
    let name = raw
        .split(|&b| b == 0 || b == b':')
        .next()
        .and_then(|b| String::from_utf8(b.to_vec()).ok())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| VmError::InvalidInput("empty package name in cmdline".into()))?;

    Ok(name)
}

/// Reads the DER-encoded signing certificate from the APK binary.
///
/// Probes in priority order:
///
/// 1. **APK Signature Scheme v3** (Android 9+, ID `0xf05368c0`) — located in
///    the APK Signing Block between the ZIP file entries and the Central
///    Directory.
/// 2. **APK Signature Scheme v2** (Android 7.0+, ID `0x7109871a`) — same
///    location, different block-type ID.
/// 3. **JAR / v1 signing** (all versions) — `META-INF/<signer>.RSA/.DSA/.EC`
///    entry inside the APK ZIP archive.
///
/// The APK is located by scanning `/proc/self/maps`; it is always
/// memory-mapped by the time the VM runs. The returned DER bytes match what
/// Android's `Signature.toByteArray()` returns, so the same SHA-256 hash is
/// produced regardless of which path is taken.
pub(crate) fn read_signing_certificate() -> Result<Vec<u8>> {
    let apk_path = find_apk_path()
        .ok_or_else(|| VmError::InvalidInput("APK not found".into()))?;

    let bytes = std::fs::read(&apk_path)
        .map_err(|_| VmError::InvalidInput("cannot open APK".into()))?;

    // v3 → v2 → v1 fallback chain.
    signing_block_cert(&bytes, V3_SIGNATURE_SCHEME_ID)
        .or_else(|| signing_block_cert(&bytes, V2_SIGNATURE_SCHEME_ID))
        .or_else(|| v1_cert(&bytes))
        .ok_or_else(|| VmError::InvalidInput("no signing certificate found in APK".into()))
}

/// Reads the installer package name by calling `PackageManager.getInstallerPackageName`
/// directly from JNI, bypassing any Kotlin-layer hook point.
///
/// The call goes straight from native code to the Android runtime's PM stub.
/// A Frida hook on a Kotlin method or an Xposed replacement of the Kotlin
/// wrapper cannot intercept this call — an attacker would need to hook at the
/// JVM method level or the Binder/PM service level.
///
/// Returns `None` if the app was sideloaded (no recorded installer), if the
/// original installer was uninstalled, or if any JNI call fails. The outer
/// caller maps `None` to `InstallerPolicy::Any` at runtime, or to a
/// validation failure if the license requires a specific installer.
///
/// Any pending Java exception produced by the PM call is cleared before this
/// function returns, so the JNI frame is left in a clean state.
pub(crate) fn read_installer_package(
    env: &mut jni::JNIEnv,
    context: &jni::objects::JObject,
) -> Option<String> {
    use jni::objects::{JString, JValue};

    // Inner closure so we can clear any pending exception unconditionally at
    // the end, regardless of where the Option chain short-circuits.
    let result = (|| {
        // context.getPackageManager()
        let get_pm   = obfstr!("getPackageManager").to_owned();
        let pm_sig   = obfstr!("()Landroid/content/pm/PackageManager;").to_owned();
        let pm = env
            .call_method(context, get_pm.as_str(), pm_sig.as_str(), &[])
            .ok()?
            .l()
            .ok()?;

        // Build a JString for our own package id (already read from cmdline).
        let package_id = read_package_id().ok()?;
        let j_pkg = env.new_string(&package_id).ok()?;

        // pm.getInstallerPackageName(packageId)
        let get_inst = obfstr!("getInstallerPackageName").to_owned();
        let inst_sig = obfstr!("(Ljava/lang/String;)Ljava/lang/String;").to_owned();
        let installer = env
            .call_method(
                &pm,
                get_inst.as_str(),
                inst_sig.as_str(),
                &[JValue::Object(j_pkg.as_ref())],
            )
            .ok()?
            .l()
            .ok()?;

        if installer.is_null() {
            return None;
        }

        let j_str = JString::from(installer);
        env.get_string(&j_str)
            .ok()
            .map(|s| s.to_string_lossy().into_owned())
    })();

    // Clear any pending Java exception so the JNI frame is clean for the
    // caller to make further JNI calls.
    if env.exception_check().unwrap_or(false) {
        let _ = env.exception_clear();
    }

    result
}

/// Scans `/proc/self/maps` for the path to the running APK.
///
/// Every line in `/proc/self/maps` has the form:
///   `addr-addr perms offset dev inode path`
/// The APK is always mapped (dex, resources, and native libs are read directly
/// from it), so its path appears at least once. We return the first `.apk` path
/// found.
fn find_apk_path() -> Option<String> {
    let proc_maps = obfstr!("/proc/self/maps").to_owned();
    let maps = std::fs::read_to_string(&proc_maps).ok()?;
    let apk_ext = obfstr!(".apk").to_owned();
    for line in maps.lines() {
        if let Some(path) = line.split_whitespace().last() {
            if path.ends_with(apk_ext.as_str()) {
                return Some(path.to_string());
            }
        }
    }
    None
}

/// Extracts the first X.509 certificate DER bytes from a PKCS#7 SignedData blob.
///
/// The PKCS#7 structure used by Android JAR signing is:
///
/// ```text
/// SEQUENCE {                         -- ContentInfo
///   OID (1.2.840.113549.1.7.2)       -- signedData
///   [0] {
///     SEQUENCE {                     -- SignedData
///       INTEGER                      -- version
///       SET { ... }                  -- digestAlgorithms
///       SEQUENCE { ... }             -- encapContentInfo
///       [0] {                        -- certificates  (tag 0xA0)
///         SEQUENCE { ... }           -- X.509 Certificate  ← we want this
///       }
///       SET { ... }                  -- signerInfos
///     }
///   }
/// }
/// ```
///
/// Returns the raw DER bytes of the first certificate (SEQUENCE tag + length +
/// value), which is identical to what `Signature.toByteArray()` returns on the
/// Java side.
fn extract_cert_from_pkcs7(data: &[u8]) -> Option<Vec<u8>> {
    let mut pos = 0;

    expect_tag(data, &mut pos, 0x30)?; // ContentInfo SEQUENCE
    read_length(data, &mut pos)?;

    expect_tag(data, &mut pos, 0x06)?; // OID
    let oid_len = read_length(data, &mut pos)?;
    pos += oid_len;

    expect_tag(data, &mut pos, 0xA0)?; // [0] EXPLICIT content
    read_length(data, &mut pos)?;

    expect_tag(data, &mut pos, 0x30)?; // SignedData SEQUENCE
    read_length(data, &mut pos)?;

    expect_tag(data, &mut pos, 0x02)?; // version INTEGER
    let ver_len = read_length(data, &mut pos)?;
    pos += ver_len;

    expect_tag(data, &mut pos, 0x31)?; // digestAlgorithms SET
    let da_len = read_length(data, &mut pos)?;
    pos += da_len;

    expect_tag(data, &mut pos, 0x30)?; // encapContentInfo SEQUENCE
    let ci_len = read_length(data, &mut pos)?;
    pos += ci_len;

    expect_tag(data, &mut pos, 0xA0)?; // [0] certificates
    let certs_len = read_length(data, &mut pos)?;
    let certs_end = pos + certs_len;

    // The first certificate starts here. Record the position BEFORE consuming
    // the tag so the returned slice includes the full DER (tag + length + value).
    let cert_start = pos;
    expect_tag(data, &mut pos, 0x30)?; // Certificate SEQUENCE
    let cert_body_len = read_length(data, &mut pos)?;
    let cert_end = pos + cert_body_len;

    if cert_end > certs_end || cert_end > data.len() {
        return None;
    }

    Some(data[cert_start..cert_end].to_vec())
}

/// Advances `pos` past a single DER tag byte, returning `None` if it does not
/// match `expected`.
fn expect_tag(data: &[u8], pos: &mut usize, expected: u8) -> Option<()> {
    if *data.get(*pos)? != expected {
        return None;
    }
    *pos += 1;
    Some(())
}

/// Reads a DER length field starting at `pos`, advances `pos` past it, and
/// returns the decoded length.
///
/// Handles short form (< 0x80) and long form (up to 4 length bytes).
fn read_length(data: &[u8], pos: &mut usize) -> Option<usize> {
    let first = *data.get(*pos)? as usize;
    *pos += 1;

    if first < 0x80 {
        return Some(first);
    }

    let num_bytes = first & 0x7f;
    if num_bytes == 0 || num_bytes > 4 {
        return None;
    }

    let mut len = 0usize;
    for _ in 0..num_bytes {
        len = (len << 8) | (*data.get(*pos)? as usize);
        *pos += 1;
    }
    Some(len)
}

// ── v1 (JAR signing) ─────────────────────────────────────────────────────────

/// Extracts the signing certificate from the v1 (JAR) `META-INF/*.RSA` entry.
///
/// Returns `None` if the APK has no JAR-signing entry or if the PKCS#7 blob
/// cannot be parsed — callers should treat `None` as "v1 not present".
fn v1_cert(apk_bytes: &[u8]) -> Option<Vec<u8>> {
    use std::io::Cursor;

    let cursor = Cursor::new(apk_bytes);
    let mut archive = zip::ZipArchive::new(cursor).ok()?;

    let meta_inf = obfstr!("META-INF/").to_owned();
    let ext_rsa  = obfstr!(".RSA").to_owned();
    let ext_dsa  = obfstr!(".DSA").to_owned();
    let ext_ec   = obfstr!(".EC").to_owned();

    let mut sig_entry_name = None;
    for i in 0..archive.len() {
        if let Ok(entry) = archive.by_index(i) {
            let name = entry.name().to_owned();
            if name.starts_with(&*meta_inf)
                && (name.ends_with(&*ext_rsa)
                    || name.ends_with(&*ext_dsa)
                    || name.ends_with(&*ext_ec))
            {
                sig_entry_name = Some(name);
                break;
            }
        }
    }

    let sig_entry_name = sig_entry_name?;
    let mut entry = archive.by_name(&sig_entry_name).ok()?;

    let mut pkcs7 = Vec::new();
    entry.read_to_end(&mut pkcs7).ok()?;

    extract_cert_from_pkcs7(&pkcs7)
}

// ── v2 / v3 (APK Signing Block) ──────────────────────────────────────────────

/// Extracts the first signer's DER certificate from an APK Signing Block entry
/// identified by `scheme_id` (`V2_SIGNATURE_SCHEME_ID` or `V3_SIGNATURE_SCHEME_ID`).
///
/// Returns `None` if the APK has no signing block, the requested scheme is
/// absent, or the signer data is malformed.
fn signing_block_cert(apk: &[u8], scheme_id: u32) -> Option<Vec<u8>> {
    let cd_offset = find_cd_offset(apk)?;
    let pairs     = signing_block_pairs(apk, cd_offset)?;
    let sig_value = find_in_pairs(pairs, scheme_id)?;
    cert_from_v2v3_signers(sig_value)
}

/// Locates the ZIP Central Directory offset by scanning backwards for the EOCD
/// record signature (`PK\x05\x06`).
///
/// Handles ZIP comment fields up to 65 535 bytes long. Does not handle
/// ZIP64 (APKs are rarely larger than 4 GiB in practice).
fn find_cd_offset(apk: &[u8]) -> Option<usize> {
    if apk.len() < EOCD_FIXED_SIZE {
        return None;
    }

    // Scan backwards from the earliest possible EOCD position.
    let scan_end   = apk.len() - EOCD_FIXED_SIZE;
    let scan_start = scan_end.saturating_sub(u16::MAX as usize);

    let eocd_off = (scan_start..=scan_end)
        .rev()
        .find(|&i| &apk[i..i + 4] == EOCD_SIGNATURE)?;

    // Central Directory offset lives at bytes 16-19 of the EOCD record.
    let cd_offset = u32::from_le_bytes(
        apk[eocd_off + 16..eocd_off + 20].try_into().ok()?
    ) as usize;

    // Sanity check: CD must not start after the EOCD.
    if cd_offset > eocd_off {
        return None;
    }

    Some(cd_offset)
}

/// Returns a slice covering the ID-value pairs inside the APK Signing Block,
/// or `None` if no signing block is present.
///
/// The APK Signing Block is structured as:
///
/// ```text
/// [8]  size_of_block  (= pairs_len + 24; excludes this leading field)
/// [N]  ID-value pairs
/// [8]  size_of_block  (repeated)
/// [16] "APK Sig Block 42"
/// ```
///
/// The block ends immediately before the Central Directory at `cd_offset`.
fn signing_block_pairs(apk: &[u8], cd_offset: usize) -> Option<&[u8]> {
    // The 16-byte magic must sit just before cd_offset.
    if cd_offset < 24 {
        return None;
    }
    let magic_start = cd_offset - 16;
    if &apk[magic_start..cd_offset] != APK_SIG_BLOCK_MAGIC {
        return None;
    }

    // Read the trailing size field (8 bytes before the magic).
    let size_off  = cd_offset - 24;
    let block_size = u64::from_le_bytes(
        apk[size_off..size_off + 8].try_into().ok()?
    ) as usize;

    // block_size = pairs_len + 24; must be at least 24 (empty pairs).
    if block_size < 24 {
        return None;
    }

    // ID-value pairs span from cd_offset - block_size to cd_offset - 24.
    let pairs_start = cd_offset.checked_sub(block_size)?;
    let pairs_end   = cd_offset - 24;

    // Verify the leading size field matches.
    if pairs_start < 8 {
        return None;
    }
    let leading = u64::from_le_bytes(
        apk[pairs_start - 8..pairs_start].try_into().ok()?
    ) as usize;
    if leading != block_size {
        return None;
    }

    if pairs_end > apk.len() || pairs_start > pairs_end {
        return None;
    }

    Some(&apk[pairs_start..pairs_end])
}

/// Iterates over the length-prefixed ID-value pairs in the APK Signing Block
/// and returns the value slice for the first pair whose ID matches `target_id`.
///
/// Each pair is encoded as:
/// ```text
/// [8] pair_size  (= id_bytes(4) + value_bytes)
/// [4] ID
/// [pair_size - 4] value
/// ```
fn find_in_pairs(pairs: &[u8], target_id: u32) -> Option<&[u8]> {
    let mut pos = 0;
    while pos + 12 <= pairs.len() {
        let pair_size = u64::from_le_bytes(
            pairs[pos..pos + 8].try_into().ok()?
        ) as usize;
        if pair_size < 4 {
            break;
        }
        let end = pos + 8 + pair_size;
        if end > pairs.len() {
            break;
        }
        let id = u32::from_le_bytes(pairs[pos + 8..pos + 12].try_into().ok()?);
        if id == target_id {
            return Some(&pairs[pos + 12..end]);
        }
        pos = end;
    }
    None
}

/// Parses the v2/v3 signer sequence and returns the DER X.509 certificate of
/// the first signer.
///
/// The v2/v3 signer block value (after the 4-byte block ID) is:
///
/// ```text
/// uint32  length of "signers" sequence
///   uint32  length of first signer
///     uint32  length of "signed_data"
///       uint32  length of "digests" sequence  → skip
///       uint32  length of "certificates" sequence
///         uint32  length of first certificate DER blob
///         bytes   DER  ← this is what we return
///       …
///     …
///   …
/// ```
///
/// All length prefixes are unsigned 32-bit little-endian integers.
fn cert_from_v2v3_signers(value: &[u8]) -> Option<Vec<u8>> {
    let mut pos = 0;

    // signers: uint32-prefixed sequence
    let signers_len = read_le_u32(value, &mut pos)?;
    if pos + signers_len > value.len() { return None; }

    // first signer: uint32-prefixed blob
    let signer_len = read_le_u32(value, &mut pos)?;
    if pos + signer_len > value.len() { return None; }

    // signed_data: uint32-prefixed blob
    let sd_len = read_le_u32(value, &mut pos)?;
    let sd_end = pos + sd_len;
    if sd_end > value.len() { return None; }

    // digests sequence: skip
    let digests_len = read_le_u32(value, &mut pos)?;
    pos = pos.checked_add(digests_len)?;
    if pos > sd_end { return None; }

    // certificates sequence: uint32-prefixed
    let certs_len = read_le_u32(value, &mut pos)?;
    let certs_end = pos + certs_len;
    if certs_end > sd_end { return None; }

    // first certificate: uint32-prefixed DER blob
    let cert_len = read_le_u32(value, &mut pos)?;
    if pos + cert_len > certs_end { return None; }

    Some(value[pos..pos + cert_len].to_vec())
}

/// Reads a 4-byte little-endian `u32` from `data[*pos..]`, advances `*pos`,
/// and returns the value as `usize`.
fn read_le_u32(data: &[u8], pos: &mut usize) -> Option<usize> {
    if *pos + 4 > data.len() { return None; }
    let v = u32::from_le_bytes(data[*pos..*pos + 4].try_into().ok()?) as usize;
    *pos += 4;
    Some(v)
}
