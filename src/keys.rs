/// Returns the Ed25519 public key used to verify the codesign asset bundle.
///
/// The key bytes are obfuscated at compile time by `obfstr::obfbytes!` — they
/// are XOR-encrypted with a random per-build key and decrypted on the stack at
/// call time. The `.rodata` and `.data` sections of the `.so` contain no
/// readable 32-byte key blob; an attacker scanning for high-entropy constants
/// finds nothing.
///
/// **Replace the placeholder bytes below with your actual 32-byte Ed25519
/// public key before building a production release.** Generate the key with:
///
/// ```text
/// # One-time: generate a keypair
/// openssl genpkey -algorithm ed25519 -out vendor_private.pem
///
/// # Extract the 32-byte public key as hex
/// openssl pkey -in vendor_private.pem -pubout -outform DER \
///   | tail -c 32 | xxd -p
/// ```
///
/// Paste the 64 hex characters as `\xNN` byte literals below.
#[cfg(feature = "jni")]
pub(crate) fn codesign_public_key() -> [u8; 32] {
    // obfbytes! stores an XOR-encrypted copy in the binary and decrypts it
    // onto the stack at runtime. Change the bytes inside to your actual key.
    let key = *obfstr::obfbytes!(
        b"\x00\x00\x00\x00\x00\x00\x00\x00\
          \x00\x00\x00\x00\x00\x00\x00\x00\
          \x00\x00\x00\x00\x00\x00\x00\x00\
          \x00\x00\x00\x00\x00\x00\x00\x00"
    );
    // Catch the placeholder in debug non-test builds.
    // Integration tests legitimately use the zero key and are not JNI builds.
    debug_assert_ne!(
        key, [0u8; 32],
        "codesign_public_key is all-zeros — replace with vendor Ed25519 public key before shipping"
    );
    key
}
