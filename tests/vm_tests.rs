use ed25519_dalek::{Signer, SigningKey};
use secure_android_vm::{
    encrypt_firmware, encrypt_license_for_signing_certificate, sha256, sign_code_assets,
    CodeIdentity, FirmwareLicense, InstallerPolicy, Instruction, OpcodeTable, Program, SecureStore,
    SecureVm, StartCode, VmError,
};

#[test]
fn runs_loaded_program() {
    let mut vm = SecureVm::new();
    let program = Program::new(vec![
        Instruction::PushI64(7),
        Instruction::PushI64(5),
        Instruction::Mul,
        Instruction::PushI64(1),
        Instruction::Add,
        Instruction::Halt,
    ])
    .unwrap();

    vm.load_program(program).unwrap();
    vm.start().unwrap();

    let report = vm.run().unwrap();

    assert_eq!(report.result, 36);
    assert_eq!(report.steps, 6);
}

#[test]
fn requires_vm_to_be_started() {
    let mut vm = SecureVm::new();

    let error = vm.run().unwrap_err();

    assert!(matches!(error, VmError::Stopped));
}

#[test]
fn stack_is_clean_after_runtime_error() {
    let mut vm = SecureVm::new();
    // Push a value then divide by zero — the stack has one item when the error fires.
    vm.load_program(Program::new(vec![
        Instruction::PushI64(1),
        Instruction::PushI64(0),
        Instruction::Div,
        Instruction::Halt,
    ]).unwrap()).unwrap();
    vm.start().unwrap();

    assert!(matches!(vm.run().unwrap_err(), VmError::DivisionByZero));

    // A successful run after the error must return 0 (empty stack), not a
    // leftover value from the failed execution.
    vm.load_program(Program::new(vec![Instruction::Halt]).unwrap()).unwrap();
    let report = vm.run().unwrap();
    assert_eq!(report.result, 0);
}

#[test]
fn round_trips_bytecode() {
    let program = Program::new(vec![
        Instruction::PushI64(10),
        Instruction::Store(0),
        Instruction::Load(0),
        Instruction::PushI64(3),
        Instruction::Sub,
        Instruction::Halt,
    ])
    .unwrap();

    let decoded = Program::from_bytes(&program.to_bytes()).unwrap();

    assert_eq!(decoded, program);
}

#[test]
fn encrypts_and_decrypts_secret() {
    let mut vm = SecureVm::new();
    let passphrase = b"correct horse battery staple";

    vm.store_secret("api_token", b"top-secret", passphrase)
        .unwrap();

    let (_salt, exported) = vm.secure_store().export_records();
    // With HMAC-hashed key names the map is keyed by [u8;32] — there is no
    // plaintext "api_token" key to index by. Verify the one record exists and
    // its ciphertext is not the raw plaintext.
    assert_eq!(exported.len(), 1);
    let record = exported.values().next().unwrap();
    assert_ne!(record.ciphertext, b"top-secret");

    // Verify that the key name does not appear in the serialized blob.
    let blob = vm.secure_store().to_bytes().unwrap();
    assert!(!blob.windows(b"api_token".len()).any(|w| w == b"api_token"));
    assert_eq!(
        vm.load_secret("api_token", passphrase).unwrap(),
        b"top-secret"
    );
}

#[test]
fn rejects_wrong_secret_passphrase() {
    let mut vm = SecureVm::new();

    vm.store_secret("api_token", b"top-secret", b"correct-passphrase")
        .unwrap();

    assert!(vm
        .load_secret("api_token", b"incorrect-passphrase")
        .is_err());
}

#[test]
fn starts_from_encrypted_license_and_firmware_bundle() {
    let signing_certificate = b"debug-app-signing-certificate";
    let identity = CodeIdentity::from_certificate(
        "com.example.securevm",
        signing_certificate,
        Some("com.android.vending".to_string()),
    )
    .unwrap();
    let program = Program::new(vec![
        Instruction::PushI64(20),
        Instruction::PushI64(22),
        Instruction::Add,
        Instruction::Halt,
    ])
    .unwrap();
    let license = FirmwareLicense::new(
        "com.example.securevm",
        identity.signing_cert_sha256,
        InstallerPolicy::Required("com.android.vending".to_string()),
        sha256(&program.to_bytes()),
        [7_u8; 32],
        [17_u8; 32],
        [0_u8; 32], // identity opcode table
        0,          // no expiry
        0,          // firmware_flags: 0 = no debug
    );
    // Constant-byte keys are only acceptable in tests. Never use predictable
    // byte patterns for a production Ed25519 signing key.
    let signing_key = SigningKey::from_bytes(&[3_u8; 32]);
    let verifying_key = signing_key.verifying_key().to_bytes();

    let encrypted_license =
        encrypt_license_for_signing_certificate(&license, signing_certificate).unwrap();
    let encrypted_firmware =
        encrypt_firmware(&program.to_bytes(), &license.firmware_key().unwrap()).unwrap();
    let codesign = sign_code_assets(
        &identity,
        &encrypted_license,
        &encrypted_firmware,
        |payload| Ok(signing_key.sign(payload).to_bytes()),
    )
    .unwrap();

    let mut vm = SecureVm::new();
    let start_code = vm.start_with_verified_assets(
        "com.example.securevm",
        Some("com.android.vending"),
        signing_certificate,
        &encrypted_license,
        &encrypted_firmware,
        &codesign,
        &verifying_key,
    );

    assert_eq!(start_code, StartCode::Ok);
    assert_eq!(vm.run().unwrap().result, 42);

    let encrypted_data = vm.encrypt_customer_data(b"sqlite-row-or-pref").unwrap();
    assert_ne!(encrypted_data, b"sqlite-row-or-pref");
    let decrypted_data = vm.decrypt_customer_data(&encrypted_data).unwrap();
    assert_eq!(decrypted_data, b"sqlite-row-or-pref");
}

#[test]
fn rejects_license_for_different_signing_certificate() {
    let identity =
        CodeIdentity::from_certificate("com.example.securevm", b"original-certificate", None)
            .unwrap();
    let program = Program::new(vec![Instruction::PushI64(1), Instruction::Halt]).unwrap();
    let license = FirmwareLicense::new(
        "com.example.securevm",
        identity.signing_cert_sha256,
        InstallerPolicy::Any,
        sha256(&program.to_bytes()),
        [9_u8; 32],
        [19_u8; 32],
        [0_u8; 32], // identity opcode table
        0,          // no expiry
        0,          // firmware_flags: 0 = no debug
    );
    // Constant-byte keys are only acceptable in tests.
    let signing_key = SigningKey::from_bytes(&[4_u8; 32]);
    let verifying_key = signing_key.verifying_key().to_bytes();

    let encrypted_license =
        encrypt_license_for_signing_certificate(&license, b"original-certificate").unwrap();
    let encrypted_firmware =
        encrypt_firmware(&program.to_bytes(), &license.firmware_key().unwrap()).unwrap();
    let codesign = sign_code_assets(
        &identity,
        &encrypted_license,
        &encrypted_firmware,
        |payload| Ok(signing_key.sign(payload).to_bytes()),
    )
    .unwrap();

    let mut vm = SecureVm::new();

    assert_eq!(
        vm.start_with_verified_assets(
            "com.example.securevm",
            None,
            b"re-signed-certificate",
            &encrypted_license,
            &encrypted_firmware,
            &codesign,
            &verifying_key,
        ),
        StartCode::IntegrityFailed
    );
}

#[test]
fn secure_store_round_trips_through_bytes() {
    let mut vm = SecureVm::new();
    let passphrase = b"correct horse battery staple";

    vm.store_secret("token", b"secret-value", passphrase).unwrap();
    vm.store_secret("key2", b"another-secret", passphrase).unwrap();

    let blob = vm.export_store().unwrap();

    // The blob must not contain any plaintext.
    assert!(!blob.windows(b"secret-value".len()).any(|w| w == b"secret-value"));
    assert!(!blob.windows(b"another-secret".len()).any(|w| w == b"another-secret"));

    // Restore into a fresh store and verify decryption still works.
    let restored = SecureStore::from_bytes(&blob).unwrap();
    assert_eq!(restored.get("token", passphrase).unwrap(), b"secret-value");
    assert_eq!(restored.get("key2", passphrase).unwrap(), b"another-secret");
}

#[test]
fn secure_store_rejects_corrupt_blob() {
    let mut vm = SecureVm::new();
    vm.store_secret("k", b"v-value-here", b"correct-passphrase-x").unwrap();
    let mut blob = vm.export_store().unwrap();

    // Flip a byte in the ciphertext region.
    let last = blob.last_mut().unwrap();
    *last ^= 0xff;

    assert!(SecureStore::from_bytes(&blob).is_err()
        || SecureStore::from_bytes(&blob)
            .unwrap()
            .get("k", b"correct-passphrase-x")
            .is_err());
}

#[test]
fn per_license_opcode_table_round_trips() {
    // Non-zero seed → shuffled opcode table. Firmware encoded with this table
    // must decode correctly when the same seed is in the license.
    let opcode_seed = [42_u8; 32];
    let table = OpcodeTable::from_seed(&opcode_seed);

    let program = Program::new(vec![
        Instruction::PushI64(6),
        Instruction::PushI64(7),
        Instruction::Mul,
        Instruction::Halt,
    ])
    .unwrap();

    // Encode with the shuffled table.
    let encoded = program.to_bytes_with_table(&table);
    // Canonical bytes should differ (seed is not identity).
    assert_ne!(encoded, program.to_bytes());
    // Decoding with the same table must recover the original program.
    let decoded = Program::from_bytes_with_table(&encoded, &table).unwrap();
    assert_eq!(decoded, program);

    // Trying to decode with the identity table must fail (unknown opcode).
    assert!(Program::from_bytes(&encoded).is_err()
        || Program::from_bytes(&encoded).unwrap() != program);
}

#[test]
fn shuffled_opcode_table_works_end_to_end() {
    let signing_certificate = b"debug-cert-for-opcode-test";
    let opcode_seed = [99_u8; 32];
    let table = OpcodeTable::from_seed(&opcode_seed);

    let identity = CodeIdentity::from_certificate(
        "com.example.securevm",
        signing_certificate,
        None,
    )
    .unwrap();

    let program = Program::new(vec![
        Instruction::PushI64(3),
        Instruction::PushI64(14),
        Instruction::Add,
        Instruction::Halt,
    ])
    .unwrap();

    // Encode firmware with the shuffled table and hash the ENCODED bytes.
    let encoded_firmware_bytes = program.to_bytes_with_table(&table);
    let firmware_hash = sha256(&encoded_firmware_bytes);

    let license = FirmwareLicense::new(
        "com.example.securevm",
        identity.signing_cert_sha256,
        InstallerPolicy::Any,
        firmware_hash,
        [55_u8; 32],
        [66_u8; 32],
        opcode_seed,
        0, // no expiry
        0, // firmware_flags: 0 = no debug
    );

    let signing_key = SigningKey::from_bytes(&[77_u8; 32]);
    let verifying_key = signing_key.verifying_key().to_bytes();

    let encrypted_license =
        encrypt_license_for_signing_certificate(&license, signing_certificate).unwrap();
    let encrypted_firmware =
        encrypt_firmware(&encoded_firmware_bytes, &license.firmware_key().unwrap()).unwrap();
    let codesign = sign_code_assets(
        &identity,
        &encrypted_license,
        &encrypted_firmware,
        |payload| Ok(signing_key.sign(payload).to_bytes()),
    )
    .unwrap();

    let mut vm = SecureVm::new();
    let code = vm.start_with_verified_assets(
        "com.example.securevm",
        None,
        signing_certificate,
        &encrypted_license,
        &encrypted_firmware,
        &codesign,
        &verifying_key,
    );

    assert_eq!(code, StartCode::Ok);
    assert_eq!(vm.run().unwrap().result, 17);
}

#[test]
fn rejects_patched_firmware_asset() {
    let signing_certificate = b"release-app-signing-certificate";
    let identity =
        CodeIdentity::from_certificate("com.example.securevm", signing_certificate, None).unwrap();
    let program = Program::new(vec![Instruction::PushI64(10), Instruction::Halt]).unwrap();
    let license = FirmwareLicense::new(
        "com.example.securevm",
        identity.signing_cert_sha256,
        InstallerPolicy::Any,
        sha256(&program.to_bytes()),
        [11_u8; 32],
        [21_u8; 32],
        [0_u8; 32], // identity opcode table
        0,          // no expiry
        0,          // firmware_flags: 0 = no debug
    );
    // Constant-byte keys are only acceptable in tests.
    let signing_key = SigningKey::from_bytes(&[5_u8; 32]);
    let verifying_key = signing_key.verifying_key().to_bytes();
    let encrypted_license =
        encrypt_license_for_signing_certificate(&license, signing_certificate).unwrap();
    let mut encrypted_firmware =
        encrypt_firmware(&program.to_bytes(), &license.firmware_key().unwrap()).unwrap();
    let codesign = sign_code_assets(
        &identity,
        &encrypted_license,
        &encrypted_firmware,
        |payload| Ok(signing_key.sign(payload).to_bytes()),
    )
    .unwrap();

    let last = encrypted_firmware.last_mut().unwrap();
    *last ^= 0x01;

    let mut vm = SecureVm::new();

    assert_eq!(
        vm.start_with_verified_assets(
            "com.example.securevm",
            None,
            signing_certificate,
            &encrypted_license,
            &encrypted_firmware,
            &codesign,
            &verifying_key,
        ),
        StartCode::IntegrityFailed
    );
}

#[test]
fn rejects_expired_license() {
    let signing_certificate = b"release-app-signing-certificate";
    let identity =
        CodeIdentity::from_certificate("com.example.securevm", signing_certificate, None).unwrap();
    let program = Program::new(vec![Instruction::PushI64(1), Instruction::Halt]).unwrap();

    // valid_until = 1 (1970-01-01T00:00:01Z) — always in the past.
    let license = FirmwareLicense::new(
        "com.example.securevm",
        identity.signing_cert_sha256,
        InstallerPolicy::Any,
        sha256(&program.to_bytes()),
        [33_u8; 32],
        [44_u8; 32],
        [0_u8; 32],
        1, // expired
        0, // firmware_flags: 0 = no debug
    );
    let signing_key = SigningKey::from_bytes(&[6_u8; 32]);
    let verifying_key = signing_key.verifying_key().to_bytes();
    let encrypted_license =
        encrypt_license_for_signing_certificate(&license, signing_certificate).unwrap();
    let encrypted_firmware =
        encrypt_firmware(&program.to_bytes(), &license.firmware_key().unwrap()).unwrap();
    let codesign = sign_code_assets(
        &identity,
        &encrypted_license,
        &encrypted_firmware,
        |payload| Ok(signing_key.sign(payload).to_bytes()),
    )
    .unwrap();

    let mut vm = SecureVm::new();
    assert_eq!(
        vm.start_with_verified_assets(
            "com.example.securevm",
            None,
            signing_certificate,
            &encrypted_license,
            &encrypted_firmware,
            &codesign,
            &verifying_key,
        ),
        StartCode::LicenseFailed
    );
}

#[test]
fn rejects_stack_overflow() {
    // MAX_STACK_DEPTH is 1 024; 1 025 pushes exceeds the limit.
    let mut instructions: Vec<Instruction> = (0..1025)
        .map(|_| Instruction::PushI64(0))
        .collect();
    instructions.push(Instruction::Halt);
    let program = Program::new(instructions).unwrap();

    let mut vm = SecureVm::new();
    vm.load_program(program).unwrap();
    vm.start().unwrap();

    assert!(matches!(vm.run(), Err(VmError::StackOverflow)));
}
