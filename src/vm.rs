//! Secure virtual machine — lifecycle, bytecode execution, and key management.
//!
//! [`SecureVm`] is the primary public type. It transitions between `Stopped`
//! and `Running` states via [`SecureVm::start_with_verified_assets`] and
//! [`SecureVm::stop`]. All cryptographic secrets are zeroed on `stop()` or
//! when the value is dropped.

use rand::RngCore;
use std::hint::black_box;
use zeroize::{Zeroize, Zeroizing};
use crate::memguard::LockedPage;

use crate::{
    check_so_integrity, is_debugger_attached,
    is_emulator, is_rooted, CodeIdentity, FirmwareBundle, Instruction, Program, Result,
    SecureStore, VmError,
};
use crate::firmware::{CustomerKeyInit, decrypt_program, encrypt_program};
use crate::wbc::WbcAes256Tables;

/// Number of general-purpose integer registers available to the VM.
///
/// 16 registers (indices 0–15) provide enough scratch space for typical
/// firmware computations without the complexity of a large register file.
/// All registers are initialised to zero on `new()` and reset to zero on
/// every `load_program()` call.
const REGISTER_COUNT: usize = 16;

/// Maximum number of bytecode instructions the VM will execute per `run()`.
///
/// This is a denial-of-service guard. Without a limit, a firmware bug (or
/// deliberately malicious bytecode) containing an infinite loop would hang the
/// calling thread permanently. 100 000 steps is generous for the intended
/// firmware use-cases and can be adjusted with `SecureVm::set_max_steps`.
const DEFAULT_MAX_STEPS: usize = 100_000;

/// How many instruction steps elapse between consecutive debugger checks
/// during execution.
///
/// The check at startup (`start_with_verified_assets`) catches debuggers that
/// are attached before the app runs. However, an attacker can attach a
/// debugger *after* startup to observe the firmware in action. Periodic checks
/// during the execution loop catch late-attached debuggers. Checking every
/// 10 000 steps is a balance: too frequent and it slows normal execution; too
/// rare and an attacker has a large window after attaching.
const DEBUGGER_CHECK_INTERVAL: usize = 10_000;

/// Maximum nesting depth for `Call` / `Ret` subroutine calls.
///
/// Each `Call` pushes a return address onto the call stack. At 256 frames deep
/// the VM aborts with `CallStackOverflow` rather than growing the call stack
/// unboundedly. This prevents stack-exhaustion attacks from recursive firmware.
const CALL_STACK_DEPTH_LIMIT: usize = 256;

/// Maximum number of values the evaluation stack may hold simultaneously.
///
/// Checked before every push inside `execute()`. Firmware that would exceed
/// this limit aborts with [`VmError::StackOverflow`] instead of growing the
/// heap unboundedly. 1 024 values × 8 bytes = 8 KiB — generous for the
/// intended use-cases and large enough for deeply nested loops with multiple
/// temporaries per frame.
const MAX_STACK_DEPTH: usize = 1_024;

/// Holds the customer-data key in one of three forms depending on hardware support.
///
/// On Android with the `jni` feature, `init` first attempts to place the key in
/// Android Keystore (StrongBox → TEE), so the key bytes never appear in
/// userspace. On non-Android targets, or when Keystore is unavailable, the key
/// is held in Rust heap memory XOR-masked with a session-ephemeral random mask.
#[derive(Debug)]
enum CustomerKeyStorage {
    /// Key lives inside Android Keystore (StrongBox or TEE). The `alias` is
    /// the only Rust-side artefact; the key bytes themselves never leave the
    /// secure element. Crypto is performed via JNI calls to `javax.crypto.Cipher`.
    #[cfg(all(target_os = "android", feature = "jni"))]
    HardwareBacked { alias: String },
    /// Customer-data key embedded into white-box AES-256 T-tables. No raw key
    /// bytes are present anywhere in this variant; an attacker who dumps the
    /// tables sees 256-entry lookup tables, not a 32-byte AES key.
    WhiteBox { tables: WbcAes256Tables },
    /// No key is available (VM is stopped or was never started with verified assets).
    None,
}

impl zeroize::Zeroize for CustomerKeyStorage {
    fn zeroize(&mut self) {
        match self {
            #[cfg(all(target_os = "android", feature = "jni"))]
            CustomerKeyStorage::HardwareBacked { alias } => alias.zeroize(),
            CustomerKeyStorage::WhiteBox { tables } => tables.zeroize(),
            CustomerKeyStorage::None => {}
        }
    }
}

/// The lifecycle state of the VM.
///
/// The VM starts `Stopped`. `start()` or `start_with_verified_assets()`
/// moves it to `Running`. `stop()` returns it to `Stopped`. Only a `Running`
/// VM can execute bytecode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VmState {
    /// The VM is idle. No program is being executed and no customer-data key
    /// is held in memory.
    Stopped,
    /// The VM has been started and is ready to execute bytecode via `run()`.
    Running,
}

/// The result of a successful `run()` call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RunReport {
    /// The value on top of the evaluation stack when `Halt` was reached, or
    /// 0 if the stack was empty. This is the firmware's "return value" — how
    /// to interpret it depends on the firmware's protocol with the app.
    pub result: i64,
    /// The number of instruction steps executed before halting. Useful for
    /// performance analysis and confirming that execution terminated before
    /// the step limit.
    pub steps: usize,
}

/// Numeric return codes from `start_with_verified_assets()`.
///
/// These map to integer constants in the Kotlin `SecureVm` companion object
/// so Android developers can switch on the return value. `#[repr(i32)]` ensures
/// the enum variants cast to the expected integer values across the JNI boundary.
/// `#[must_use]` warns at compile time if the return value is ignored.
#[repr(i32)]
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StartCode {
    /// All verification checks passed and the VM is now in the `Running` state
    /// with the program loaded and the customer-data key available.
    Ok = 0,

    /// A caller-supplied argument was missing, empty, or structurally invalid
    /// (e.g. the codesign public key was not 32 bytes, the signing certificate
    /// bytes were empty, or the VM was already running).
    InvalidInput = 1,

    /// The Ed25519 signature in `codesign.bin` did not verify, or one of the
    /// asset blobs had wrong magic bytes or an incorrect AES-GCM authentication
    /// tag. This indicates the assets were tampered with or the wrong public
    /// key was used.
    IntegrityFailed = 2,

    /// The license was structurally valid but did not match the runtime app
    /// identity (package name, signing certificate, or installer). The license
    /// was issued for a different app or distribution channel.
    LicenseFailed = 3,

    /// The firmware blob decrypted successfully but could not be parsed as
    /// valid VM bytecode. This suggests the firmware asset is corrupt or was
    /// built for a different VM version.
    FirmwareFailed = 4,

    /// A debugger, dynamic instrumentation framework, rooted environment, or
    /// emulator was detected. The VM refuses to start in an analysed or
    /// virtualised environment to protect firmware secrets.
    EnvironmentBlocked = 5,

    /// An unexpected error occurred that does not fit any of the above
    /// categories. Should not happen in practice; if it does, it is a bug.
    Unknown = 99,
}

/// The secure virtual machine that runs protected firmware.
///
/// `SecureVm` is the primary type in this crate. It owns:
///
/// - **`state`**: lifecycle (Stopped / Running).
/// - **`program_key`**: a session-ephemeral 256-bit AES key generated fresh on
///   `new()` and rotated on every `stop()`. The decrypted firmware is never
///   stored as a `Vec<Instruction>` between `run()` calls — it is kept as
///   AES-GCM ciphertext under this key and decrypted transiently during
///   `execute()`.
/// - **`encrypted_program`**: the firmware re-encrypted under `program_key`.
///   Between calls to `run()` only ciphertext exists in memory.
/// - **`stack`**: the evaluation stack. Cleared before every `run()`.
/// - **`registers`**: 16 scratch registers, zeroed on construction and after
///   `load_program()`.
/// - **`call_stack`**: return-address stack for `Call` / `Ret`.
/// - **`max_steps`**: execution step limit (default 100 000).
/// - **`store`**: the encrypted key-value store for persistent secrets.
/// - **`key_storage`**: holds the customer-data key in the most secure form
///   the device supports — `HardwareBacked` (Android Keystore: StrongBox or
///   TEE, key bytes never leave secure hardware) or `WhiteBox` (customer-data
///   key embedded in AES T-tables; no raw bytes stored). Set on a successful
///   `start_with_verified_assets()`, cleared on `stop()`.
#[derive(Debug)]
pub struct SecureVm {
    state: VmState,
    /// Session-ephemeral key used to re-encrypt the firmware at rest.
    /// `LockedPage` mlocks the page (prevents swap) and zeroes on drop,
    /// including on any error path that causes `SecureVm` to be dropped early.
    program_key: LockedPage<[u8; 32]>,
    /// Firmware stored as AES-GCM ciphertext between `run()` calls.
    encrypted_program: Option<Vec<u8>>,
    stack: Vec<i64>,
    /// Registers hold (raw_value ^ reg_mask[i]) — the plaintext computation
    /// value never appears in a memory dump. Derived from program_key each run.
    registers: [i64; REGISTER_COUNT],
    /// Per-register XOR mask. Zeroed between sessions; re-derived from
    /// program_key at the start of each execute() call.
    reg_mask: [i64; REGISTER_COUNT],
    /// Key for depth-variant stack slot encoding.
    /// Stack depth d stores (value ^ stack_key.rotate_right(d % 61 + 1)).
    /// Zeroed between sessions; derived from program_key ^ nonce_prefix.
    stack_key: i64,
    /// Per-run XOR applied to every instruction discriminant before dispatch.
    /// Derived from program_key ^ nonce_prefix; changes every session so the
    /// comparison values in the dispatch chain are never the same twice.
    dispatch_mask: u32,
    call_stack: Vec<usize>,
    max_steps: usize,
    store: SecureStore,
    /// Customer-data key storage. Starts as `None`; set on
    /// `start_with_verified_assets()`; cleared back to `None` on `stop()`.
    key_storage: CustomerKeyStorage,
    /// 8-byte random prefix prepended to every software-path AES-GCM nonce.
    /// Rotated on every `stop()` so nonces from different sessions never collide
    /// even when `nonce_counter` resets to zero. 8 random bytes raises the
    /// birthday bound for prefix collisions from 2^16 to 2^32 devices/sessions.
    nonce_prefix: [u8; 8],
    /// Monotonic counter for the software-path AES-GCM nonce (the remaining 4
    /// bytes after `nonce_prefix`). Provides deterministic uniqueness within a
    /// session. ~4 billion operations per session before exhaustion; well beyond
    /// any realistic workload. Overflows at `u32::MAX` → error.
    nonce_counter: u32,
    /// When `true`, `execute()` emits a per-instruction trace to stderr /
    /// logcat (prefix `[SVM-DEBUG]`). Controlled by bit 0 of `firmware_flags`
    /// in the decrypted license. Always `false` in `new()`; set by
    /// `start_with_verified_assets()` after the license is decrypted.
    ///
    /// Never set this in a production license — the trace output is visible to
    /// anyone who can read logcat on the device.
    debug_mode: bool,
}

impl Default for SecureVm {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for SecureVm {
    fn drop(&mut self) {
        // Ensure sensitive material is zeroed even if stop() was never called.
        self.key_storage.zeroize();
        self.program_key.zeroize();
        self.stack.zeroize();
        self.registers.zeroize();
        self.reg_mask.zeroize();
        self.stack_key.zeroize();
        self.dispatch_mask.zeroize();
        self.call_stack.zeroize();
        self.nonce_prefix.zeroize();
        self.nonce_counter.zeroize();
    }
}

impl SecureVm {
    /// Creates a new, stopped VM with no program loaded, all registers zeroed,
    /// an empty encrypted store, and freshly randomised session keys.
    pub fn new() -> Self {
        // SAFETY: [u8; 32] is valid when all bytes are zero.
        let mut program_key: LockedPage<[u8; 32]> = unsafe { LockedPage::new_zeroed() };
        let mut nonce_prefix = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut *program_key);
        rand::thread_rng().fill_bytes(&mut nonce_prefix);
        Self {
            state: VmState::Stopped,
            program_key,
            encrypted_program: None,
            stack: Vec::new(),
            registers: [0; REGISTER_COUNT],
            reg_mask: [0; REGISTER_COUNT],
            stack_key: 0,
            dispatch_mask: 0,
            call_stack: Vec::new(),
            max_steps: DEFAULT_MAX_STEPS,
            store: SecureStore::new(),
            key_storage: CustomerKeyStorage::None,
            nonce_prefix,
            nonce_counter: 0,
            debug_mode: false,
        }
    }

    /// Transitions the VM from `Stopped` to `Running` without any asset
    /// verification.
    ///
    /// Use this only when you are manually loading bytecode via
    /// `load_program_bytes()` — for example in tests or a development build
    /// where you control the firmware directly. In production, always use
    /// `start_with_verified_assets()` instead to ensure the firmware and
    /// license have been cryptographically verified.
    ///
    /// # Errors
    ///
    /// Returns `AlreadyRunning` if the VM is already in the `Running` state.
    pub fn start(&mut self) -> Result<()> {
        if self.state == VmState::Running {
            return Err(VmError::AlreadyRunning);
        }

        self.state = VmState::Running;
        Ok(())
    }

    /// The main secure startup path — verifies the firmware assets, loads the
    /// program, and derives the customer-data key.
    ///
    /// Call this method at app startup after reading the three asset files
    /// from the APK. The Kotlin `SecureVm.startFromAssets()` method calls this
    /// on your behalf after loading the assets from the `assets/` directory.
    ///
    /// **Verification pipeline** (see also `FirmwareBundle`):
    ///
    /// 1. **Environment check** (before any crypto): if a tracer, injection
    ///    framework, unlocked bootloader, Magisk overlay mount, or emulator is
    ///    detected, return `EnvironmentBlocked` immediately. This is the first
    ///    step because it is cheap (no KDF) and prevents the attacker from
    ///    setting breakpoints on KDF outputs.
    /// 2. Build `CodeIdentity` from the signing certificate bytes (hashes the
    ///    cert internally).
    /// 3. Verify the Ed25519 signature in `codesign` — confirms assets are
    ///    unmodified.
    /// 4. Decrypt and parse `encrypted_license` using the identity-derived key.
    /// 5. Validate the license identity fields against the runtime identity.
    /// 6. Decrypt `encrypted_firmware` using the firmware key from the license.
    /// 7. Verify the firmware hash.
    /// 8. Parse the decrypted bytes as VM bytecode.
    /// 9. Re-encrypt the firmware under a session-ephemeral key and store the
    ///    ciphertext. The decoded `Vec<Instruction>` is dropped; only ciphertext
    ///    lives between `run()` calls.
    /// 10. Store the customer-data key masked with a session-ephemeral XOR mask.
    ///     The unmasked key never persists in memory across method calls.
    /// 11. Transition the VM to `Running`.
    ///
    /// # Return value
    ///
    /// Returns a `StartCode` — never panics. The caller should check the code
    /// and handle each case appropriately (see `StartCode` variant docs).
    #[allow(clippy::too_many_arguments)]
    pub fn start_with_verified_assets(
        &mut self,
        package_id: &str,
        installer_package: Option<&str>,
        signing_certificate: &[u8],
        encrypted_license: &[u8],
        encrypted_firmware: &[u8],
        codesign: &[u8],
        codesign_public_key: &[u8; 32],
    ) -> StartCode {
        // Guard: reject the all-zeros Ed25519 key placeholder in production builds.
        // Prevents shipping before the vendor key has been replaced in keys.rs.
        #[cfg(all(feature = "enforce_codesign_key", not(test)))]
        if codesign_public_key == &[0u8; 32] {
            return StartCode::InvalidInput;
        }

        // Step 1: check environment before doing any crypto. Refuses to start
        // if a debugger/injector is attached, the device is rooted, the
        // process is running inside an emulator, or the .so has been patched.
        if is_debugger_attached() || is_rooted() || is_emulator() || !check_so_integrity() {
            return StartCode::EnvironmentBlocked;
        }

        let result = (|| {
            let identity = CodeIdentity::from_certificate(
                package_id,
                signing_certificate,
                installer_package.map(ToOwned::to_owned),
            )?;
            let bundle = FirmwareBundle::new(
                encrypted_license.to_vec(),
                encrypted_firmware.to_vec(),
                codesign.to_vec(),
            );
            let (program, key_init, firmware_flags) =
                bundle.decrypt_program_and_customer_key(&identity, codesign_public_key)?;
            self.load_program(program)?;

            // Bit 0 of firmware_flags enables the per-instruction debug trace.
            self.debug_mode = firmware_flags & 0x01 != 0;

            // Place the customer-data key into storage. The hardware Keystore
            // path (StrongBox → TEE) is tried first inside
            // `decrypt_program_and_customer_key`; if available it returns
            // `Hardware(alias)` and no key bytes appear here. Otherwise the
            // white-box AES-256 tables containing the embedded key are returned.
            self.key_storage = match key_init {
                #[cfg(all(target_os = "android", feature = "jni"))]
                CustomerKeyInit::Hardware(alias) => CustomerKeyStorage::HardwareBacked { alias },
                CustomerKeyInit::WhiteBox(tables) => CustomerKeyStorage::WhiteBox { tables },
            };

            self.start()
        })();

        // Map internal errors to the public StartCode enum. The mapping is
        // deliberately coarse: callers do not need (and should not see) the
        // internal error messages — they need enough information to decide
        // what to show the user.
        match result {
            Ok(()) => StartCode::Ok,
            Err(VmError::InvalidInput(_)) => StartCode::InvalidInput,
            Err(VmError::InvalidLicense(_)) => StartCode::LicenseFailed,
            Err(VmError::InvalidPackage(_)) | Err(VmError::Crypto) => StartCode::IntegrityFailed,
            Err(VmError::InvalidBytecode { .. }) => StartCode::FirmwareFailed,
            Err(VmError::AlreadyRunning) => StartCode::InvalidInput,
            Err(VmError::EnvironmentBlocked) => StartCode::EnvironmentBlocked,
            Err(_) => StartCode::Unknown,
        }
    }

    /// Stops the VM and clears sensitive state from memory.
    ///
    /// After `stop()`:
    /// - `state` is `Stopped`.
    /// - `encrypted_program` is cleared — the re-encrypted firmware is gone.
    /// - `stack` and `registers` are reset to zero.
    /// - `masked_customer_key` is zeroized and cleared.
    /// - `program_key` and `key_mask` are zeroized and re-randomised so that
    ///   any heap fragments from this session cannot be replayed in the next.
    ///
    /// Always call this (or `close()` in Kotlin) when the app moves to the
    /// background.
    pub fn stop(&mut self) -> Result<()> {
        self.state = VmState::Stopped;
        self.encrypted_program = None;
        self.stack.zeroize();
        self.registers.zeroize();
        self.call_stack.zeroize();
        // Clear key storage. For HardwareBacked, only the alias string in Rust
        // memory is zeroized; the hardware key persists in Keystore across
        // sessions so the same license can re-use it on next start().
        // For Software, both masked_key and mask bytes are zeroized.
        self.key_storage.zeroize();
        self.key_storage = CustomerKeyStorage::None;
        // Zeroize and rotate the program key so heap fragments from this
        // session cannot be used to recover material in the next session.
        self.program_key.zeroize();
        rand::thread_rng().fill_bytes(&mut *self.program_key);
        // Clear the obfuscation masks derived from program_key / nonce_prefix.
        // They will be re-derived from fresh material on the next run() call.
        self.reg_mask.zeroize();
        self.stack_key.zeroize();
        self.dispatch_mask.zeroize();
        // Reset the nonce counter and rotate the nonce prefix so that the next
        // session starts at counter 0 with a fresh prefix — preventing nonce
        // reuse across sessions even when the same customer key is reloaded.
        self.nonce_counter.zeroize();
        self.nonce_prefix.zeroize();
        rand::thread_rng().fill_bytes(&mut self.nonce_prefix);
        self.debug_mode = false;
        Ok(())
    }

    /// Returns the current lifecycle state of the VM.
    pub fn state(&self) -> VmState {
        self.state
    }

    /// Overrides the maximum instruction step count for this VM instance.
    ///
    /// Useful for firmware that legitimately requires more than 100 000 steps,
    /// or for tests that want to confirm the limit is enforced at a specific
    /// threshold.
    ///
    /// # Errors
    ///
    /// Returns `InvalidInput` if `max_steps` is zero (a zero limit would
    /// abort execution before the first instruction).
    pub fn set_max_steps(&mut self, max_steps: usize) -> Result<()> {
        if max_steps == 0 {
            return Err(VmError::InvalidInput(
                "max_steps must be greater than zero".to_string(),
            ));
        }

        self.max_steps = max_steps;
        Ok(())
    }

    /// Serialises `program` to bytes, re-encrypts the bytes under the
    /// session-ephemeral `program_key`, and stores only the ciphertext.
    ///
    /// The decoded `Vec<Instruction>` is never stored persistently. Between
    /// `run()` calls the firmware exists only as AES-GCM ciphertext; it is
    /// decrypted transiently at the start of each `run()` call and the
    /// plaintext bytes are wrapped in `Zeroizing` so they are zeroed when
    /// the local binding is dropped.
    pub fn load_program(&mut self, program: Program) -> Result<()> {
        let plaintext = Zeroizing::new(program.to_bytes());
        self.encrypted_program = Some(encrypt_program(&plaintext, &self.program_key)?);
        self.stack.zeroize();
        // Zeroize encoded registers then clear the mask so reg_read() returns 0
        // until derive_run_masks() re-derives the mask at the next run() call.
        self.registers.zeroize();
        self.reg_mask.zeroize();
        self.stack_key.zeroize();
        self.call_stack.zeroize();
        Ok(())
    }

    /// Parses raw bytecode bytes into a `Program` and loads it.
    ///
    /// Convenience wrapper around `Program::from_bytes` + `load_program`.
    /// Useful for manual / test scenarios where you have raw bytecode rather
    /// than a `Program` object.
    ///
    /// # Errors
    ///
    /// Returns `InvalidBytecode` if the bytes cannot be parsed.
    pub fn load_program_bytes(&mut self, bytecode: &[u8]) -> Result<()> {
        self.load_program(Program::from_bytes(bytecode)?)
    }

    /// Executes the loaded program and returns the result.
    ///
    /// Pre-conditions:
    /// - The VM must be in the `Running` state.
    /// - A program must be loaded.
    ///
    /// The stack, registers, and call-stack are all cleared before execution
    /// so every `run()` call starts fresh. The firmware is decrypted from
    /// `encrypted_program` into a
    /// `Zeroizing<Vec<u8>>` buffer, parsed into a `Program`, and executed.
    /// The plaintext bytes are zeroed as soon as parsing completes — they do
    /// not outlive the local binding.
    ///
    /// # Errors
    ///
    /// Returns `Stopped` if the VM is not running.
    /// Returns `ProgramNotLoaded` if no program is loaded.
    /// Returns errors from `execute()` (stack underflow, division by zero,
    /// execution limit exceeded, environment blocked, etc.).
    pub fn run(&mut self) -> Result<RunReport> {
        if self.state != VmState::Running {
            return Err(VmError::Stopped);
        }

        let encrypted = self
            .encrypted_program
            .as_ref()
            .ok_or(VmError::ProgramNotLoaded)?
            .clone();

        // Decrypt into a Zeroizing buffer, parse, then let the buffer drop
        // (and be zeroed) before execution begins.
        let program = {
            let plaintext = Zeroizing::new(decrypt_program(&encrypted, &self.program_key)?);
            Program::from_bytes(&plaintext)?
        };

        self.stack.zeroize();
        self.registers.zeroize();
        self.call_stack.zeroize();

        let result = self.execute(program.instructions());
        if result.is_err() {
            self.stack.zeroize();
        }
        result
    }

    /// The inner execution loop — dispatches instructions one at a time.
    ///
    /// **Step counter** (`steps`): incremented for every instruction. When it
    /// reaches `max_steps`, execution aborts with `ExecutionLimitExceeded`.
    /// This is a denial-of-service guard against firmware with infinite loops.
    ///
    /// **Debugger check interval**: every `DEBUGGER_CHECK_INTERVAL` steps the
    /// VM calls `is_debugger_attached()`. This catches debuggers that were
    /// attached *after* the startup check. If a debugger is detected during
    /// execution, `stop()` is called immediately (to clear the customer-data
    /// key and program from memory) and `EnvironmentBlocked` is returned.
    ///
    /// **Program counter** (`pc`): an index into the `instructions` slice.
    /// Non-jump instructions advance `pc` by 1 each step. Jump and call
    /// instructions set `pc` to an absolute instruction index; `Halt` and
    /// falling off the end of the program both terminate execution cleanly.
    ///
    /// **Arithmetic**: checked arithmetic is used for `Add`, `Sub`, `Mul`,
    /// `Div`, and `Mod` so integer overflow and division-by-zero return errors
    /// rather than silently wrapping or panicking.
    ///
    /// **Stack depth**: every push is routed through `stack_push()`, which
    /// aborts with `StackOverflow` when the stack would exceed `MAX_STACK_DEPTH`
    /// (1 024 values). This prevents malicious firmware from exhausting heap
    /// memory by pushing without popping.
    fn execute(&mut self, instructions: &[Instruction]) -> Result<RunReport> {
        // Derive per-run encoding masks from the session key material.
        self.derive_run_masks();

        // Pre-compute masked dispatch discriminants. obfbytes! emits a
        // different XOR-encrypted constant per build; XOR-ing with
        // dispatch_mask makes the comparison values session-unique.
        // Computed once here, reused on every instruction step.
        let mask = self.dispatch_mask;
        let arm_push  = u32::from_le_bytes(*obfstr::obfbytes!(b"P64\x00")) ^ mask;
        let arm_add   = u32::from_le_bytes(*obfstr::obfbytes!(b"AD00"))    ^ mask;
        let arm_sub   = u32::from_le_bytes(*obfstr::obfbytes!(b"SB00"))    ^ mask;
        let arm_mul   = u32::from_le_bytes(*obfstr::obfbytes!(b"ML00"))    ^ mask;
        let arm_div   = u32::from_le_bytes(*obfstr::obfbytes!(b"DV00"))    ^ mask;
        let arm_mod_  = u32::from_le_bytes(*obfstr::obfbytes!(b"MD00"))    ^ mask;
        let arm_store = u32::from_le_bytes(*obfstr::obfbytes!(b"ST00"))    ^ mask;
        let arm_load  = u32::from_le_bytes(*obfstr::obfbytes!(b"LD00"))    ^ mask;
        let arm_eq    = u32::from_le_bytes(*obfstr::obfbytes!(b"EQ00"))    ^ mask;
        let arm_lt    = u32::from_le_bytes(*obfstr::obfbytes!(b"LT00"))    ^ mask;
        let arm_gt    = u32::from_le_bytes(*obfstr::obfbytes!(b"GT00"))    ^ mask;
        let arm_and   = u32::from_le_bytes(*obfstr::obfbytes!(b"AN00"))    ^ mask;
        let arm_or    = u32::from_le_bytes(*obfstr::obfbytes!(b"OR00"))    ^ mask;
        let arm_xor   = u32::from_le_bytes(*obfstr::obfbytes!(b"XR00"))    ^ mask;
        let arm_shl   = u32::from_le_bytes(*obfstr::obfbytes!(b"SL00"))    ^ mask;
        let arm_shr   = u32::from_le_bytes(*obfstr::obfbytes!(b"SR00"))    ^ mask;
        let arm_not   = u32::from_le_bytes(*obfstr::obfbytes!(b"NT00"))    ^ mask;
        let arm_dup   = u32::from_le_bytes(*obfstr::obfbytes!(b"DU00"))    ^ mask;
        let arm_pop_  = u32::from_le_bytes(*obfstr::obfbytes!(b"PP00"))    ^ mask;
        let arm_jmp   = u32::from_le_bytes(*obfstr::obfbytes!(b"JM00"))    ^ mask;
        let arm_jmpif = u32::from_le_bytes(*obfstr::obfbytes!(b"JI00"))    ^ mask;
        let arm_jifn  = u32::from_le_bytes(*obfstr::obfbytes!(b"JN00"))    ^ mask;
        let arm_call  = u32::from_le_bytes(*obfstr::obfbytes!(b"CL00"))    ^ mask;
        let arm_ret   = u32::from_le_bytes(*obfstr::obfbytes!(b"RT00"))    ^ mask;
        let arm_halt  = u32::from_le_bytes(*obfstr::obfbytes!(b"HT00"))    ^ mask;

        let mut steps = 0;
        let mut pc = 0;
        let len = instructions.len();

        while pc < len {
            if steps >= self.max_steps {
                return Err(VmError::ExecutionLimitExceeded);
            }

            // Periodic debugger check to catch late-attached tracers.
            if steps % DEBUGGER_CHECK_INTERVAL == 0 && is_debugger_attached() {
                let _ = self.stop();
                return Err(VmError::EnvironmentBlocked);
            }

            steps += 1;
            let mut next_pc = pc + 1;

            if self.debug_mode {
                eprintln!(
                    "[SVM-DEBUG] step={steps:>6} pc={pc:>5} instr={:?}  stack_depth={}",
                    instructions[pc],
                    self.stack.len()
                );
            }

            // Compute the session-masked discriminant for this instruction.
            // black_box prevents LLVM from seeing through the XOR and
            // rebuilding a static jump table from the branch targets.
            let disc = black_box(Self::instr_disc(&instructions[pc]) ^ mask);

            // ── Dispatch (if/else chain — no static jump table) ──────────────
            //
            // Each arm compares `disc` against a session-unique runtime value
            // (arm_xxx = obfbytes_const ^ dispatch_mask). Static disassemblers
            // see non-trivial computed comparisons, not an indexed branch table.

            if disc == arm_push {
                let Instruction::PushI64(value) = instructions[pc] else { unreachable!() };
                self.stack_push(value)?;

            } else if disc == arm_add {
                self.binary_op(i64::checked_add)?;
            } else if disc == arm_sub {
                self.binary_op(i64::checked_sub)?;
            } else if disc == arm_mul {
                self.binary_op(i64::checked_mul)?;

            } else if disc == arm_div {
                let rhs = self.pop()?;
                if rhs == 0 { return Err(VmError::DivisionByZero); }
                let lhs = self.pop()?;
                self.stack_push(lhs.checked_div(rhs).ok_or(VmError::DivisionByZero)?)?;

            } else if disc == arm_mod_ {
                let rhs = self.pop()?;
                if rhs == 0 { return Err(VmError::DivisionByZero); }
                let lhs = self.pop()?;
                self.stack_push(lhs.checked_rem(rhs).ok_or(VmError::DivisionByZero)?)?;

            } else if disc == arm_store {
                let Instruction::Store(register) = instructions[pc] else { unreachable!() };
                let index = self.register_index(register)?;
                let val = self.pop()?;
                self.reg_write(index, val);

            } else if disc == arm_load {
                let Instruction::Load(register) = instructions[pc] else { unreachable!() };
                let index = self.register_index(register)?;
                self.stack_push(self.reg_read(index))?;

            } else if disc == arm_eq {
                let rhs = self.pop()?;
                let lhs = self.pop()?;
                self.stack_push(if lhs == rhs { 1 } else { 0 })?;
            } else if disc == arm_lt {
                let rhs = self.pop()?;
                let lhs = self.pop()?;
                self.stack_push(if lhs < rhs { 1 } else { 0 })?;
            } else if disc == arm_gt {
                let rhs = self.pop()?;
                let lhs = self.pop()?;
                self.stack_push(if lhs > rhs { 1 } else { 0 })?;

            } else if disc == arm_and {
                self.binary_op(|a, b| Some(a & b))?;
            } else if disc == arm_or {
                self.binary_op(|a, b| Some(a | b))?;
            } else if disc == arm_xor {
                self.binary_op(|a, b| Some(a ^ b))?;

            } else if disc == arm_shl {
                let shift = self.pop()?;
                let value = self.pop()?;
                if !(0..64).contains(&shift) {
                    return Err(VmError::InvalidInput("shift amount must be 0–63".to_string()));
                }
                self.stack_push(value << shift)?;
            } else if disc == arm_shr {
                let shift = self.pop()?;
                let value = self.pop()?;
                if !(0..64).contains(&shift) {
                    return Err(VmError::InvalidInput("shift amount must be 0–63".to_string()));
                }
                self.stack_push(value >> shift)?;
            } else if disc == arm_not {
                let value = self.pop()?;
                self.stack_push(!value)?;

            } else if disc == arm_dup {
                // peek() decodes TOS; stack_push() re-encodes at new depth.
                let value = self.peek()?;
                self.stack_push(value)?;
            } else if disc == arm_pop_ {
                self.pop()?;

            } else if disc == arm_jmp {
                let Instruction::Jmp(target) = instructions[pc] else { unreachable!() };
                next_pc = target as usize;
            } else if disc == arm_jmpif {
                let Instruction::JmpIf(target) = instructions[pc] else { unreachable!() };
                if self.pop()? != 0 { next_pc = target as usize; }
            } else if disc == arm_jifn {
                let Instruction::JmpIfNot(target) = instructions[pc] else { unreachable!() };
                if self.pop()? == 0 { next_pc = target as usize; }

            } else if disc == arm_call {
                let Instruction::Call(target) = instructions[pc] else { unreachable!() };
                if self.call_stack.len() >= CALL_STACK_DEPTH_LIMIT {
                    return Err(VmError::CallStackOverflow);
                }
                self.call_stack.push(pc + 1);
                next_pc = target as usize;
            } else if disc == arm_ret {
                next_pc = self.call_stack.pop().ok_or(VmError::StackUnderflow)?;

            } else if disc == arm_halt {
                if self.debug_mode {
                    eprintln!(
                        "[SVM-DEBUG] HALT  result={} steps={steps}",
                        self.peek().unwrap_or(0)
                    );
                }
                break;
            } else {
                return Err(VmError::InvalidBytecode {
                    offset: pc,
                    reason: "unknown instruction discriminant".to_string(),
                });
            }

            if self.debug_mode {
                match self.stack.last() {
                    Some(_) => eprintln!("[SVM-DEBUG]        => TOS={}", self.peek().unwrap_or(0)),
                    None    => eprintln!("[SVM-DEBUG]        => (stack empty)"),
                }
            }

            if next_pc > len {
                return Err(VmError::InvalidBytecode {
                    offset: pc,
                    reason: "jump target out of bounds".to_string(),
                });
            }

            pc = next_pc;
        }

        Ok(RunReport {
            result: if self.stack.is_empty() { 0 } else { self.peek().unwrap_or(0) },
            steps,
        })
    }

    /// Encrypts `value` with a passphrase-derived key and stores it under `key`
    /// in the encrypted key-value store.
    ///
    /// # Security
    ///
    /// The derived AES key is zeroized inside `SecureStore::put` before this
    /// call returns. However, the `passphrase` buffer is owned by the caller
    /// and is **not** zeroized internally. The caller is responsible for zeroing
    /// the passphrase slice after the call (e.g. with `zeroize::Zeroize::zeroize`).
    pub fn store_secret(
        &mut self,
        key: impl Into<String>,
        value: &[u8],
        passphrase: &[u8],
    ) -> Result<()> {
        self.store.put(key, value, passphrase)
    }

    /// Decrypts and returns the secret stored under `key`.
    ///
    /// # Security
    ///
    /// The derived AES key is zeroized inside `SecureStore::get` before this
    /// call returns. The `passphrase` buffer is **not** zeroized internally;
    /// the caller is responsible for zeroing it after the call.
    pub fn load_secret(&self, key: &str, passphrase: &[u8]) -> Result<Vec<u8>> {
        self.store.get(key, passphrase)
    }

    /// Removes the secret stored under `key` and returns whether it existed.
    pub fn delete_secret(&mut self, key: &str) -> bool {
        self.store.delete(key)
    }

    /// Returns a reference to the underlying `SecureStore`.
    pub fn secure_store(&self) -> &SecureStore {
        &self.store
    }

    /// Serializes all encrypted store records to a portable byte blob.
    pub fn export_store(&self) -> Result<Vec<u8>> {
        self.store.to_bytes()
    }

    /// Replaces the current store with records deserialized from a blob
    /// produced by a previous `export_store` call.
    pub fn import_store(&mut self, bytes: &[u8]) -> Result<()> {
        self.store = SecureStore::from_bytes(bytes)?;
        Ok(())
    }

    /// Encrypts `plaintext` with the customer-data key.
    ///
    /// On hardware-backed storage the AES-GCM operation runs inside the secure
    /// element (StrongBox or TEE) via JNI; the key bytes never appear in
    /// userspace. On the software path the key is unmasked transiently in a
    /// `Zeroizing<[u8; 32]>` binding and zeroed before this call returns.
    ///
    /// The nonce for the software path is `[nonce_prefix (8 bytes)][counter_be
    /// (4 bytes)]`. `nonce_prefix` is a random session salt (rotated on every
    /// `stop()`); the counter increments with each call. This eliminates the
    /// birthday-bound collision risk of purely random nonces under high-frequency
    /// encryption while preventing cross-session nonce reuse.
    ///
    /// Returns `[SVMWBC02 magic (8)][nonce (12)][ciphertext][HMAC-SHA256 (32)]`
    /// on the white-box path, or `[SVMDAT01 magic (8)][iv (12)][ciphertext + GCM tag
    /// (16)]` on the hardware-backed path.
    ///
    /// # Errors
    ///
    /// Returns `ProgramNotLoaded` if no customer-data key is available.
    /// Returns `Crypto` if encryption fails.
    /// Returns `InvalidInput` if the session nonce counter has wrapped at `u32::MAX`
    /// (~4 billion operations per session).
    pub fn encrypt_customer_data(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        // Hardware path: delegate to Android Keystore (nonce generated inside
        // the secure element). Prepend SVMDAT01 magic for format parity.
        #[cfg(all(target_os = "android", feature = "jni"))]
        if let CustomerKeyStorage::HardwareBacked { alias } = &self.key_storage {
            let alias = alias.clone();
            let raw = crate::keystore::ks_encrypt(&alias, plaintext)
                .ok_or_else(|| VmError::InvalidInput("Keystore encryption failed".into()))?;
            let mut blob = Vec::with_capacity(8 + raw.len());
            blob.extend_from_slice(b"SVMDAT01");
            blob.extend_from_slice(&raw);
            return Ok(blob);
        }

        // White-box path: nonce from the monotonic session counter.
        let nonce = match &self.key_storage {
            CustomerKeyStorage::WhiteBox { .. } => self.next_nonce()?,
            CustomerKeyStorage::None => return Err(VmError::ProgramNotLoaded),
            #[cfg(all(target_os = "android", feature = "jni"))]
            CustomerKeyStorage::HardwareBacked { .. } => unreachable!(),
        };
        match &self.key_storage {
            CustomerKeyStorage::WhiteBox { tables } => tables.encrypt_with_nonce(plaintext, &nonce),
            _ => unreachable!(),
        }
    }

    /// Decrypts `ciphertext` with the customer-data key.
    ///
    /// On hardware-backed storage decryption runs inside the secure element via
    /// JNI. On the software path the key is unmasked transiently inside a
    /// `Zeroizing<[u8; 32]>` binding and zeroed before the call returns.
    ///
    /// Accepts blobs from both the hardware path (`[SVMDAT01][iv][ct+tag]`) and
    /// any earlier software-path blobs with the same format.
    ///
    /// # Errors
    ///
    /// Returns `ProgramNotLoaded` if no customer-data key is available.
    /// Returns `Crypto` if decryption fails (wrong key, tampered ciphertext, …).
    pub fn decrypt_customer_data(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        match &self.key_storage {
            #[cfg(all(target_os = "android", feature = "jni"))]
            CustomerKeyStorage::HardwareBacked { alias } => {
                let blob = if ciphertext.starts_with(b"SVMDAT01") {
                    &ciphertext[8..]
                } else {
                    ciphertext
                };
                crate::keystore::ks_decrypt(alias, blob).ok_or(VmError::Crypto)
            }
            CustomerKeyStorage::WhiteBox { tables } => tables.decrypt(ciphertext),
            CustomerKeyStorage::None => Err(VmError::ProgramNotLoaded),
        }
    }

    /// Builds the 12-byte nonce for the next software-path AES-GCM encryption.
    ///
    /// Format: `[nonce_prefix (8 bytes)][nonce_counter as big-endian u32 (4 bytes)]`.
    /// Increments `nonce_counter` after success; errors when the counter reaches
    /// `u32::MAX` (~4 billion operations — far beyond any realistic session budget).
    ///
    /// The prefix is fixed for the lifetime of a session (rotated on `stop()`)
    /// and the counter advances monotonically. Using a 32-bit counter caps each
    /// session to ~4 billion encrypt/decrypt operations — well beyond realistic
    /// firmware workloads. When the counter would overflow `u32::MAX` the call
    /// returns an error rather than silently wrapping and reusing a nonce.
    fn next_nonce(&mut self) -> Result<[u8; 12]> {
        let count = self.nonce_counter;
        if count == u32::MAX {
            return Err(VmError::InvalidInput("nonce counter exhausted".into()));
        }
        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(&self.nonce_prefix);
        nonce[8..].copy_from_slice(&count.to_be_bytes());
        self.nonce_counter = count + 1;
        Ok(nonce)
    }

    // ── Obfuscation helpers ───────────────────────────────────────────────────

    /// Derives the three session-scoped encoding masks from the current
    /// `program_key` and `nonce_prefix`. Must be called at the start of every
    /// `execute()` invocation before any register or stack operation.
    ///
    /// Also re-encodes any existing register values from the OLD mask to the
    /// NEW mask (so a mid-session mask rotation would be safe, though we only
    /// call this once per `run()`).
    fn derive_run_masks(&mut self) {
        // reg_mask — walk through program_key with stride 7 (coprime to 32)
        // so consecutive registers draw maximally different key bytes.
        let old_mask = self.reg_mask;
        for (i, old) in old_mask.iter().enumerate() {
            let o = i.wrapping_mul(7) & 0x1f;
            self.reg_mask[i] = i64::from_le_bytes([
                self.program_key[o],
                self.program_key[(o + 1) & 0x1f],
                self.program_key[(o + 2) & 0x1f],
                self.program_key[(o + 3) & 0x1f],
                self.program_key[(o + 4) & 0x1f],
                self.program_key[(o + 5) & 0x1f],
                self.program_key[(o + 6) & 0x1f],
                self.program_key[(o + 7) & 0x1f],
            ]);
            // Decode with old mask, re-encode with new mask.
            // On first call (old_mask = 0, registers = 0) this is a no-op,
            // leaving registers[i] = 0 ^ new_mask[i] = new_mask[i] (encoded 0).
            let raw = self.registers[i] ^ old;
            self.registers[i] = raw ^ self.reg_mask[i];
        }

        // stack_key — XOR of program_key upper half with nonce_prefix.
        // Changes every session because nonce_prefix rotates on stop().
        let sk: [u8; 8] = std::array::from_fn(|j| self.program_key[16 + j] ^ self.nonce_prefix[j]);
        self.stack_key = i64::from_le_bytes(sk);
        if self.stack_key == 0 {
            // Degenerate case (astronomically rare with random keys); use
            // program_key bytes directly rather than an all-zero mask.
            self.stack_key = i64::from_le_bytes(self.program_key[0..8].try_into().unwrap());
        }

        // dispatch_mask — 4 bytes from both sources, used to XOR every
        // instruction discriminant before comparison in the dispatch chain.
        self.dispatch_mask = u32::from_le_bytes([
            self.program_key[0] ^ self.nonce_prefix[0],
            self.program_key[1] ^ self.nonce_prefix[1],
            self.program_key[2] ^ self.nonce_prefix[2],
            self.program_key[3] ^ self.nonce_prefix[3],
        ]);
    }

    /// Returns the decoded value of register `idx`.
    ///
    /// Registers store `raw_value ^ reg_mask[idx]`; a memory dump of the
    /// process shows the encoded bytes, not the computation values.
    #[inline(always)]
    fn reg_read(&self, idx: usize) -> i64 {
        self.registers[idx] ^ self.reg_mask[idx]
    }

    /// Encodes `val` and stores it in register `idx`.
    #[inline(always)]
    fn reg_write(&mut self, idx: usize, val: i64) {
        self.registers[idx] = val ^ self.reg_mask[idx];
    }

    /// Decodes the top-of-stack value without popping it.
    #[inline(always)]
    fn peek(&self) -> Result<i64> {
        let enc = *self.stack.last().ok_or(VmError::StackUnderflow)?;
        let d = (self.stack.len() - 1) as u32;
        Ok(enc ^ self.stack_key.rotate_right(d % 61 + 1))
    }

    /// Maps each `Instruction` variant to a compile-time obfstr-encrypted u32.
    ///
    /// `obfbytes!` stores an XOR-encrypted copy in the binary; the tag values
    /// differ in every build. A reverse engineer comparing two `.so` builds
    /// cannot map discriminant values to opcodes by pattern-matching constants.
    #[inline(always)]
    fn instr_disc(instr: &Instruction) -> u32 {
        match instr {
            Instruction::PushI64(_)  => u32::from_le_bytes(*obfstr::obfbytes!(b"P64\x00")),
            Instruction::Add         => u32::from_le_bytes(*obfstr::obfbytes!(b"AD00")),
            Instruction::Sub         => u32::from_le_bytes(*obfstr::obfbytes!(b"SB00")),
            Instruction::Mul         => u32::from_le_bytes(*obfstr::obfbytes!(b"ML00")),
            Instruction::Div         => u32::from_le_bytes(*obfstr::obfbytes!(b"DV00")),
            Instruction::Mod         => u32::from_le_bytes(*obfstr::obfbytes!(b"MD00")),
            Instruction::Store(_)    => u32::from_le_bytes(*obfstr::obfbytes!(b"ST00")),
            Instruction::Load(_)     => u32::from_le_bytes(*obfstr::obfbytes!(b"LD00")),
            Instruction::Eq          => u32::from_le_bytes(*obfstr::obfbytes!(b"EQ00")),
            Instruction::Lt          => u32::from_le_bytes(*obfstr::obfbytes!(b"LT00")),
            Instruction::Gt          => u32::from_le_bytes(*obfstr::obfbytes!(b"GT00")),
            Instruction::And         => u32::from_le_bytes(*obfstr::obfbytes!(b"AN00")),
            Instruction::Or          => u32::from_le_bytes(*obfstr::obfbytes!(b"OR00")),
            Instruction::Xor         => u32::from_le_bytes(*obfstr::obfbytes!(b"XR00")),
            Instruction::Shl         => u32::from_le_bytes(*obfstr::obfbytes!(b"SL00")),
            Instruction::Shr         => u32::from_le_bytes(*obfstr::obfbytes!(b"SR00")),
            Instruction::Not         => u32::from_le_bytes(*obfstr::obfbytes!(b"NT00")),
            Instruction::Dup         => u32::from_le_bytes(*obfstr::obfbytes!(b"DU00")),
            Instruction::Pop         => u32::from_le_bytes(*obfstr::obfbytes!(b"PP00")),
            Instruction::Jmp(_)      => u32::from_le_bytes(*obfstr::obfbytes!(b"JM00")),
            Instruction::JmpIf(_)    => u32::from_le_bytes(*obfstr::obfbytes!(b"JI00")),
            Instruction::JmpIfNot(_) => u32::from_le_bytes(*obfstr::obfbytes!(b"JN00")),
            Instruction::Call(_)     => u32::from_le_bytes(*obfstr::obfbytes!(b"CL00")),
            Instruction::Ret         => u32::from_le_bytes(*obfstr::obfbytes!(b"RT00")),
            Instruction::Halt        => u32::from_le_bytes(*obfstr::obfbytes!(b"HT00")),
        }
    }

    // ── Stack helpers ─────────────────────────────────────────────────────────

    /// Encodes `v` and pushes it onto the evaluation stack.
    ///
    /// Slot at depth `d` stores `v ^ stack_key.rotate_right(d % 61 + 1)` so
    /// the plaintext computation value is never visible in a memory dump.
    fn stack_push(&mut self, v: i64) -> Result<()> {
        if self.stack.len() >= MAX_STACK_DEPTH {
            return Err(VmError::StackOverflow);
        }
        let d = self.stack.len() as u32;
        self.stack.push(v ^ self.stack_key.rotate_right(d % 61 + 1));
        Ok(())
    }

    /// Pops two values from the stack, applies `op(lhs, rhs)`, and pushes the result.
    ///
    /// The operand pushed first is the left-hand side; the operand pushed second
    /// (closer to the top) is the right-hand side — consistent with the stack
    /// ordering described in the [`Instruction`] documentation.
    fn binary_op(&mut self, op: fn(i64, i64) -> Option<i64>) -> Result<()> {
        let rhs = self.pop()?;
        let lhs = self.pop()?;
        self.stack_push(op(lhs, rhs).ok_or(VmError::InvalidInput("integer overflow".to_string()))?)?;
        Ok(())
    }

    /// Decodes and pops the top of the evaluation stack, or errors on underflow.
    fn pop(&mut self) -> Result<i64> {
        let enc = self.stack.pop().ok_or(VmError::StackUnderflow)?;
        let d = self.stack.len() as u32; // depth of the slot that was just popped
        Ok(enc ^ self.stack_key.rotate_right(d % 61 + 1))
    }

    /// Converts a `u8` register operand to a `usize` index, checking the range.
    fn register_index(&self, register: u8) -> Result<usize> {
        let index = usize::from(register);
        if index >= REGISTER_COUNT {
            return Err(VmError::RegisterOutOfRange(index));
        }
        Ok(index)
    }
}

