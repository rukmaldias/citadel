use thiserror::Error;

/// Result alias used throughout the crate.
///
/// Most functions in this crate return either the requested value or a
/// `VmError` that explains why the operation failed.
pub type Result<T> = std::result::Result<T, VmError>;

/// All errors that can be returned by the VM, storage, or asset-loading code.
///
/// Each variant maps to a specific failure case such as bad bytecode,
/// decryption problems, or an invalid runtime state. The variants are grouped
/// loosely by the layer that produces them:
///
/// - **VM execution layer**: `AlreadyRunning`, `Stopped`, `ProgramNotLoaded`,
///   `InvalidBytecode`, `StackUnderflow`, `StackOverflow`, `DivisionByZero`,
///   `RegisterOutOfRange`, `ExecutionLimitExceeded`, `CallStackOverflow`
/// - **Crypto / asset layer**: `Crypto`, `InvalidPackage`, `InvalidLicense`
/// - **Storage layer**: `KeyNotFound`, `InvalidInput`
/// - **Environment / anti-debug layer**: `EnvironmentBlocked`
#[derive(Debug, Error)]
pub enum VmError {
    /// The VM is already in the `Running` state.
    ///
    /// Produced by the VM execution layer when `start()` or
    /// `start_with_verified_assets()` is called while the VM is already
    /// running. Call `stop()` first.
    #[error("VM is already running")]
    AlreadyRunning,

    /// The VM is in the `Stopped` state and cannot run.
    ///
    /// Produced by the VM execution layer when `run()` is called before
    /// `start()`. Make sure the VM has been started and a program has been
    /// loaded before calling `run()`.
    #[error("VM is stopped")]
    Stopped,

    /// No program has been loaded into the VM.
    ///
    /// Produced by the VM execution layer when `run()` is called without a
    /// prior `load_program()` call, or when `encrypt_customer_data()` /
    /// `decrypt_customer_data()` is called before a verified startup (because
    /// the customer-data key only exists after `start_with_verified_assets()`
    /// succeeds).
    #[error("VM is not loaded with a program")]
    ProgramNotLoaded,

    /// The bytecode stream contains an unrecognised or malformed instruction.
    ///
    /// Produced by the bytecode parsing layer (`Program::from_bytes`). The
    /// `offset` field points to the byte in the input where the error was
    /// detected, and `reason` describes what was wrong (e.g., unknown opcode,
    /// missing payload bytes, jump target out of bounds).
    #[error("invalid bytecode at offset {offset}: {reason}")]
    InvalidBytecode { offset: usize, reason: String },

    /// A pop was attempted on an empty evaluation stack.
    ///
    /// Produced by the VM execution layer when an arithmetic, store, or branch
    /// instruction finds the stack empty, or when `Ret` is executed without a
    /// matching `Call`. This indicates either a firmware bug or tampered
    /// bytecode.
    #[error("stack underflow")]
    StackUnderflow,

    /// A division by zero was attempted during VM execution.
    ///
    /// Produced by the `Div` and `Mod` instructions when the divisor on the
    /// stack is zero.
    #[error("division by zero")]
    DivisionByZero,

    /// A register index in the bytecode is out of the valid range (0–15).
    ///
    /// Produced by the VM execution layer when a `Store` or `Load` instruction
    /// references a register number that is greater than or equal to
    /// `REGISTER_COUNT`. The invalid index is included so the caller can log
    /// it for debugging.
    #[error("register index {0} is out of range")]
    RegisterOutOfRange(usize),

    /// The VM's step counter exceeded the configured maximum.
    ///
    /// Produced by the VM execution layer as a denial-of-service guard. If
    /// firmware contains an infinite loop or unexpectedly long computation,
    /// execution is terminated rather than hanging the calling thread. The
    /// limit can be tuned with `SecureVm::set_max_steps`.
    #[error("execution limit exceeded")]
    ExecutionLimitExceeded,

    /// A `Call` instruction exceeded the maximum subroutine nesting depth.
    ///
    /// Produced by the VM execution layer when the call stack depth reaches
    /// `CALL_STACK_DEPTH_LIMIT` (256). Prevents stack-overflow attacks from
    /// unbounded recursion in firmware. Legitimate firmware should never hit
    /// this limit in practice.
    #[error("call stack overflow")]
    CallStackOverflow,

    /// A value push would exceed the maximum evaluation-stack depth.
    ///
    /// Produced by the VM execution layer when `self.stack.len() >= MAX_STACK_DEPTH`
    /// (1 024 values) before a push. Prevents heap exhaustion from malicious
    /// firmware that pushes without popping. Legitimate firmware should never hit
    /// this limit in practice.
    #[error("stack overflow")]
    StackOverflow,

    /// An underlying cryptographic operation failed.
    ///
    /// Produced by the crypto layer (AES-GCM, Argon2id) when encryption,
    /// decryption, or key derivation fails. The error is intentionally
    /// opaque — reporting the specific internal error could help an attacker
    /// distinguish between wrong-key and corrupt-ciphertext scenarios.
    #[error("crypto error")]
    Crypto,

    /// A binary asset blob has a bad format, wrong magic bytes, or failed
    /// authentication.
    ///
    /// Produced by the firmware/license layer when parsing `firmware.bin`,
    /// `license.bin`, or `codesign.bin`. The inner string provides a
    /// developer-facing description of what was wrong, but should not be
    /// surfaced to end users.
    #[error("invalid encrypted package: {0}")]
    InvalidPackage(String),

    /// The license payload is structurally invalid or the identity check
    /// failed.
    ///
    /// Produced by the firmware layer when the license cannot be parsed, its
    /// magic bytes are wrong, or the runtime app identity (package name,
    /// signing cert, installer) does not match what the license was issued for.
    #[error("invalid license: {0}")]
    InvalidLicense(String),

    /// A lookup in the secure key-value store found no matching entry.
    ///
    /// Produced by `SecureStore::get` when the requested key has not been
    /// stored.
    #[error("key not found")]
    KeyNotFound,

    /// A caller-supplied value is out of range or otherwise unusable.
    ///
    /// Produced at various validation points: empty program, passphrase too
    /// short, string too long for the binary format, shift amount out of range,
    /// etc. The inner string explains which constraint was violated.
    #[error("invalid input: {0}")]
    InvalidInput(String),

    /// An anti-debugging or environment-integrity check failed.
    ///
    /// Produced by the environment layer (`is_debugger_attached()`) and
    /// surfaced by the VM when a tracer or dynamic instrumentation framework
    /// is detected. The VM stops immediately and returns this error so that
    /// secrets are cleared from memory before the attacker can read them.
    #[error("environment check failed")]
    EnvironmentBlocked,
}
