//! Stack-machine bytecode for the Secure VM.
//!
//! This module defines the instruction set, the opcode-remapping table that
//! provides per-license polymorphism, and the `Program` container that ties
//! them together.
//!
//! ## Instruction set
//!
//! The VM is a **stack machine**: instructions operate on an evaluation stack
//! of `i64` values. 64-bit signed integers cover the full range of Java `long`
//! without overflow surprises on Android. A small bank of 256 **registers**
//! (`Store`/`Load`) provides named variables for structured algorithms.
//!
//! The current instruction set (`OPCODE_COUNT = 25`) supports:
//!
//! - Arithmetic: `PushI64`, `Add`, `Sub`, `Mul`, `Div`, `Mod`
//! - Comparison: `Eq`, `Lt`, `Gt` (push 1/0)
//! - Bitwise: `And`, `Or`, `Xor`, `Shl`, `Shr`, `Not`
//! - Stack: `Dup`, `Pop`
//! - Control flow: `Jmp`, `JmpIf`, `JmpIfNot`, `Call`, `Ret`, `Halt`
//! - Memory: `Store(register)`, `Load(register)`
//!
//! This set is sufficient for loops, conditionals, and subroutines —
//! effectively Turing-complete within the step and call-depth limits the VM
//! enforces at runtime.
//!
//! ## Per-license opcode remapping
//!
//! [`OpcodeTable`] maps each of the 25 canonical opcode bytes to a customer-
//! specific encoded byte, derived from the license's `opcode_seed` via
//! ChaCha20. Because different licenses assign different bytes to the same
//! instruction, an attacker who reverse-engineers one customer's VM cannot
//! directly apply that knowledge to another's firmware.
//!
//! The zero seed is a defined sentinel that produces the identity table
//! (encoded = canonical), useful for tests and single-customer deployments.
//!
//! ## Program limits
//!
//! [`MAX_PROGRAM_LEN`] caps the number of decoded instructions to prevent
//! unbounded heap allocation from a crafted or corrupted firmware blob.

use rand::seq::SliceRandom;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use zeroize::Zeroize;

use crate::{Result, VmError};

// Opcode constants for the compact binary bytecode format.
// Each instruction is identified by a single byte opcode. Values 0x01–0x24
// and 0xFF are assigned; all other byte values are rejected by the parser.
//
// Arithmetic (original)
const OP_PUSH_I64: u8    = 0x01; // 8-byte LE i64 payload
const OP_ADD: u8         = 0x02;
const OP_SUB: u8         = 0x03;
const OP_MUL: u8         = 0x04;
const OP_DIV: u8         = 0x05;
const OP_STORE: u8       = 0x06; // 1-byte register index payload
const OP_LOAD: u8        = 0x07; // 1-byte register index payload
// Extended arithmetic
const OP_MOD: u8         = 0x08;
// Comparison — push 1 (true) or 0 (false)
const OP_EQ: u8          = 0x09;
const OP_LT: u8          = 0x0A;
const OP_GT: u8          = 0x0B;
// Bitwise
const OP_AND: u8         = 0x0C;
const OP_OR: u8          = 0x0D;
const OP_XOR: u8         = 0x0E;
const OP_SHL: u8         = 0x0F;
const OP_SHR: u8         = 0x10;
const OP_NOT: u8         = 0x11;
// Stack manipulation
const OP_DUP: u8         = 0x12;
const OP_POP: u8         = 0x13;
// Control flow — 4-byte u32 LE absolute instruction-index payload
const OP_JMP: u8         = 0x20;
const OP_JMP_IF: u8      = 0x21;
const OP_JMP_IF_NOT: u8  = 0x22;
const OP_CALL: u8        = 0x23;
const OP_RET: u8         = 0x24;
// Halt
const OP_HALT: u8        = 0xFF;

/// Number of distinct opcode bytes in the VM's instruction set.
pub const OPCODE_COUNT: usize = 25;

/// The canonical opcode bytes, in canonical order (instruction index 0–24).
///
/// `OpcodeTable::from_seed` shuffles this array — the result is the encoded
/// byte assigned to each instruction for a given license's opcode seed. The
/// identity table (`OpcodeTable::identity()`) leaves this array unchanged.
const CANONICAL_OPCODES: [u8; OPCODE_COUNT] = [
    OP_PUSH_I64, OP_ADD, OP_SUB, OP_MUL, OP_DIV,
    OP_STORE,    OP_LOAD,
    OP_MOD,
    OP_EQ,  OP_LT,  OP_GT,
    OP_AND, OP_OR,  OP_XOR, OP_SHL, OP_SHR, OP_NOT,
    OP_DUP, OP_POP,
    OP_JMP, OP_JMP_IF, OP_JMP_IF_NOT, OP_CALL, OP_RET,
    OP_HALT,
];

/// A bijective mapping between canonical opcode bytes and the encoded bytes
/// stored in a customer's `firmware.bin`.
///
/// ## Why this matters
///
/// In the default (identity) table every opcode byte in the firmware is the
/// same as its canonical value (`Add` is always `0x02`, etc.). Any two
/// customers' firmware blobs use the same byte assignments, so an attacker
/// who reverse-engineers the opcode table for one customer can trivially
/// read another's bytecode once decrypted.
///
/// With a per-license `OpcodeTable`, each customer's firmware uses a
/// different random assignment. `Add` might be `0x24` for customer A and
/// `0x0F` for customer B. The attacker must reverse-engineer the VM AND
/// know the customer-specific opcode seed to decode any given firmware blob —
/// and the seed is inside the encrypted license.
///
/// ## Usage
///
/// ```text
/// // Build tool: encode firmware for a specific license
/// let table = OpcodeTable::from_seed(&opcode_seed);
/// let encoded_bytes = program.to_bytes_with_table(&table);
/// // ...encrypt encoded_bytes into firmware.bin...
///
/// // VM: decode firmware using the seed from the decrypted license
/// let table = OpcodeTable::from_seed(license.opcode_seed());
/// let program = Program::from_bytes_with_table(&decrypted_firmware, &table)?;
/// ```
///
/// A seed of all-zeros returns the identity table — encoded bytes equal
/// canonical bytes, no remapping applied. Use this for tests and the default
/// single-customer case.
pub struct OpcodeTable {
    /// remap[canonical_byte] = encoded_byte. Zero for bytes not in the
    /// canonical set (0x00 is not a valid canonical opcode).
    remap: [u8; 256],
    /// unremap[encoded_byte] = canonical_byte. Zero for bytes that are not
    /// valid encoded opcodes in this table.
    unremap: [u8; 256],
}

impl OpcodeTable {
    /// Returns the identity table: encoded bytes are the same as canonical
    /// bytes, so `to_bytes_with_table` and `from_bytes_with_table` behave
    /// identically to `to_bytes` and `from_bytes`.
    pub fn identity() -> Self {
        let mut remap   = [0u8; 256];
        let mut unremap = [0u8; 256];
        for &b in CANONICAL_OPCODES.iter() {
            remap[b as usize]   = b;
            unremap[b as usize] = b;
        }
        Self { remap, unremap }
    }

    /// Derives a deterministic opcode table from a 32-byte seed.
    ///
    /// Internally, the 25 canonical opcode bytes are shuffled using
    /// `rand_chacha::ChaCha20Rng` seeded with `seed` (Fisher-Yates via
    /// `SliceRandom::shuffle`). `ChaCha20Rng` is algorithm-stable across
    /// crate versions; `StdRng` is not. The result is bijective: every
    /// canonical byte maps to a unique encoded byte and vice versa.
    ///
    /// A seed of all zeros returns `OpcodeTable::identity()` — a defined
    /// sentinel meaning "no remapping". Any other seed produces a shuffled
    /// table. Two licenses with different seeds have incompatible opcode
    /// encodings: bytecode compiled for one license cannot be parsed
    /// correctly by a VM loaded with the other.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        if seed == &[0u8; 32] {
            return Self::identity();
        }

        let mut shuffled = CANONICAL_OPCODES;
        // ChaCha20Rng is algorithm-stable across Rust/rand versions; StdRng is not.
        let mut rng = ChaCha20Rng::from_seed(*seed);
        shuffled.shuffle(&mut rng);

        let mut remap   = [0u8; 256];
        let mut unremap = [0u8; 256];
        for (i, &canonical) in CANONICAL_OPCODES.iter().enumerate() {
            let encoded = shuffled[i];
            remap[canonical as usize]  = encoded;
            unremap[encoded as usize]  = canonical;
        }
        Self { remap, unremap }
    }

    /// Maps a canonical opcode byte to its encoded form for this table.
    ///
    /// For the identity table this is the identity function. For a shuffled
    /// table, a given canonical byte is replaced with a different byte
    /// specific to this license's seed.
    pub(crate) fn remap_opcode(&self, canonical: u8) -> u8 {
        self.remap[canonical as usize]
    }

    /// Maps an encoded byte back to its canonical opcode.
    ///
    /// Returns `None` if `encoded` is not a valid opcode in this table
    /// (i.e., the bytecode byte is unrecognised). The zero-sentinel is safe
    /// because `0x00` is never a valid canonical opcode.
    pub(crate) fn unremap_opcode(&self, encoded: u8) -> Option<u8> {
        let c = self.unremap[encoded as usize];
        if c == 0 { None } else { Some(c) }
    }
}

/// One instruction that the virtual machine can execute.
///
/// The instruction set covers arithmetic, bitwise logic, comparison, stack
/// manipulation, subroutine calls, and conditional branching. Together these
/// are sufficient to express loops, conditionals, and structured subroutines —
/// making the firmware language Turing-complete within the step and call-depth
/// limits enforced by the runtime.
///
/// The format is a proprietary stack machine. Because no public tooling exists
/// for this bytecode, an attacker who obtains `firmware.bin` and manages to
/// decrypt it still has to reverse-engineer the instruction set before they can
/// understand the logic. Per-license opcode remapping (see `OpcodeTable`) adds
/// a further layer: the same byte means different instructions in different
/// customers' firmware, so reverse-engineering one customer's VM reveals nothing
/// about another's.
///
/// ## Stack ordering convention
///
/// For binary operations the operand pushed *first* is the left-hand side and
/// the operand pushed *second* (closer to the top) is the right-hand side.
/// So `PushI64(10), PushI64(3), Sub` computes `10 − 3 = 7`.
///
/// ## Jump targets
///
/// `Jmp`, `JmpIf`, `JmpIfNot`, and `Call` all take an absolute
/// **instruction index** — the position in the instruction array produced by
/// `Program::new` / `from_bytes`. A target equal to the program length jumps
/// past the last instruction and halts. A target greater than the program
/// length is a runtime error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Instruction {
    // ── Arithmetic ────────────────────────────────────────────────────────────

    /// Push a signed 64-bit integer constant onto the evaluation stack.
    ///
    /// Canonical encoding: `0x01` + 8 bytes little-endian `i64`.
    PushI64(i64),

    /// Pop `lhs` and `rhs`, push `lhs + rhs`. Aborts on overflow.
    Add,

    /// Pop `lhs` and `rhs`, push `lhs − rhs`. Aborts on overflow.
    Sub,

    /// Pop `lhs` and `rhs`, push `lhs × rhs`. Aborts on overflow.
    Mul,

    /// Pop `lhs` and `rhs`, push integer quotient `lhs / rhs`.
    ///
    /// Aborts with `DivisionByZero` if `rhs == 0` or on overflow
    /// (`i64::MIN / -1`).
    Div,

    /// Pop `lhs` and `rhs`, push `lhs % rhs` (signed remainder).
    ///
    /// Aborts with `DivisionByZero` if `rhs == 0` or on overflow.
    Mod,

    // ── Register file ─────────────────────────────────────────────────────────

    /// Pop the top-of-stack and write it to register `r` (0–15).
    ///
    /// Canonical encoding: `0x06` + 1-byte register index.
    Store(u8),

    /// Push the current value of register `r` (0–15) onto the stack.
    ///
    /// Canonical encoding: `0x07` + 1-byte register index.
    Load(u8),

    // ── Comparison ────────────────────────────────────────────────────────────

    /// Pop `lhs` and `rhs`, push `1` if equal, `0` otherwise.
    Eq,

    /// Pop `lhs` and `rhs`, push `1` if `lhs < rhs`, `0` otherwise.
    Lt,

    /// Pop `lhs` and `rhs`, push `1` if `lhs > rhs`, `0` otherwise.
    Gt,

    // ── Bitwise ───────────────────────────────────────────────────────────────

    /// Pop `lhs` and `rhs`, push `lhs & rhs` (bitwise AND).
    And,

    /// Pop `lhs` and `rhs`, push `lhs | rhs` (bitwise OR).
    Or,

    /// Pop `lhs` and `rhs`, push `lhs ^ rhs` (bitwise XOR).
    Xor,

    /// Pop `shift` then `value`, push `value << shift`. `shift` must be 0–63.
    Shl,

    /// Pop `shift` then `value`, push `value >> shift` (arithmetic).
    /// `shift` must be 0–63.
    Shr,

    /// Pop `value`, push `~value` (bitwise NOT).
    Not,

    // ── Stack manipulation ────────────────────────────────────────────────────

    /// Duplicate the top-of-stack without consuming it.
    Dup,

    /// Discard the top-of-stack.
    Pop,

    // ── Control flow ─────────────────────────────────────────────────────────

    /// Unconditionally jump to instruction index `target`.
    ///
    /// Canonical encoding: `0x20` + 4-byte little-endian `u32`.
    Jmp(u32),

    /// Pop `condition`; jump to `target` if `condition != 0`.
    ///
    /// Canonical encoding: `0x21` + 4-byte little-endian `u32`.
    JmpIf(u32),

    /// Pop `condition`; jump to `target` if `condition == 0`.
    ///
    /// Canonical encoding: `0x22` + 4-byte little-endian `u32`.
    JmpIfNot(u32),

    /// Push the return address and jump to `target` (subroutine call).
    ///
    /// Limited to `CALL_STACK_DEPTH_LIMIT` (256) nested frames.
    ///
    /// Canonical encoding: `0x23` + 4-byte little-endian `u32`.
    Call(u32),

    /// Return from a subroutine. Pops the call stack and jumps to the saved
    /// return address. Aborts with `StackUnderflow` if there is no matching
    /// `Call`.
    Ret,

    // ── Halt ──────────────────────────────────────────────────────────────────

    /// Stop execution. The top-of-stack value becomes the `RunReport::result`.
    Halt,
}

impl Zeroize for Instruction {
    fn zeroize(&mut self) {
        // Zero the payload fields first using volatile writes so the compiler
        // cannot elide them. Then overwrite *self with Halt — the smallest
        // unit variant — to replace the discriminant tag and any union storage
        // that was shared between the old variant and the new one.
        match self {
            Self::PushI64(v)    => v.zeroize(),
            Self::Store(r) | Self::Load(r) => r.zeroize(),
            Self::Jmp(t) | Self::JmpIf(t) | Self::JmpIfNot(t) | Self::Call(t) => t.zeroize(),
            _ => {}
        }
        *self = Self::Halt;
    }
}

/// Hard upper bound on the number of instructions in a single program.
///
/// Without this limit an untrusted (or corrupted) firmware blob could produce a
/// bytecode stream that allocates an unbounded `Vec<Instruction>` in
/// `from_bytes_with_table`, exhausting heap memory before any bounds check
/// can trigger. 1,000,000 instructions is orders of magnitude larger than any
/// legitimate program while still fitting comfortably in a few MB of RAM.
pub const MAX_PROGRAM_LEN: usize = 1_000_000;

/// A parsed program made up of VM instructions.
///
/// `Program` owns the decoded instruction list and provides the canonical way
/// to move between the in-memory representation (used for execution) and the
/// compact binary form (used for storage inside encrypted firmware assets).
///
/// Programs are immutable once constructed. Any modification requires building
/// a new `Program` through `new()` or `from_bytes()`, both of which validate
/// the content, preventing a partially-built or empty program from reaching the
/// execution engine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Program {
    instructions: Vec<Instruction>,
}

impl Program {
    /// Creates a new program from an already-built instruction list.
    ///
    /// # Errors
    ///
    /// Returns `InvalidInput` if `instructions` is empty.
    pub fn new(instructions: Vec<Instruction>) -> Result<Self> {
        if instructions.is_empty() {
            return Err(VmError::InvalidInput("program cannot be empty".to_string()));
        }
        Ok(Self { instructions })
    }

    /// Parses a program from raw bytecode bytes using the identity opcode
    /// table (canonical bytes = encoded bytes).
    ///
    /// Equivalent to `Program::from_bytes_with_table(bytes,
    /// &OpcodeTable::identity())`. Use this when no per-license opcode
    /// remapping was applied at build time.
    ///
    /// # Errors
    ///
    /// Returns `InvalidBytecode` if any opcode is unrecognised or a payload
    /// is truncated. Returns `InvalidInput` if the program is empty.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Self::from_bytes_with_table(bytes, &OpcodeTable::identity())
    }

    /// Parses a program from raw bytecode bytes, decoding opcodes through
    /// `table`.
    ///
    /// Each byte that represents an opcode is first mapped through
    /// `table.unremap_opcode()` to recover the canonical opcode, then parsed
    /// normally. Payload bytes (the 8-byte `PushI64` operand, the 1-byte
    /// register index, the 4-byte jump target) are never remapped — only
    /// opcode bytes are affected.
    ///
    /// The table must be the same one that was used when the firmware was
    /// encoded with `to_bytes_with_table`. Using a different table produces
    /// `InvalidBytecode` errors or silently wrong instruction decoding.
    ///
    /// # Errors
    ///
    /// Returns `InvalidBytecode` if any encoded byte is not a valid opcode in
    /// `table`, or if a payload is truncated. Returns `InvalidInput` if the
    /// decoded program is empty.
    pub fn from_bytes_with_table(bytes: &[u8], table: &OpcodeTable) -> Result<Self> {
        let mut offset = 0;
        let mut instructions = Vec::new();

        while offset < bytes.len() {
            let op_offset = offset;
            let encoded = bytes[offset];
            offset += 1;

            // Decode to canonical byte through the opcode table.
            let opcode = table
                .unremap_opcode(encoded)
                .ok_or_else(|| VmError::InvalidBytecode {
                    offset: op_offset,
                    reason: "unknown opcode".to_string(),
                })?;

            let instruction = match opcode {
                OP_PUSH_I64    => Instruction::PushI64(read_i64(bytes, &mut offset, op_offset)?),
                OP_ADD         => Instruction::Add,
                OP_SUB         => Instruction::Sub,
                OP_MUL         => Instruction::Mul,
                OP_DIV         => Instruction::Div,
                OP_MOD         => Instruction::Mod,
                OP_STORE       => Instruction::Store(read_register(bytes, &mut offset, op_offset)?),
                OP_LOAD        => Instruction::Load(read_register(bytes, &mut offset, op_offset)?),
                OP_EQ          => Instruction::Eq,
                OP_LT          => Instruction::Lt,
                OP_GT          => Instruction::Gt,
                OP_AND         => Instruction::And,
                OP_OR          => Instruction::Or,
                OP_XOR         => Instruction::Xor,
                OP_SHL         => Instruction::Shl,
                OP_SHR         => Instruction::Shr,
                OP_NOT         => Instruction::Not,
                OP_DUP         => Instruction::Dup,
                OP_POP         => Instruction::Pop,
                OP_JMP         => Instruction::Jmp(read_u32(bytes, &mut offset, op_offset)?),
                OP_JMP_IF     => Instruction::JmpIf(read_u32(bytes, &mut offset, op_offset)?),
                OP_JMP_IF_NOT => Instruction::JmpIfNot(read_u32(bytes, &mut offset, op_offset)?),
                OP_CALL        => Instruction::Call(read_u32(bytes, &mut offset, op_offset)?),
                OP_RET         => Instruction::Ret,
                OP_HALT        => Instruction::Halt,
                _              => return invalid(op_offset, "unknown canonical opcode"),
            };

            instructions.push(instruction);
            if instructions.len() > MAX_PROGRAM_LEN {
                return Err(VmError::InvalidBytecode {
                    offset: op_offset,
                    reason: format!(
                        "program exceeds MAX_PROGRAM_LEN ({MAX_PROGRAM_LEN}) instructions"
                    ),
                });
            }
        }

        Self::new(instructions)
    }

    /// Serializes the program using the identity opcode table.
    ///
    /// Equivalent to `to_bytes_with_table(&OpcodeTable::identity())`.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.to_bytes_with_table(&OpcodeTable::identity())
    }

    /// Serializes the program, encoding each opcode byte through `table`.
    ///
    /// Each canonical opcode byte is replaced with
    /// `table.remap_opcode(canonical)` before being written. Payload bytes
    /// are written unchanged. The output is byte-for-byte compatible with
    /// `from_bytes_with_table` using the same table.
    ///
    /// Use this in the asset-generation tool when building firmware for a
    /// license that has a non-identity opcode seed:
    ///
    /// ```text
    /// let table = OpcodeTable::from_seed(license.opcode_seed());
    /// let encoded = program.to_bytes_with_table(&table);
    /// // encrypt `encoded` into firmware.bin
    /// ```
    pub fn to_bytes_with_table(&self, table: &OpcodeTable) -> Vec<u8> {
        let mut bytes = Vec::new();

        for instruction in &self.instructions {
            match instruction {
                Instruction::PushI64(v) => {
                    bytes.push(table.remap_opcode(OP_PUSH_I64));
                    bytes.extend_from_slice(&v.to_le_bytes());
                }
                Instruction::Add  => bytes.push(table.remap_opcode(OP_ADD)),
                Instruction::Sub  => bytes.push(table.remap_opcode(OP_SUB)),
                Instruction::Mul  => bytes.push(table.remap_opcode(OP_MUL)),
                Instruction::Div  => bytes.push(table.remap_opcode(OP_DIV)),
                Instruction::Mod  => bytes.push(table.remap_opcode(OP_MOD)),
                Instruction::Store(r) => { bytes.push(table.remap_opcode(OP_STORE)); bytes.push(*r); }
                Instruction::Load(r)  => { bytes.push(table.remap_opcode(OP_LOAD));  bytes.push(*r); }
                Instruction::Eq   => bytes.push(table.remap_opcode(OP_EQ)),
                Instruction::Lt   => bytes.push(table.remap_opcode(OP_LT)),
                Instruction::Gt   => bytes.push(table.remap_opcode(OP_GT)),
                Instruction::And  => bytes.push(table.remap_opcode(OP_AND)),
                Instruction::Or   => bytes.push(table.remap_opcode(OP_OR)),
                Instruction::Xor  => bytes.push(table.remap_opcode(OP_XOR)),
                Instruction::Shl  => bytes.push(table.remap_opcode(OP_SHL)),
                Instruction::Shr  => bytes.push(table.remap_opcode(OP_SHR)),
                Instruction::Not  => bytes.push(table.remap_opcode(OP_NOT)),
                Instruction::Dup  => bytes.push(table.remap_opcode(OP_DUP)),
                Instruction::Pop  => bytes.push(table.remap_opcode(OP_POP)),
                Instruction::Jmp(t) => {
                    bytes.push(table.remap_opcode(OP_JMP));
                    bytes.extend_from_slice(&t.to_le_bytes());
                }
                Instruction::JmpIf(t) => {
                    bytes.push(table.remap_opcode(OP_JMP_IF));
                    bytes.extend_from_slice(&t.to_le_bytes());
                }
                Instruction::JmpIfNot(t) => {
                    bytes.push(table.remap_opcode(OP_JMP_IF_NOT));
                    bytes.extend_from_slice(&t.to_le_bytes());
                }
                Instruction::Call(t) => {
                    bytes.push(table.remap_opcode(OP_CALL));
                    bytes.extend_from_slice(&t.to_le_bytes());
                }
                Instruction::Ret  => bytes.push(table.remap_opcode(OP_RET)),
                Instruction::Halt => bytes.push(table.remap_opcode(OP_HALT)),
            }
        }

        bytes
    }

    /// Returns the instruction slice for the execution engine.
    ///
    /// `pub(crate)` intentionally: external callers should execute through
    /// `SecureVm::run()` or serialise through `to_bytes()`. Direct access to
    /// the instruction list would let callers reconstruct firmware logic.
    pub(crate) fn instructions(&self) -> &[Instruction] {
        &self.instructions
    }
}

impl Zeroize for Program {
    fn zeroize(&mut self) {
        self.instructions.zeroize();
    }
}

impl Drop for Program {
    fn drop(&mut self) {
        self.zeroize();
    }
}

// ── Parser helpers ────────────────────────────────────────────────────────────

fn read_i64(bytes: &[u8], offset: &mut usize, op_offset: usize) -> Result<i64> {
    if *offset + 8 > bytes.len() {
        return invalid(op_offset, "PUSH_I64 requires 8 payload bytes");
    }
    let mut raw = [0_u8; 8];
    raw.copy_from_slice(&bytes[*offset..*offset + 8]);
    *offset += 8;
    Ok(i64::from_le_bytes(raw))
}

fn read_u32(bytes: &[u8], offset: &mut usize, op_offset: usize) -> Result<u32> {
    if *offset + 4 > bytes.len() {
        return invalid(op_offset, "control-flow instruction requires 4 payload bytes");
    }
    let mut raw = [0_u8; 4];
    raw.copy_from_slice(&bytes[*offset..*offset + 4]);
    *offset += 4;
    Ok(u32::from_le_bytes(raw))
}

fn read_register(bytes: &[u8], offset: &mut usize, op_offset: usize) -> Result<u8> {
    if *offset >= bytes.len() {
        return invalid(op_offset, "register instruction requires 1 payload byte");
    }
    let register = bytes[*offset];
    *offset += 1;
    Ok(register)
}

fn invalid<T>(offset: usize, reason: &str) -> Result<T> {
    Err(VmError::InvalidBytecode {
        offset,
        reason: reason.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pins the exact Fisher-Yates shuffle output for a fixed seed so that a
    /// `rand_chacha` upgrade that silently changes the algorithm is caught
    /// immediately. If this test fails after bumping `rand_chacha`, the encoded
    /// opcode tables are incompatible with all existing firmware — investigate
    /// before merging.
    #[test]
    fn from_seed_chacha20_output_is_pinned() {
        let seed: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
        ];
        let table = OpcodeTable::from_seed(&seed);
        // Collect the encoded byte assigned to each canonical opcode, in order.
        let shuffled: Vec<u8> = CANONICAL_OPCODES
            .iter()
            .map(|&c| table.remap_opcode(c))
            .collect();

        // Pinned output for seed [0x01..0x20] from rand_chacha 0.3 / ChaCha20.
        // If this fails after a dependency bump, the shuffle algorithm changed and
        // existing firmware cannot be decoded — do NOT just update the values.
        let expected: [u8; OPCODE_COUNT] = [
            0x0d, 0x07, 0x05, 0x11, 0xff, 0x0b, 0x06, 0x09, 0x20,
            0x0f, 0x12, 0x24, 0x0e, 0x02, 0x22, 0x21, 0x23, 0x04,
            0x0a, 0x01, 0x08, 0x0c, 0x13, 0x03, 0x10,
        ];

        assert_eq!(
            shuffled.as_slice(),
            expected.as_slice(),
            "ChaCha20 shuffle changed — actual: {:02x?}", shuffled
        );
    }
}
