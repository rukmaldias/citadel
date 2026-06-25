//! Fuzz `Program::from_bytes` and `Program::from_bytes_with_table` — the VM
//! bytecode parser.
//!
//! The parser iterates over (opcode byte, operand bytes) pairs and must never
//! allocate more than `MAX_PROGRAM_LEN` (1 000 000) instructions regardless of
//! what the length field claims. It must also reject unknown opcodes cleanly.
//!
//! We also fuzz `from_bytes_with_table` with the identity table and a
//! fixed-seed shuffled table to exercise the opcode-remapping path.

#![no_main]

use libfuzzer_sys::fuzz_target;
use secure_android_vm::{OpcodeTable, Program};

// Fixed seed — chosen once, never changes, so the fuzzer can build a stable
// corpus across runs. Not a security value.
const SEED: [u8; 32] = [0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

fuzz_target!(|data: &[u8]| {
    // Identity table (zero seed).
    let _ = Program::from_bytes(data);

    // Shuffled table — exercises the opcode-remap branch.
    let table = OpcodeTable::from_seed(&SEED);
    let _ = Program::from_bytes_with_table(data, &table);
});
