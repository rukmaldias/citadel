---
id: vm-design
title: "VM Design: The Instruction Set"
sidebar_position: 7
---

## What is a stack machine?

The VM is a **stack machine**: instructions operate on a *stack* (a last-in, first-out list of values) rather than explicitly specifying registers for each operation.

:::tip **A stack of plates**

Imagine a stack of numbered plates. `PushI64(5)` adds a plate labelled "5" to the top. `PushI64(3)` adds "3" on top of "5". `Add` takes the two top plates (3 and 5), adds them, and puts back a single plate labelled "8". `Halt` looks at the top plate and returns its value as the result.

:::

The VM also has 16 **registers** — named slots that can hold `i64` values. Registers let you save a computed value for later use without it being immediately consumed by the next operation.

## The instruction set

All values are signed 64-bit integers (`i64`). All arithmetic uses *checked operations* — overflow and divide-by-zero produce an error rather than silently wrapping or producing undefined behaviour.

| Instruction | Opcode | Stack effect | Description |
|---|---|---|---|
| *Arithmetic* | | | |
| PushI64(n) | 0x01 | → n | Push a 64-bit integer literal |
| Add | 0x02 | a b → a+b | Checked add |
| Sub | 0x03 | a b → a-b | Checked subtract |
| Mul | 0x04 | a b → a×b | Checked multiply |
| Div | 0x05 | a b → a÷b | Checked divide (error on zero) |
| Mod | 0x08 | a b → a mod b | Remainder (error on zero) |
| *Registers* | | | |
| Store(r) | 0x06 | v → | Pop into register r (0--15) |
| Load(r) | 0x07 | → v | Push from register r |
| *Comparison (push 1 or 0)* | | | |
| Eq | 0x09 | a b → (a==b) | 1 if equal, else 0 |
| Lt | 0x0A | a b → (a&lt;b) | 1 if less-than |
| Gt | 0x0B | a b → (a&gt;b) | 1 if greater-than |
| *Bitwise* | | | |
| And | 0x0C | a b → a&amp;b | Bitwise AND |
| Or | 0x0D | a b → a\|b | Bitwise OR |
| Xor | 0x0E | a b → a⊕b | Bitwise XOR |
| Shl | 0x0F | v n → v&lt;&lt;n | Left shift; n in 0–63 |
| Shr | 0x10 | v n → v&gt;&gt;n | Arithmetic right shift |
| Not | 0x11 | v → ~v | Bitwise NOT |
| *Stack* | | | |
| Dup | 0x12 | v → v v | Duplicate top |
| Pop | 0x13 | v → | Discard top |
| *Control flow (4-byte u32 LE target index)* | | | |
| Jmp(t) | 0x20 | --- | Unconditional jump |
| JmpIf(t) | 0x21 | cond → | Jump if cond ≠ 0 |
| JmpIfNot(t) | 0x22 | cond → | Jump if cond = 0 |
| Call(t) | 0x23 | --- | Push return addr; jump (max 256 deep) |
| Ret | 0x24 | --- | Pop call stack; return |
| *Termination* | | | |
| Halt | 0xFF | --- | Stop; return top-of-stack (or 0) |

## A complete worked example

Let us trace the execution of a simple program that computes (10 - 3) × 6, stores the result in register 0, then returns it.

```rust
use secure_android_vm::{Instruction, Program};

// (10 - 3) * 6 = 42
let program = Program::new(vec![
    Instruction::PushI64(10),   // stack: [10]
    Instruction::PushI64(3),    // stack: [10, 3]   <- 3 is TOS
    Instruction::Sub,           // pops 3, pops 10, pushes 10-3=7
                                // stack: [7]
    Instruction::PushI64(6),    // stack: [7, 6]
    Instruction::Mul,           // pops 6, pops 7, pushes 7*6=42
                                // stack: [42]
    Instruction::Store(0),      // pops 42 into register[0]
                                // stack: []
    Instruction::Load(0),       // pushes register[0]=42
                                // stack: [42]
    Instruction::Halt,          // stops; returns TOS = 42
])?;
```

:::info

**Stack ordering for binary ops:** The first value pushed is the *left* operand, and the second (closer to the top) is the *right* operand. So `PushI64(10), PushI64(3), Sub` computes 10 - 3 = 7, not 3 - 10 = -7. This is the natural stack-machine convention.

:::

## A control-flow example: computing max(a, b)

```rust
// Compute max(register[0], register[1]):
// Store 10 in r0, 42 in r1; result should be 42.
let program = Program::new(vec![
    Instruction::PushI64(10),  // i=0
    Instruction::Store(0),     // i=1  register[0] = 10
    Instruction::PushI64(42),  // i=2
    Instruction::Store(1),     // i=3  register[1] = 42

    // if register[0] > register[1], jump to instruction 10 (return r0)
    Instruction::Load(0),      // i=4  stack: [10]
    Instruction::Load(1),      // i=5  stack: [10, 42]
    Instruction::Gt,           // i=6  stack: [0] (10 > 42 is false)
    Instruction::JmpIf(10),    // i=7  cond=0, no jump

    Instruction::Load(1),      // i=8  stack: [42]  <- r1 is bigger
    Instruction::Halt,         // i=9  result = 42

    Instruction::Load(0),      // i=10 stack: [10] (only if r0 > r1)
    Instruction::Halt,         // i=11 result = 10
])?;
```

## Execution limits and why they exist

| Limit | Reason |
|---|---|
| 100,000 steps/run | Prevents infinite loops from hanging the Android UI thread. Configurable via `set_max_steps` for computation-heavy firmware. |
| Stack depth: 1,024 | Prevents unbounded heap growth from deeply nested calls or malicious firmware. 1,024 × 8 bytes = 8 KB. |
| Call stack: 256 frames | Prevents stack-overflow attacks and infinite recursion. |
| Program size: 1,000,000 instructions | Prevents a crafted or corrupted firmware blob from allocating gigabytes of heap during parsing. The parser rejects oversized blobs immediately. |
| Debugger check every 10,000 steps | Catches debuggers attached *after* startup. Without this check, an attacker could attach a debugger after the initial checks pass. |

:::warning **Checkpoint**

You should now understand:

- How a stack machine works (push, pop, binary operations)
- How to write a simple program using the instruction set
- Why execution limits exist and what each limit prevents
- Why control flow uses absolute instruction indices rather than offsets

:::
