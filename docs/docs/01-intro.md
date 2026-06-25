---
id: intro
title: "Introduction: The Problem We Are Solving"
sidebar_position: 1
---

## Android apps can be reverse-engineered

When you build an Android app, the code you write gets compiled and packaged into a file ending in `.apk`. An APK is simply a ZIP archive containing your compiled Kotlin/Java code (in a format called *DEX*), your native libraries (`.so` files), and your assets.

The problem is that this compiled code is not truly secret. Anyone who downloads your APK can run tools like **jadx** or **apktool** to reconstruct something very close to your original source code. Even your native `.so` libraries can be loaded into **Ghidra** or **IDA Pro** and analysed.

:::tip **The Glass House**

Imagine your business logic is written on a whiteboard inside a glass house. Anyone walking by can read it. Hiding it inside the glass house does not help — it is still visible. You need to put it in a locked room with opaque walls.

:::

This is a real business problem. Examples of code that should not be easily readable from an APK:

- Licence validation logic ("is this user's subscription active?")
- Anti-cheat algorithms in mobile games
- Proprietary financial calculation formulas
- Security-critical authentication flows

## What this library does

**Secure Android VM** solves this problem by:

1. Expressing your sensitive logic as *bytecode* — a stream of bytes that only this library's custom virtual machine can interpret.
2. **Encrypting** that bytecode before it goes into the APK. The decryption key is mathematically tied to your app's signing certificate, so a repackaged APK cannot decrypt it.
3. Verifying a **digital signature** that covers the encrypted files, so any modification is detected immediately.
4. Running multiple **anti-analysis checks** at startup to detect debuggers, root access, and emulators.

:::info **Virtual Machine (VM)**

A virtual machine is a program that executes a custom set of instructions, like a mini-CPU implemented in software. Instead of running directly on your phone's ARM processor, your "firmware" runs on this software CPU. The instruction set is custom-designed and changes per-licence, so an attacker who extracts the encrypted bytes still cannot understand them without knowing the instruction mapping.

:::

## How to read this document

This document is structured so that you can read it from start to finish without needing prior knowledge of cryptography or Android internals. Each concept is introduced before it is used.

- **Sections 2--3**: Cryptography and Android security foundations. Read these first even if they feel slow — the rest of the document assumes you know these concepts.
- **Sections 4--6**: Requirements, architecture, and security design. The *what* and *why* before the *how*.
- **Sections 7--8**: Implementation details and obfuscation.
- **Sections 9--10**: Asset generation and Kotlin usage — the practical "what you type" sections.
- **Sections 11--12**: Modern engineering practices (CI, supply chain, key management).
- **Section 13**: Glossary — look up any term you encounter.

:::info

Blue boxes explain concepts. Green boxes give analogies. Purple boxes describe modern industry practices. Orange boxes are checkpoints to test your understanding. Red boxes are security warnings that must not be ignored.

:::
