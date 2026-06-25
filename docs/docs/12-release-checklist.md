---
id: release-checklist
title: Release Build Checklist
sidebar_position: 12
---

Use this checklist before distributing any production APK. Check every item.

1. **Replace `LICENCE_EMBED_SECRET`** with 32 random bytes in `src/firmware.rs`. Stored as a CI secret. Never committed to git.
2. **Replace Ed25519 public key** in `src/keys.rs` with your generated key. Private key stored in secrets manager or HSM.
3. **Generate assets** using the *release* signing certificate. Verify the tool prints `firmware_flags=0 (release mode)`.
4. **Verify `firmware_flags: 0`** in `licensepack.json` — bit 0 (trace) and bit 1 (allow debugger) must both be cleared. A dev licence with `firmware_flags: 3` must be replaced before shipping.
5. **Verify three asset files** are present and non-zero in `app/src/main/assets/`.
6. **Build the `.so`** with all four enforce flags and `--release`.
7. **Run `patch_so`** for each ABI. Verify output shows non-zero sha256 and hmac values.
8. **Test the signed APK** on a physical device (not an emulator — the emulator check will block startup).
9. **Check CI is green**: all six jobs passing, supply-chain audit clean.
10. **Set `installer_policy: "required:com.android.vending"`** for Play Store distribution.

:::danger

Steps 1, 2, and 7 are the most commonly forgotten. The `enforce_*` feature flags exist precisely to catch steps 1 and 2 at runtime. Step 7 (`patch_so`) is caught by `enforce_patch`. These are not optional — each missing step leaves a security gap.

:::
