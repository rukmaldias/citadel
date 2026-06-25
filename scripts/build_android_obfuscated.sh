#!/usr/bin/env bash
# Build the Android JNI library with LLVM obfuscation (CFF + SUB) applied.
#
# Usage:
#   scripts/build_android_obfuscated.sh [arm64-v8a | armeabi-v7a | x86_64] [api-level]
#
# Defaults: arm64-v8a, API 26.
#
# Prerequisites:
#   - ANDROID_NDK_HOME set (or SDK present via android-actions/setup-android)
#   - cargo-ndk installed (cargo install cargo-ndk)
#   - scripts/build_obfuscator.sh has already been run, OR the obfuscator
#     plugin will be built automatically by this script.
#
# The LLVM plugin is loaded into rustc (not into the NDK compiler) because
# our crate is pure Rust.  The plugin runs during Rust→LLVM-IR codegen on the
# host machine; the resulting native code targets the chosen Android ABI.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

ABI="${1:-arm64-v8a}"
API="${2:-26}"

case "$ABI" in
  arm64-v8a)       TARGET="aarch64-linux-android"  ;;
  armeabi-v7a)     TARGET="armv7-linux-androideabi" ;;
  x86_64)          TARGET="x86_64-linux-android"   ;;
  *)  echo "Unknown ABI '$ABI'. Use arm64-v8a | armeabi-v7a | x86_64" >&2; exit 1 ;;
esac

# ── 1. Ensure plugin is built ─────────────────────────────────────────────────
PLUGIN_CACHE="$REPO_ROOT/build/obfuscator/plugin_path.txt"
if [[ ! -f "$PLUGIN_CACHE" ]]; then
    echo "Plugin not found — building now..."
    bash "$SCRIPT_DIR/build_obfuscator.sh"
fi
PLUGIN_PATH=$(cat "$PLUGIN_CACHE")
if [[ ! -f "$PLUGIN_PATH" ]]; then
    echo "Cached plugin path '$PLUGIN_PATH' not found — rebuilding..." >&2
    bash "$SCRIPT_DIR/build_obfuscator.sh"
    PLUGIN_PATH=$(cat "$PLUGIN_CACHE")
fi
echo "Using obfuscator plugin: $PLUGIN_PATH"

# ── 2. Build ──────────────────────────────────────────────────────────────────
# The plugin registers `registerOptimizerLastEPCallback`, so simply loading it
# is enough — no explicit `--passes=` flag needed.  It fires automatically for
# any O1+ build, which `--profile release-obfuscated` (below) guarantees.
#
# Note: RUSTFLAGS set here overrides any [target.xxx.rustflags] in config.toml.
# The base optimisation flags are already in the release-obfuscated profile.
# -Z llvm-plugins is rustc's native mechanism for loading LLVM pass plugins.
# The -Z namespace requires the nightly channel.  Install the target first:
#   rustup target add aarch64-linux-android --toolchain nightly
RUST_CHANNEL="${RUST_CHANNEL:-nightly}"
export RUSTFLAGS="-Z llvm-plugins=${PLUGIN_PATH}"

echo "Building $ABI (target=$TARGET, API=$API) with obfuscation..."
cargo "+${RUST_CHANNEL}" ndk \
    --target "$ABI" \
    --platform "$API" \
    -- build \
        --profile release-obfuscated \
        --features jni

SO=$(find "$REPO_ROOT/target/$TARGET/release-obfuscated" \
    -name "libsecure_android_vm.so" | head -1)

if [[ -z "$SO" ]]; then
    echo "ERROR: .so not found after build." >&2; exit 1
fi
echo ""
echo "Built: $SO"
echo "Size:  $(du -sh "$SO" | awk '{print $1}')"
