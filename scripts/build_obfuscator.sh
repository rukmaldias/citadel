#!/usr/bin/env bash
# Build the SecureVm LLVM obfuscator plugin against the same LLVM that rustc
# bundles.  Must be run on the host that will later invoke `cargo ndk`.
#
# Usage:
#   scripts/build_obfuscator.sh [--release]
#
# Output:
#   build/obfuscator/libSecureVmObfuscatorPlugin.so  (Linux)
#   build/obfuscator/libSecureVmObfuscatorPlugin.dylib (macOS)
#
# The path is also written to build/obfuscator/plugin_path.txt so the caller
# can source it without re-parsing CMake output.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
BUILD_TYPE="${1:---release}"

OBFUSCATOR_SRC="$REPO_ROOT/obfuscator"
BUILD_DIR="$REPO_ROOT/build/obfuscator"

# ── 1. Determine rustc's LLVM version ────────────────────────────────────────
RUSTC_LLVM_MAJOR=$(rustc --version --verbose 2>/dev/null \
    | grep "LLVM version" | awk '{print $3}' | cut -d. -f1)

if [[ -z "$RUSTC_LLVM_MAJOR" ]]; then
    echo "ERROR: Could not determine rustc's LLVM version. Is rustc in PATH?" >&2
    exit 1
fi
echo "rustc LLVM major version: $RUSTC_LLVM_MAJOR"

# ── 2. Locate LLVM cmake package ─────────────────────────────────────────────
# Priority order:
#   a. LLVM_DIR env var (caller override)
#   b. llvm-config-<major> from PATH (apt.llvm.org installs these)
#   c. llvm-config (unversioned) if major matches
#   d. Homebrew on macOS

if [[ -n "${LLVM_DIR:-}" ]]; then
    echo "Using caller-supplied LLVM_DIR=$LLVM_DIR"
elif command -v "llvm-config-${RUSTC_LLVM_MAJOR}" &>/dev/null; then
    LLVM_CONFIG="llvm-config-${RUSTC_LLVM_MAJOR}"
    LLVM_PREFIX=$("$LLVM_CONFIG" --prefix)
    LLVM_DIR="$LLVM_PREFIX/lib/cmake/llvm"
    echo "Found llvm-config-${RUSTC_LLVM_MAJOR} → $LLVM_PREFIX"
elif command -v llvm-config &>/dev/null; then
    FOUND_MAJOR=$(llvm-config --version | cut -d. -f1)
    if [[ "$FOUND_MAJOR" == "$RUSTC_LLVM_MAJOR" ]]; then
        LLVM_PREFIX=$(llvm-config --prefix)
        LLVM_DIR="$LLVM_PREFIX/lib/cmake/llvm"
        echo "Found unversioned llvm-config ($FOUND_MAJOR) → $LLVM_PREFIX"
    else
        echo "ERROR: llvm-config reports LLVM $FOUND_MAJOR but rustc needs LLVM $RUSTC_LLVM_MAJOR." >&2
        echo "Install the matching version:" >&2
        echo "  Linux:  sudo apt-get install llvm-${RUSTC_LLVM_MAJOR}-dev" >&2
        echo "  macOS:  brew install llvm@${RUSTC_LLVM_MAJOR}" >&2
        exit 1
    fi
elif [[ "$(uname)" == "Darwin" ]]; then
    # Homebrew ships a versioned formula (llvm@N) for older stable releases and
    # the unversioned "llvm" for the current stable.  Try both.
    BREW_VERSIONED_PREFIX=$(brew --prefix "llvm@${RUSTC_LLVM_MAJOR}" 2>/dev/null || true)
    BREW_CURRENT_PREFIX=$(brew --prefix "llvm" 2>/dev/null || true)

    pick_prefix() {
        local prefix="$1"
        local cfg="$prefix/bin/llvm-config"
        [[ -x "$cfg" ]] || return 1
        local found_major=$("$cfg" --version | cut -d. -f1)
        [[ "$found_major" == "$RUSTC_LLVM_MAJOR" ]] || return 1
        echo "$prefix"
    }

    LLVM_PREFIX=$(pick_prefix "$BREW_VERSIONED_PREFIX" 2>/dev/null \
               || pick_prefix "$BREW_CURRENT_PREFIX" 2>/dev/null \
               || true)

    if [[ -z "$LLVM_PREFIX" ]]; then
        # Homebrew has the formula but the installed version is wrong — upgrade.
        BREW_STABLE_MAJOR=$(brew info llvm --json 2>/dev/null \
            | python3 -c "import sys,json; d=json.load(sys.stdin); print(d[0]['versions']['stable'].split('.')[0])" 2>/dev/null || true)
        if [[ "$BREW_STABLE_MAJOR" == "$RUSTC_LLVM_MAJOR" ]]; then
            echo "Upgrading Homebrew llvm to match rustc (LLVM ${RUSTC_LLVM_MAJOR})..."
            brew upgrade llvm || brew install llvm
            LLVM_PREFIX=$(brew --prefix llvm)
        fi
    fi

    if [[ -z "$LLVM_PREFIX" ]]; then
        echo "ERROR: LLVM ${RUSTC_LLVM_MAJOR} not found on macOS." >&2
        echo "  brew install llvm       (if Homebrew stable == ${RUSTC_LLVM_MAJOR})" >&2
        echo "  brew install llvm@${RUSTC_LLVM_MAJOR}  (if versioned formula exists)" >&2
        echo "Or set: LLVM_DIR=/usr/local/opt/llvm/lib/cmake/llvm" >&2
        exit 1
    fi

    LLVM_DIR="$LLVM_PREFIX/lib/cmake/llvm"
    echo "Found Homebrew LLVM at $LLVM_PREFIX ($(${LLVM_PREFIX}/bin/llvm-config --version))"
else
    echo "ERROR: LLVM ${RUSTC_LLVM_MAJOR} dev files not found." >&2
    echo "Install with:" >&2
    echo "  Linux:  wget https://apt.llvm.org/llvm.sh && chmod +x llvm.sh && sudo ./llvm.sh ${RUSTC_LLVM_MAJOR}" >&2
    echo "Or set LLVM_DIR=/path/to/llvm/lib/cmake/llvm" >&2
    exit 1
fi

# ── 3. Configure and build ────────────────────────────────────────────────────
mkdir -p "$BUILD_DIR"

CMAKE_BUILD_TYPE="Release"
if [[ "$BUILD_TYPE" == "--debug" ]]; then
    CMAKE_BUILD_TYPE="Debug"
fi

# When using Homebrew LLVM on macOS, the system AppleClang cannot find C++
# stdlib headers inside the Homebrew LLVM include tree.  Use Homebrew's own
# clang/clang++ for the plugin build so the toolchain is self-consistent.
# LLVM_DIR = <prefix>/lib/cmake/llvm  →  strip suffix to get prefix  →  add /bin
EXTRA_CMAKE_ARGS=()
LLVM_BIN_DIR="${LLVM_DIR%/lib/cmake/llvm}/bin"
if [[ "$(uname)" == "Darwin" && -x "$LLVM_BIN_DIR/clang++" ]]; then
    EXTRA_CMAKE_ARGS+=(
        -DCMAKE_C_COMPILER="$LLVM_BIN_DIR/clang"
        -DCMAKE_CXX_COMPILER="$LLVM_BIN_DIR/clang++"
    )
    echo "Using Homebrew clang++: $LLVM_BIN_DIR/clang++"
fi

cmake -S "$OBFUSCATOR_SRC" -B "$BUILD_DIR" \
    -DLLVM_DIR="$LLVM_DIR" \
    -DCMAKE_BUILD_TYPE="$CMAKE_BUILD_TYPE" \
    -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
    "${EXTRA_CMAKE_ARGS[@]}"

cmake --build "$BUILD_DIR" --parallel "$(nproc 2>/dev/null || sysctl -n hw.ncpu)"

# ── 4. Locate the built plugin ────────────────────────────────────────────────
if [[ "$(uname)" == "Darwin" ]]; then
    PLUGIN_EXT="dylib"
else
    PLUGIN_EXT="so"
fi

PLUGIN_PATH=$(find "$BUILD_DIR" -name "libSecureVmObfuscatorPlugin.$PLUGIN_EXT" | head -1)
if [[ -z "$PLUGIN_PATH" ]]; then
    echo "ERROR: Plugin library not found after build." >&2
    exit 1
fi

echo "$PLUGIN_PATH" > "$BUILD_DIR/plugin_path.txt"
echo ""
echo "Plugin built: $PLUGIN_PATH"
echo "Path cached:  $BUILD_DIR/plugin_path.txt"
