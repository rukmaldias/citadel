cmake_minimum_required(VERSION 3.20)
project(SecureVmObfuscator LANGUAGES C CXX)

# Find the LLVM that rustc bundles.  The build script passes:
#   -DLLVM_DIR=<path-to-llvm-cmake>
# Use `scripts/build_obfuscator.sh` which derives the path automatically.
find_package(LLVM REQUIRED CONFIG)

message(STATUS "Found LLVM ${LLVM_VERSION} at ${LLVM_DIR}")

if(${LLVM_VERSION_MAJOR} LESS 18)
  message(FATAL_ERROR
    "LLVM ${LLVM_VERSION_MAJOR} found; rustc LLVM (>= 18) required. "
    "Run scripts/build_obfuscator.sh to set LLVM_DIR correctly.")
endif()

add_definitions(${LLVM_DEFINITIONS})
include_directories(${LLVM_INCLUDE_DIRS})

add_library(SecureVmObfuscatorPlugin SHARED
  ObfuscatorPlugin.cpp
  ControlFlowFlattening.cpp
  InstructionSubstitution.cpp
)

target_compile_features(SecureVmObfuscatorPlugin PRIVATE cxx_std_17)

# Plugins must NOT link against LLVM static libs — they share the host
# process's LLVM at runtime.  Linking would cause duplicate-symbol crashes.
target_link_libraries(SecureVmObfuscatorPlugin PRIVATE)

set_target_properties(SecureVmObfuscatorPlugin PROPERTIES
  OUTPUT_NAME "SecureVmObfuscatorPlugin"
)

# On macOS the linker rejects undefined symbols in dylibs by default.
# LLVM pass plugins intentionally leave LLVM symbols undefined — they are
# resolved at dlopen() time from the host process (rustc).
if(APPLE)
  target_link_options(SecureVmObfuscatorPlugin PRIVATE -undefined dynamic_lookup)
endif()
