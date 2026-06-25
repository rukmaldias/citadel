#include "ControlFlowFlattening.h"
#include "InstructionSubstitution.h"
#include "llvm/Passes/PassBuilder.h"
// PassPlugin.h moved from llvm/Passes/ to llvm/Plugins/ in LLVM 22.
#if __has_include("llvm/Plugins/PassPlugin.h")
#  include "llvm/Plugins/PassPlugin.h"
#else
#  include "llvm/Passes/PassPlugin.h"
#endif

using namespace llvm;
using namespace svm;

static void registerCallbacks(PassBuilder &PB) {
    // ── Automatic hook: fires at the end of the optimisation pipeline ─────────
    // Placing obfuscation after all other passes means the IR is maximally
    // simplified first — CFF sees fewer redundant blocks, SUB sees fewer
    // redundant instructions.  O0 builds are skipped so debug builds are fast.
    // LLVM >= 22 added a ThinOrFullLTOPhase third argument to this callback.
    PB.registerOptimizerLastEPCallback(
        [](ModulePassManager &MPM, OptimizationLevel Level,
           ThinOrFullLTOPhase /*Phase*/) {
            if (Level == OptimizationLevel::O0) return;
            FunctionPassManager FPM;
            FPM.addPass(InstructionSubstitution());
            // CFF after SUB: flattened switch handles substituted instructions.
            FPM.addPass(ControlFlowFlattening(/*Probability=*/70));
            MPM.addPass(createModuleToFunctionPassAdaptor(std::move(FPM)));
        });

    // ── Explicit pipeline names (for opt -passes=... testing) ─────────────────
    PB.registerPipelineParsingCallback(
        [](StringRef Name, FunctionPassManager &FPM,
           ArrayRef<PassBuilder::PipelineElement>) -> bool {
            if (Name == "svm-sub") { FPM.addPass(InstructionSubstitution());       return true; }
            if (Name == "svm-cff") { FPM.addPass(ControlFlowFlattening(/*p=*/100)); return true; }
            return false;
        });
}

// New-pass-manager plugin entry point.  Loaded by:
//   rustc  -C llvm-args=--load-pass-plugin=/path/to/libSecureVmObfuscatorPlugin.so
//   opt    --load-pass-plugin=/path/...  --passes=svm-cff,...
extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
    return {LLVM_PLUGIN_API_VERSION, "SecureVmObfuscator",
            LLVM_VERSION_STRING, registerCallbacks};
}
