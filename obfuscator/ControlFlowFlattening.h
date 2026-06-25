#pragma once
#include "llvm/IR/PassManager.h"

namespace svm {

/// Flattens the control flow of eligible functions by routing all branches
/// through a central switch dispatcher.  A static disassembler sees a loop
/// over a switch variable instead of the original branch structure.
///
/// Only applied to functions with >= MIN_BLOCKS basic blocks that are not
/// exception-handling functions and do not contain invoke instructions.
/// Applied probabilistically (Probability %) to avoid breaking Rust runtime
/// internals that match the size threshold.
class ControlFlowFlattening : public llvm::PassInfoMixin<ControlFlowFlattening> {
public:
    static constexpr unsigned MIN_BLOCKS = 6;

    explicit ControlFlowFlattening(unsigned Probability = 70);

    llvm::PreservedAnalyses run(llvm::Function &F,
                                llvm::FunctionAnalysisManager &AM);

    // Do not abort the pipeline if the function is opted out.
    static bool isRequired() { return false; }

private:
    unsigned Probability;

    bool shouldFlatten(llvm::Function &F) const;
    bool flatten(llvm::Function &F) const;
};

} // namespace svm
