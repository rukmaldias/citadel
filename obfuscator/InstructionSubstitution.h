#pragma once
#include "llvm/IR/PassManager.h"

namespace svm {

/// Replaces arithmetic and bitwise instructions with semantically-equivalent
/// but structurally different sequences.  Makes pattern-matching on known
/// algorithms harder for static analysis tools.
///
/// Applied to the same functions as CFF (same name-based exclusions).
/// Transformations:
///   Add(a,b)  →  Sub(a, Neg(b))
///   And(a,b)  →  Xor(Xor(a, Not(b)), Not(b))
///   Or(a,b)   →  Or(And(a,b), Xor(a,b))
///   Xor(a,b)  →  Sub(Or(a,b), And(a,b))
class InstructionSubstitution
    : public llvm::PassInfoMixin<InstructionSubstitution> {
public:
    llvm::PreservedAnalyses run(llvm::Function &F,
                                llvm::FunctionAnalysisManager &AM);
    static bool isRequired() { return false; }
};

} // namespace svm
