#include "InstructionSubstitution.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"

#include <vector>

using namespace llvm;
using namespace svm;

// Same crypto-exclusion list as CFF — don't perturb constant-time code.
static bool shouldSubstitute(Function &F) {
    StringRef N = F.getName();
    return !N.contains("wbc")  && !N.contains("aes")  &&
           !N.contains("hmac") && !N.contains("kdf")  &&
           !N.contains("argon")&& !N.contains("chacha")&&
           !N.contains("panic")&& !N.contains("unwind")&&
           !N.contains("__rust_");
}

// Add(a, b) → Sub(a, Neg(b))
static Value *replaceAdd(BinaryOperator *BO, IRBuilder<> &B) {
    return B.CreateSub(BO->getOperand(0),
                       B.CreateNeg(BO->getOperand(1), "svm.neg"),
                       "svm.sub");
}

// And(a, b) → Xor(Xor(a, Not(b)), Not(b))  [= a & b identity]
static Value *replaceAnd(BinaryOperator *BO, IRBuilder<> &B) {
    Value *NotB = B.CreateNot(BO->getOperand(1), "svm.not");
    return B.CreateXor(B.CreateXor(BO->getOperand(0), NotB, "svm.x1"),
                       NotB, "svm.x2");
}

// Or(a, b) → Or(And(a, b), Xor(a, b))
static Value *replaceOr(BinaryOperator *BO, IRBuilder<> &B) {
    Value *A = BO->getOperand(0), *Bv = BO->getOperand(1);
    return B.CreateOr(B.CreateAnd(A, Bv, "svm.and"),
                      B.CreateXor(A, Bv, "svm.xor"),
                      "svm.or");
}

// Xor(a, b) → Sub(Or(a, b), And(a, b))
static Value *replaceXor(BinaryOperator *BO, IRBuilder<> &B) {
    Value *A = BO->getOperand(0), *Bv = BO->getOperand(1);
    return B.CreateSub(B.CreateOr (A, Bv, "svm.or"),
                       B.CreateAnd(A, Bv, "svm.and"),
                       "svm.sub");
}

PreservedAnalyses InstructionSubstitution::run(Function &F,
                                               FunctionAnalysisManager &) {
    if (!shouldSubstitute(F)) return PreservedAnalyses::all();

    std::vector<BinaryOperator *> Work;
    for (auto &BB : F)
        for (auto &I : BB)
            if (auto *BO = dyn_cast<BinaryOperator>(&I))
                switch (BO->getOpcode()) {
                case Instruction::Add:
                case Instruction::And:
                case Instruction::Or:
                case Instruction::Xor:
                    Work.push_back(BO);
                    break;
                default: break;
                }

    if (Work.empty()) return PreservedAnalyses::all();

    for (auto *BO : Work) {
        IRBuilder<> B(BO);
        Value *Rep = nullptr;
        switch (BO->getOpcode()) {
        case Instruction::Add: Rep = replaceAdd(BO, B); break;
        case Instruction::And: Rep = replaceAnd(BO, B); break;
        case Instruction::Or:  Rep = replaceOr (BO, B); break;
        case Instruction::Xor: Rep = replaceXor(BO, B); break;
        default: break;
        }
        if (Rep) {
            BO->replaceAllUsesWith(Rep);
            BO->eraseFromParent();
        }
    }

    return PreservedAnalyses::none();
}
