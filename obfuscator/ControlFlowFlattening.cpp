#include "ControlFlowFlattening.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/Local.h"

#include <map>
#include <mutex>
#include <random>
#include <vector>

using namespace llvm;
using namespace svm;

ControlFlowFlattening::ControlFlowFlattening(unsigned Prob) : Probability(Prob) {}

bool ControlFlowFlattening::shouldFlatten(Function &F) const {
    if (F.isDeclaration() || F.empty()) return false;
    // Too few blocks — nothing meaningful to flatten.
    if (F.size() < MIN_BLOCKS) return false;
    // Exception-handling functions: landing pads, cleanup pads, etc.
    if (F.hasPersonalityFn()) return false;
    for (auto &BB : F) {
        if (BB.isEHPad()) return false;
        // invoke generates unwind edges that CFF cannot reroute through a switch.
        if (isa<InvokeInst>(BB.getTerminator())) return false;
    }
    // Skip Rust panic/unwind glue by name substring.
    StringRef Name = F.getName();
    if (Name.contains("panic") || Name.contains("unwind") ||
        Name.contains("rust_begin_unwind") || Name.contains("__rust_"))
        return false;
    // Skip constant-time crypto code — SUB/CFF can break timing properties.
    if (Name.contains("wbc") || Name.contains("aes") ||
        Name.contains("hmac") || Name.contains("kdf") ||
        Name.contains("argon") || Name.contains("chacha"))
        return false;

    // Probabilistic gate so a minority of borderline functions are left clear.
    static std::mt19937 RNG{std::random_device{}()};
    static std::mutex   RNG_mu;
    std::lock_guard<std::mutex> lk(RNG_mu);
    return (RNG() % 100) < Probability;
}

bool ControlFlowFlattening::flatten(Function &F) const {
    LLVMContext &Ctx = F.getContext();
    // Use IntegerType* so ConstantInt::get() returns ConstantInt* (not Constant*),
    // required by SwitchInst::addCase() in LLVM >= 22.
    IntegerType *I32Ty = IntegerType::get(Ctx, 32);

    // ── Step 0: Demote SSA to memory form ────────────────────────────────────
    // After CFF, basic blocks are no longer dominance-ordered; SSA cross-block
    // uses would violate the dominator property and crash the verifier.
    // Demoting PHI nodes and cross-block register definitions to alloca/load/
    // store makes the IR valid for any block ordering.
    BasicBlock *Entry = &F.getEntryBlock();

    // 0a. Demote PHI nodes — they encode predecessor-specific values.
    {
        std::vector<PHINode *> Phis;
        for (auto &BB : F)
            for (auto &I : BB)
                if (auto *P = dyn_cast<PHINode>(&I))
                    Phis.push_back(P);
        for (auto *P : Phis)
            DemotePHIToStack(P);
    }

    // 0b. Demote any remaining instruction whose value crosses a block boundary.
    {
        std::vector<Instruction *> ToDemote;
        for (auto &BB : F) {
            for (auto &I : BB) {
                if (I.isTerminator() || isa<AllocaInst>(I)) continue;
                for (auto *U : I.users()) {
                    auto *UI = dyn_cast<Instruction>(U);
                    if (UI && UI->getParent() != &BB) {
                        ToDemote.push_back(&I);
                        break;
                    }
                }
            }
        }
        for (auto *I : ToDemote)
            DemoteRegToStack(*I);
    }

    // ── Collect non-entry blocks ──────────────────────────────────────────────
    std::vector<BasicBlock *> Blocks;
    for (auto &BB : F)
        if (&BB != Entry)
            Blocks.push_back(&BB);

    if (Blocks.empty()) return false;

    // Assign unique integer IDs.
    std::map<BasicBlock *, uint32_t> ID;
    for (unsigned i = 0; i < Blocks.size(); ++i)
        ID[Blocks[i]] = i + 1; // 0 is reserved for "go to first block"

    // ── Split entry after all allocas ─────────────────────────────────────────
    // The pre-alloca region remains in Entry; everything else moves to a new
    // "orig_entry" block that becomes block 0 in the dispatch table.
    BasicBlock::iterator SplitPt = Entry->begin();
    while (SplitPt != Entry->end() && isa<AllocaInst>(*SplitPt))
        ++SplitPt;

    BasicBlock *OrigEntry = Entry->splitBasicBlock(SplitPt, "svm.blk0");
    ID[OrigEntry] = 0;
    Blocks.insert(Blocks.begin(), OrigEntry);

    // ── Allocate and initialise the switch variable ───────────────────────────
    // Insert at the end of Entry's alloca sequence.
    Instruction *InsertBefore = Entry->getTerminator();
    IRBuilder<> AllocaB(InsertBefore);
    AllocaInst *SwitchVar = AllocaB.CreateAlloca(I32Ty, nullptr, "svm.state");
    // Entry always falls through to the dispatcher; set state = 0 (OrigEntry).
    AllocaB.CreateStore(ConstantInt::get(I32Ty, 0), SwitchVar);
    // Remove the unconditional branch splitBasicBlock inserted (we'll replace
    // Entry's terminator with a branch to the dispatch block we create next).
    Entry->getTerminator()->eraseFromParent();

    // ── Build the dispatch basic block ────────────────────────────────────────
    BasicBlock *DispatchBB = BasicBlock::Create(Ctx, "svm.dispatch", &F, OrigEntry);
    // Insert an unconditional branch at the end of Entry using the BasicBlock*
    // overload of InsertPosition (not deprecated, unlike Instruction*).
    BranchInst::Create(DispatchBB, Entry);

    IRBuilder<> DispB(DispatchBB);
    Value *State = DispB.CreateLoad(I32Ty, SwitchVar, "svm.sv");

    BasicBlock *DefaultBB = BasicBlock::Create(Ctx, "svm.default", &F);
    new UnreachableInst(Ctx, DefaultBB);

    SwitchInst *SW = DispB.CreateSwitch(State, DefaultBB, Blocks.size());
    for (auto *BB : Blocks)
        SW->addCase(ConstantInt::get(I32Ty, ID[BB]), BB);

    // ── Redirect each block's outgoing branches through the dispatcher ─────────
    for (auto *BB : Blocks) {
        Instruction *Term = BB->getTerminator();
        IRBuilder<> B(Term);

        if (auto *BI = dyn_cast<BranchInst>(Term)) {
            if (BI->isUnconditional()) {
                BasicBlock *Succ = BI->getSuccessor(0);
                auto It = ID.find(Succ);
                if (It != ID.end()) {
                    B.CreateStore(ConstantInt::get(I32Ty, It->second), SwitchVar);
                    // Use iterator overload — Instruction* is deprecated in LLVM 22.
                    BranchInst::Create(DispatchBB, Term->getIterator());
                    Term->eraseFromParent();
                }
            } else {
                BasicBlock *T = BI->getSuccessor(0);
                BasicBlock *Fl = BI->getSuccessor(1);
                auto TIt = ID.find(T), FIt = ID.find(Fl);
                if (TIt != ID.end() && FIt != ID.end()) {
                    Value *Next = B.CreateSelect(
                        BI->getCondition(),
                        ConstantInt::get(I32Ty, TIt->second),
                        ConstantInt::get(I32Ty, FIt->second),
                        "svm.next");
                    B.CreateStore(Next, SwitchVar);
                    BranchInst::Create(DispatchBB, Term->getIterator());
                    Term->eraseFromParent();
                }
            }
        }
        // ret / unreachable / switch terminators stay as-is; they already exit
        // the function or are the dispatch switch itself.
    }

    return true;
}

PreservedAnalyses ControlFlowFlattening::run(Function &F,
                                             FunctionAnalysisManager &) {
    if (!shouldFlatten(F)) return PreservedAnalyses::all();
    if (!flatten(F))       return PreservedAnalyses::all();
    return PreservedAnalyses::none();
}
