//
// Created by root on 8/22/2024.
//

#ifndef ALIASACCESS_H
#define ALIASACCESS_H
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/PassManager.h"

namespace llvm {
class AliasAccess : PassInfoMixin<AliasAccess> {
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &AM);
  Function *buildGetterFunction(Module &M);
  void process(Function &F, Function *Getter);
  static bool isRequired() { return true; }
};
}
#endif //ALIASACCESS_H
