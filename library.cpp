#include "library.h"

using namespace BinaryNinja;

extern "C"
{
    BN_DECLARE_CORE_ABI_VERSION

    BINARYNINJAPLUGIN bool CorePluginInit()
    {
        PluginCommand::Register(
            "Native Predicate Solver\\Patch Opaque Predicates (Current Function)",
            "Patch opaque predicates in current function",
            [](BinaryView* view) {
                uint64_t addr = view->GetCurrentOffset();
                auto functions = view->GetAnalysisFunctionsContainingAddress(addr);
                if (functions.empty()) {
                    LogWarn("No function at current address 0x%llx", addr);
                    return;
                }
                
                auto func = functions[0];
                auto mlil = func->GetMediumLevelIL();
                if (!mlil) {
                    LogWarn("No MLIL available for function at 0x%llx", func->GetStart());
                    return;
                }
                
                auto arch = func->GetArchitecture();
                if (!arch) {
                    LogWarn("Failed to get architecture for function");
                    return;
                }
                
                std::string funcName = func->GetSymbol() ? func->GetSymbol()->GetShortName() : "sub_" + std::to_string(func->GetStart());
                LogInfo("[+] Processing %s", funcName.c_str());
                
                int totalPatches = 0;
                int pass = 1;
                const int maxPasses = 10;
                
                while (pass <= maxPasses) {
                    int patchCount = 0;
                    size_t instructionCount = mlil->GetInstructionCount();
                    
                    for (size_t i = 0; i < instructionCount; ++i) {
                        auto instr = mlil->GetInstruction(i);
                        if (instr.operation != MLIL_IF)
                            continue;
                        
                        auto val = mlil->GetExprValue(instr.GetConditionExpr());
                        if (val.state == BNRegisterValueType::ConstantValue) {
                            if (val.value == 0) {
                                if (view->IsNeverBranchPatchAvailable(arch, instr.address)) {
                                    view->ConvertToNop(arch, instr.address);
                                    patchCount++;
                                }
                            } else {
                                if (view->IsAlwaysBranchPatchAvailable(arch, instr.address)) {
                                    view->AlwaysBranch(arch, instr.address);
                                    patchCount++;
                                }
                            }
                        }
                    }
                    
                    totalPatches += patchCount;
                    
                    if (patchCount == 0)
                        break;
                    
                    view->UpdateAnalysis();
                    pass++;
                }
                
                LogInfo("[+] Completed: %d patches applied to %s", totalPatches, funcName.c_str());
            });

        PluginCommand::Register(
            "Native Predicate Solver\\Patch Opaque Predicates (All Functions)",
            "Recursively patch opaque predicates in all functions until none remain",
            [](BinaryView* view) {
                LogInfo("[+] Starting recursive patching for entire binary");
                
                int globalPass = 1;
                int totalGlobalPatches = 0;
                
                while (true) {
                    auto functions = view->GetAnalysisFunctionList();
                    int globalPatchCount = 0;
                    size_t funcNum = 0;
                    
                    for (auto func : functions) {
                        funcNum++;
                        
                        auto mlil = func->GetMediumLevelIL();
                        if (!mlil || mlil->GetInstructionCount() == 0)
                            continue;
                        
                        auto arch = func->GetArchitecture();
                        if (!arch)
                            continue;
                        
                        int funcPatches = 0;
                        int pass = 1;
                        
                        while (pass <= 10) {
                            int patchCount = 0;
                            
                            for (size_t i = 0; i < mlil->GetInstructionCount(); ++i) {
                                auto instr = mlil->GetInstruction(i);
                                if (instr.operation != MLIL_IF)
                                    continue;
                                
                                auto val = mlil->GetExprValue(instr.GetConditionExpr());
                                if (val.state == BNRegisterValueType::ConstantValue) {
                                    if (val.value == 0) {
                                        if (view->IsNeverBranchPatchAvailable(arch, instr.address)) {
                                            view->ConvertToNop(arch, instr.address);
                                            patchCount++;
                                        }
                                    } else {
                                        if (view->IsAlwaysBranchPatchAvailable(arch, instr.address)) {
                                            view->AlwaysBranch(arch, instr.address);
                                            patchCount++;
                                        }
                                    }
                                }
                            }
                            
                            funcPatches += patchCount;
                            
                            if (patchCount == 0)
                                break;
                            
                            view->UpdateAnalysis();
                            pass++;
                        }
                        
                        if (funcPatches > 0) {
                            globalPatchCount += funcPatches;
                        }
                    }
                    
                    totalGlobalPatches += globalPatchCount;
                    LogInfo("[+] Pass %d: %d patches applied", globalPass, globalPatchCount);
                    
                    if (globalPatchCount == 0)
                        break;
                    
                    globalPass++;
                    
                    if (globalPass > 20) {
                        LogWarn("[!] Maximum passes reached");
                        break;
                    }
                    
                    view->UpdateAnalysis();
                }
                
                LogInfo("[+] Completed: %d total patches applied", totalGlobalPatches);
            });

        return true;
    }

    BINARYNINJAPLUGIN void CorePluginDependencies()
    {
    }
}