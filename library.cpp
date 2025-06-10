#include "library.h"
#include <thread>

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

                Ref<BinaryView> viewRef = view;
                Ref<Function> funcRef = func;
                Ref<Architecture> archRef = arch;

                std::thread([viewRef, funcRef, archRef, funcName]() {
                    Ref<BackgroundTask> task = new BackgroundTask("Patching opaque predicates", true);
                    task->SetProgressText("Processing " + funcName);

                    int totalPatches = 0;
                    int pass = 1;
                    const int maxPasses = 10;

                    while (pass <= maxPasses) {
                        if (task->IsCancelled()) {
                            LogWarn("Operation cancelled by user");
                            break;
                        }

                        task->SetProgressText("Pass " + std::to_string(pass) + "/" + std::to_string(maxPasses) + " for " + funcName);

                        auto mlil = funcRef->GetMediumLevelIL();
                        if (!mlil) {
                            break;
                        }

                        int patchCount = 0;
                        size_t instructionCount = mlil->GetInstructionCount();

                        for (size_t i = 0; i < instructionCount; ++i) {
                            auto instr = mlil->GetInstruction(i);
                            if (instr.operation != MLIL_IF)
                                continue;

                            auto val = mlil->GetExprValue(instr.GetConditionExpr());
                            if (val.state == BNRegisterValueType::ConstantValue) {
                                if (val.value == 0) {
                                    if (viewRef->IsNeverBranchPatchAvailable(archRef, instr.address)) {
                                        viewRef->ConvertToNop(archRef, instr.address);
                                        patchCount++;
                                    }
                                }
                                else {
                                    if (viewRef->IsAlwaysBranchPatchAvailable(archRef, instr.address)) {
                                        viewRef->AlwaysBranch(archRef, instr.address);
                                        patchCount++;
                                    }
                                }
                            }
                        }

                        totalPatches += patchCount;

                        if (patchCount == 0)
                            break;

                        viewRef->UpdateAnalysis();
                        pass++;
                    }

                    task->Finish();
                    LogInfo("[+] Completed: %d patches applied to %s", totalPatches, funcName.c_str());
                    }).detach();
            });

        PluginCommand::Register(
            "Native Predicate Solver\\Patch Opaque Predicates (All Functions)",
            "Recursively patch opaque predicates in all functions until none remain",
            [](BinaryView* view) {
                Ref<BinaryView> viewRef = view;

                std::thread([viewRef]() {
                    Ref<BackgroundTask> task = new BackgroundTask("Patching all opaque predicates", true);
                    task->SetProgressText("Starting recursive patching for entire binary");

                    int globalPass = 1;
                    int totalGlobalPatches = 0;

                    while (true) {
                        if (task->IsCancelled()) {
                            LogWarn("Operation cancelled by user");
                            break;
                        }

                        auto functions = viewRef->GetAnalysisFunctionList();
                        int globalPatchCount = 0;
                        size_t funcNum = 0;
                        size_t totalFuncs = functions.size();

                        task->SetProgressText("Global pass " + std::to_string(globalPass) + " - Analyzing " + std::to_string(totalFuncs) + " functions");

                        for (auto func : functions) {
                            if (task->IsCancelled()) {
                                LogWarn("Operation cancelled by user");
                                break;
                            }

                            funcNum++;

                            if (funcNum % 10 == 0 || funcNum == totalFuncs) {
                                task->SetProgressText("Pass " + std::to_string(globalPass) + " - Processing function " +
                                    std::to_string(funcNum) + "/" + std::to_string(totalFuncs));
                            }

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
                                            if (viewRef->IsNeverBranchPatchAvailable(arch, instr.address)) {
                                                viewRef->ConvertToNop(arch, instr.address);
                                                patchCount++;
                                            }
                                        }
                                        else {
                                            if (viewRef->IsAlwaysBranchPatchAvailable(arch, instr.address)) {
                                                viewRef->AlwaysBranch(arch, instr.address);
                                                patchCount++;
                                            }
                                        }
                                    }
                                }

                                funcPatches += patchCount;

                                if (patchCount == 0)
                                    break;

                                viewRef->UpdateAnalysis();
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

                        task->SetProgressText("Updating analysis after pass " + std::to_string(globalPass - 1));
                        viewRef->UpdateAnalysis();
                    }

                    task->Finish();
                    LogInfo("[+] Completed: %d total patches applied", totalGlobalPatches);
                    }).detach();
            });

        return true;
    }

    BINARYNINJAPLUGIN void CorePluginDependencies()
    {
    }
}