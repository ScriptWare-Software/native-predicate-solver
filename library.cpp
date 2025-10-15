#include "library.h"
#include <thread>
#include <vector>
#include <atomic>
#include <mutex>
#include <chrono>
#include <queue>
#include <condition_variable>
using namespace BinaryNinja;

extern "C"
{
    BN_DECLARE_CORE_ABI_VERSION

        BINARYNINJAPLUGIN bool CorePluginInit()
    {
        auto settings = Settings::Instance();
        settings->RegisterGroup("nativePredicateSolver", "Native Predicate Solver");
        settings->RegisterSetting("nativePredicateSolver.maxPassesPerFunction",
            R"~({
                            "title": "Max passes per function",
                            "type": "number",
                            "default": 10,
                            "description": "Maximum number of passes to run when patching opaque predicates in a single function."
                            })~");
        settings->RegisterSetting("nativePredicateSolver.maxGlobalPasses",
            R"~({
                            "title": "Max global passes",
                            "type": "number",
                            "default": 20,
                            "description": "Maximum number of global passes when patching all functions in the binary."
                            })~");
        settings->RegisterSetting("nativePredicateSolver.threadCount",
            R"~({
                            "title": "Thread count",
                            "type": "number",
                            "default": 8,
                            "description": "Number of threads to use when patching all functions. Recommended: number of CPU cores."
                            })~");

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

                std::thread([viewRef, funcRef, archRef, funcName]() mutable {
                    Ref<BackgroundTask> task = new BackgroundTask("Patching opaque predicates", true);
                    task->SetProgressText("Processing " + funcName);
                    
                    auto startTime = std::chrono::high_resolution_clock::now();

                    int totalPatches = 0;
                    int pass = 1;
                    auto settings = Settings::Instance();
                    const int maxPasses = static_cast<int>(settings->Get<int64_t>("nativePredicateSolver.maxPassesPerFunction", viewRef));

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
                            if (i % 100 == 0 && task->IsCancelled()) {
                                break;
                            }
                            
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
                        
                        auto updatedFunctions = viewRef->GetAnalysisFunctionsContainingAddress(funcRef->GetStart());
                        if (!updatedFunctions.empty()) {
                            funcRef = updatedFunctions[0];
                        }
                        
                        pass++;
                    }

                    task->Finish();
                    
                    auto endTime = std::chrono::high_resolution_clock::now();
                    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);
                    LogInfo("[+] Completed: %d patches applied to %s in %lld ms", totalPatches, funcName.c_str(), duration.count());
                    }).detach();
            });

        struct PatchInfo {
            Ref<Architecture> arch;
            uint64_t address;
            bool alwaysBranch;
        };

        auto processFunctionBatch = [](Ref<BinaryView> viewRef, 
                                       const std::vector<Ref<Function>>& funcBatch,
                                       int maxPassesPerFunction,
                                       std::atomic<int>& patchCount,
                                       std::atomic<bool>& shouldCancel,
                                       std::mutex& updateMutex,
                                       std::atomic<size_t>& processedFunctions) {
            int localPatchCount = 0;
            
            for (auto func : funcBatch) {
                if (shouldCancel.load())
                    break;
                    
                auto mlil = func->GetMediumLevelIL();
                if (!mlil || mlil->GetInstructionCount() == 0) {
                    processedFunctions.fetch_add(1);
                    continue;
                }
                    
                auto arch = func->GetArchitecture();
                if (!arch) {
                    processedFunctions.fetch_add(1);
                    continue;
                }
                
                size_t instrCount = mlil->GetInstructionCount();
                //if (instrCount > 10000) {
                //    std::string funcName = func->GetSymbol() ? func->GetSymbol()->GetShortName() : "sub_" + std::to_string(func->GetStart());
                //    LogInfo("Processing large function %s with %zu instructions", funcName.c_str(), instrCount);
                //}
                    
                int funcPatches = 0;
                int pass = 1;
                
                while (pass <= maxPassesPerFunction) {
                    std::vector<PatchInfo> pendingPatches;
                    
                    for (size_t i = 0; i < mlil->GetInstructionCount(); ++i) {
                        if (i % 100 == 0 && shouldCancel.load()) {
                            break;
                        }
                        
                        auto instr = mlil->GetInstruction(i);
                        if (instr.operation != MLIL_IF)
                            continue;
                            
                        auto val = mlil->GetExprValue(instr.GetConditionExpr());
                        if (val.state == BNRegisterValueType::ConstantValue) {
                            if (val.value == 0) {
                                if (viewRef->IsNeverBranchPatchAvailable(arch, instr.address)) {
                                    pendingPatches.push_back({arch, instr.address, false});
                                }
                            }
                            else {
                                if (viewRef->IsAlwaysBranchPatchAvailable(arch, instr.address)) {
                                    pendingPatches.push_back({arch, instr.address, true});
                                }
                            }
                        }
                    }
                    
                    if (shouldCancel.load()) {
                        break;
                    }
                    
                    if (pendingPatches.empty())
                        break;
                    
                    {
                        std::lock_guard<std::mutex> lock(updateMutex);
                        for (const auto& patch : pendingPatches) {
                            if (patch.alwaysBranch) {
                                viewRef->AlwaysBranch(patch.arch, patch.address);
                            } else {
                                viewRef->ConvertToNop(patch.arch, patch.address);
                            }
                        }
                        viewRef->UpdateAnalysis();
                    }
                    
                    funcPatches += pendingPatches.size();
                    pass++;
                }
                
                localPatchCount += funcPatches;
                processedFunctions.fetch_add(1);
            }
            
            patchCount.fetch_add(localPatchCount);
        };

        PluginCommand::Register(
            "Native Predicate Solver\\Patch Opaque Predicates (All Functions)",
            "Recursively patch opaque predicates in all functions until none remain",
            [processFunctionBatch](BinaryView* view) {
                Ref<BinaryView> viewRef = view;

                std::thread([viewRef, processFunctionBatch]() {
                    Ref<BackgroundTask> task = new BackgroundTask("Patching all opaque predicates", true);
                    task->SetProgressText("Starting recursive patching for entire binary");
                    
                    auto startTime = std::chrono::high_resolution_clock::now();

                    auto settings = Settings::Instance();
                    const int maxGlobalPasses = static_cast<int>(settings->Get<int64_t>("nativePredicateSolver.maxGlobalPasses", viewRef));
                    const int maxPassesPerFunction = static_cast<int>(settings->Get<int64_t>("nativePredicateSolver.maxPassesPerFunction", viewRef));
                    int threadCount = static_cast<int>(settings->Get<int64_t>("nativePredicateSolver.threadCount", viewRef));
                    if (threadCount < 1) threadCount = 1;
                    
                    int globalPass = 1;
                    int totalGlobalPatches = 0;
                    
                    while (true) {
                        if (task->IsCancelled()) {
                            LogWarn("Operation cancelled by user");
                            break;
                        }
                        
                        auto functions = viewRef->GetAnalysisFunctionList();
                        size_t totalFuncs = functions.size();
                        
                        if (totalFuncs == 0) {
                            LogInfo("No functions to process");
                            break;
                        }
                        
                        task->SetProgressText("Global pass " + std::to_string(globalPass) + " - Analyzing " + std::to_string(totalFuncs) + " functions with " + std::to_string(threadCount) + " threads");
                        
                        std::atomic<int> globalPatchCount(0);
                        std::atomic<bool> shouldCancel(false);
                        std::atomic<size_t> processedFunctions(0);
                        std::mutex updateMutex;
                        
                        std::queue<Ref<Function>> workQueue;
                        std::mutex queueMutex;
                        std::condition_variable cv;
                        std::atomic<bool> workDone(false);
                        
                        for (auto& func : functions) {
                            workQueue.push(func);
                        }
                        
                        auto worker = [&]() {
                            while (true) {
                                std::vector<Ref<Function>> localBatch;
                                
                                {
                                    std::unique_lock<std::mutex> lock(queueMutex);
                                    
                                    cv.wait(lock, [&] { return !workQueue.empty() || workDone.load() || shouldCancel.load(); });
                                    
                                    if ((workDone.load() && workQueue.empty()) || shouldCancel.load())
                                        break;
                                    
                                    size_t remaining = workQueue.size();
                                    size_t batchSize = 1;
                                    if (remaining > 100) {
                                        batchSize = 5;
                                    } else if (remaining > 50) {
                                        batchSize = 3;
                                    } else if (remaining > 20) {
                                        batchSize = 2;
                                    }
                                    
                                    for (size_t i = 0; i < batchSize && !workQueue.empty(); ++i) {
                                        localBatch.push_back(workQueue.front());
                                        workQueue.pop();
                                    }
                                }
                                
                                if (!localBatch.empty()) {
                                    processFunctionBatch(viewRef, localBatch, maxPassesPerFunction,
                                                       globalPatchCount, shouldCancel, updateMutex, processedFunctions);
                                }
                            }
                        };
                        
                        std::vector<std::thread> threads;
                        for (int i = 0; i < threadCount; ++i) {
                            threads.emplace_back(worker);
                        }
                        
                        size_t lastProcessed = 0;
                        bool cancelLogged = false;
                        while (processedFunctions.load() < totalFuncs) {
                            if (task->IsCancelled()) {
                                shouldCancel.store(true);
                                if (!cancelLogged) {
                                    LogWarn("Cancelling operation...");
                                    cancelLogged = true;
                                }
                            }
                            
                            size_t currentProcessed = processedFunctions.load();
                            if (currentProcessed != lastProcessed) {
                                lastProcessed = currentProcessed;
                                int percentage = (currentProcessed * 100) / totalFuncs;
                                task->SetProgressText("Global pass " + std::to_string(globalPass) + 
                                                    " - Analyzing " + std::to_string(totalFuncs) + 
                                                    " functions with " + std::to_string(threadCount) + 
                                                    " threads (" + std::to_string(percentage) + "%)");
                            }
                            
                            std::this_thread::sleep_for(std::chrono::milliseconds(100));
                        }
                        
                        {
                            std::lock_guard<std::mutex> lock(queueMutex);
                            workDone.store(true);
                        }
                        cv.notify_all();
                        
                        for (auto& t : threads) {
                            if (t.joinable())
                                t.join();
                        }
                        
                        int patchesThisPass = globalPatchCount.load();
                        totalGlobalPatches += patchesThisPass;
                        LogInfo("[+] Pass %d: %d patches applied", globalPass, patchesThisPass);
                        
                        if (patchesThisPass == 0)
                            break;
                            
                        globalPass++;
                        
                        if (globalPass > maxGlobalPasses) {
                            LogWarn("[!] Maximum passes reached");
                            break;
                        }
                        
                        task->SetProgressText("Updating analysis after pass " + std::to_string(globalPass - 1));
                        viewRef->UpdateAnalysis();
                    }
                    
                    task->Finish();
                    
                    auto endTime = std::chrono::high_resolution_clock::now();
                    auto duration = std::chrono::duration_cast<std::chrono::seconds>(endTime - startTime);
                    LogInfo("[+] Completed: %d total patches applied in %lld seconds", totalGlobalPatches, duration.count());
                    }).detach();
            });

        return true;
    }

    BINARYNINJAPLUGIN void CorePluginDependencies()
    {
    }
}