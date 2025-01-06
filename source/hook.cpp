// Copyright (c) 2023 Evan McBroom
//
// This file is part of perfect-loader.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include "pl/hook.hpp"
#include <cstring>
#include <numeric>
#include <type_traits>

namespace Pl {
    void Detour::Enable(bool state) {
        if (state) {
            auto trampoline{ AssembleTrampoline(hook) };
            originalBytes.resize(trampoline.size());
            DWORD protection;
            if (VirtualProtect(target, trampoline.size(), PAGE_EXECUTE_READWRITE, &protection)) {
                std::memcpy(originalBytes.data(), target, originalBytes.size());
                std::memcpy(target, trampoline.data(), trampoline.size());
                (void)VirtualProtect(target, trampoline.size(), protection, &protection);
                applied = true;
            }
        } else {
            DWORD protection;
            if (applied && VirtualProtect(target, originalBytes.size(), PAGE_EXECUTE_READWRITE, &protection)) {
                std::memcpy(target, originalBytes.data(), originalBytes.size());
                (void)VirtualProtect(target, originalBytes.size(), protection, &protection);
                applied = false;
            }
        }
    }

    // Static member variable definitions for HbpHook
    std::array<std::pair<std::byte*, std::byte*>, 4> HbpHook::targetHookPairs{ { { nullptr, nullptr }, { nullptr, nullptr }, { nullptr, nullptr }, { nullptr, nullptr } } };
    PVOID HbpHook::vehHandle = nullptr;

    void HbpHook::Enable(bool state) {
        if (state) {
            // Check to ensure that HbpHook is not already being used to hook the address
            auto iter{ std::find_if(targetHookPairs.begin(), targetHookPairs.end(), [this](const std::pair<std::byte*, std::byte*>& targetHookPair) {
                return targetHookPair.first == Target();
            }) };
            if (iter == targetHookPairs.end()) {
                trace = std::make_unique<Trace>(target);
                if (trace->Set()) {
                    targetHookPairs[trace->DebugRegister()] = std::pair<std::byte*, std::byte*>(target, hook);
                    if (!vehHandle) {
                        vehHandle = AddVectoredExceptionHandler(TRUE, VehHandler);
                        applied = vehHandle != nullptr;
                    } else {
                        applied = true;
                    }
                }
            }
        } else {
            if (trace) {
                targetHookPairs[trace->DebugRegister()] = std::pair<std::byte*, std::byte*>(nullptr, nullptr);
                trace = nullptr;
            }
            // Check to see if no more hooks are set and the veh may be removed
            auto count{
                std::accumulate(targetHookPairs.begin(), targetHookPairs.end(), 0, [](size_t count, const std::pair<std::byte*, std::byte*>& targetHookPair) {
                    return count + (targetHookPair.first) ? 1 : 0;
                })
            };
            applied = (count == 0) ? !RemoveVectoredExceptionHandler(vehHandle) : false;
            if (!applied) {
                vehHandle = nullptr;
            }
        }
    }

    LONG NTAPI HbpHook::VehHandler(struct _EXCEPTION_POINTERS* ExceptionInfo) {
        auto exceptionRecord{ ExceptionInfo->ExceptionRecord };
        if (exceptionRecord->ExceptionCode == STATUS_SINGLE_STEP) {
            for (auto& targetHookPair : targetHookPairs) {
                if (exceptionRecord->ExceptionAddress == targetHookPair.first) {
                    auto contextRecord{ ExceptionInfo->ContextRecord };
#if defined(_M_IX86)
                    contextRecord->Eip = (DWORD)(targetHookPair.second);
#elif defined(_M_X64) and not defined(_M_ARM64EC)
                    contextRecord->Rip = (DWORD64)(targetHookPair.second);
#else
    #error Perfect-loader is only supported for x86 and x64 processors.
#endif
                    return EXCEPTION_CONTINUE_EXECUTION;
                }
            }
        }
        return EXCEPTION_CONTINUE_SEARCH;
    }

    Trace::Trace(std::byte* address, bool locally)
        : address(address) {
        auto thread{ GetCurrentThread() };
        CONTEXT context;
        context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (GetThreadContext(thread, &context)) {
            // Identify if one of the 4 available breakpoints is not already being used
            // The check is done by inspecting the local and global level set bits for each register
            for (reg = 0; reg < 4; reg++) {
                if ((context.Dr7 & (3 << (reg * 2))) == 0)
                    break;
            }
            if (reg < 4) {
                // Set the new context attributes
                auto value{ (decltype(CONTEXT::Dr0))address };
                switch (reg) {
                case 0: context.Dr0 = value; break;
                case 1: context.Dr1 = value; break;
                case 2: context.Dr2 = value; break;
                case 3: context.Dr3 = value; break;
                default: return;
                }

                // Relevant context.Dr7 bit values:
                // 0     L0   Local enable (e.g., local to processor)
                // 1     G0   Global enable
                // 2     L1
                // ...
                // 17:16 R/W0 Breakpoint condition
                // 19:18 LEN0 Breakpoint length
                // 21:20 R/W1
                // ...

                // Enable the breakpoint
                context.Dr7 |= (locally ? 1 : 2) << (reg * 2);
                // Set the condition to 'instruction execution' only
                context.Dr7 &= ~((3 << 16) << (reg * 4));
                // Set the breakpoint length to 0 as required for the 'instruction execution' only condition
                context.Dr7 &= ~((3 << 18) << (reg * 4));

                if (SetThreadContext(thread, &context)) {
                    set = true;
                }
            }
        }
    }

    Trace::~Trace() {
        if (set) {
            CONTEXT context;
            HANDLE thread = GetCurrentThread();
            context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            if (GetThreadContext(thread, &context)) {
                // Disable the breakpoint
                context.Dr7 &= ~(3 << (reg * 2));
                // Assume this succeeds because the destructor cannot raise an exception or return information on failure
                (void)SetThreadContext(thread, &context);
            }
        }
    }

    std::vector<uint8_t> AssembleTrampoline(std::byte* hook) {
        std::vector<uint8_t> trampoline;
        if constexpr (std::alignment_of<void*>::value == 8) {
            trampoline = std::vector<uint8_t>(12);
            // mov rax, 0x0000000000000000
            // push rax
            // ret
            *reinterpret_cast<uint16_t*>(&trampoline.data()[0]) = (uint16_t)0xb848;
            *reinterpret_cast<uint64_t*>(&trampoline.data()[2]) = (uint64_t)hook;
            trampoline.data()[10] = 0x50;
            trampoline.data()[11] = 0xc3;
        } else {
            trampoline = std::vector<uint8_t>(6);
            // push 0x00000000
            // ret
            trampoline.data()[0] = 0x68;
            *reinterpret_cast<uint32_t*>(&trampoline.data()[1]) = (uint32_t)hook;
            trampoline.data()[5] = 0xc3;
        }
        return trampoline;
    }
}