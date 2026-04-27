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
#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

namespace Pl {
    class HookBase {
    public:
        /// <summary>
        /// Initializes a hook descriptor with a target and hook addresses.
        /// </summary>
        /// <param name='target'>The function address to intercept.</param>
        /// <param name='hook'>The function address to route execution to.</param>
        HookBase(std::byte* target, std::byte* hook)
            : target(target), hook(hook) {
        }

        /// <summary>Gets whether the hook is currently active.</summary>
        auto Applied() const {
            return applied;
        }

        /// <summary>Enables or disables the hook.</summary>
        /// <param name='state'><c>true</c> to enable; <c>false</c> to disable.</param>
        virtual void Enable(bool state) = 0;

        /// <summary>Gets the hook target address.</summary>
        auto Target() const {
            return target;
        }

    protected:
        bool applied{ false };
        std::byte* hook;
        std::byte* target;
    };

    class Detour : public HookBase {
    public:
        /// <summary>
        /// Creates a detour hook and optionally enables it immediately.
        /// A detour hook will overwrite the target address with code to divert execution to the hook routine.
        /// </summary>
        /// <param name='target'>The function address to intercept.</param>
        /// <param name='hook'>The function address to route execution to.</param>
        /// <param name='enabled'>Whether to enable the detour during construction.</param>
        Detour(std::byte* target, std::byte* hook, bool enabled = true)
            : HookBase(target, hook) {
            if (enabled) {
                Enable(true);
            }
        }
        /// <summary>
        /// Disables the detour if it is still active.
        /// </summary>
        ~Detour() {
            if (applied) {
                Enable(false);
            }
        }

        /// <summary>Enables or disables the detour patch.</summary>
        /// <param name='state'><c>true</c> to enable; <c>false</c> to disable.</param>
        void Enable(bool state = true);

    private:
        std::vector<uint8_t> originalBytes;
    };

    class Trace {
    public:
        /// <summary>
        /// Attempts to place a hardware execution breakpoint (e.g. a "trace") on an address.
        /// The trace throws an exception on attempts to read, write, or fetch an instruction for the target address.
        /// </summary>
        /// <param name='address'>The instruction address to trace.</param>
        /// <param name='locally'>Whether the breakpoint should be local instead of global.</param>
        /// <remarks>
        /// A hardware interrupt will be generated for any access attempt that meets the specified tracing conditions.
        /// A vectored exception handler may be used to catch and handle the exception.
        ///
        /// Please refer the following reference for information on software tracing:
        ///   Intel (2022) Subsection 18.2, Debug Registers. Intel 64 and IA-32 Architectures Software Developer's Manual:
        ///   System Programming Guide, Volume 3 (3A, 3B, 3C &amp; 3D).
        /// </remarks>
        Trace(std::byte* address, bool locally = true);
        /// <summary>Clears the hardware breakpoint if one was configured.</summary>
        ~Trace();

        /// <summary>Gets the traced address.</summary>
        auto Address() const {
            return address;
        }

        /// <summary>Gets the debug-register index used by this trace.</summary>
        auto DebugRegister() const {
            return reg;
        }

        /// <summary>Gets whether the trace was successfully configured.</summary>
        auto Set() const {
            return set;
        }

    private:
        std::byte* address;
        size_t reg{ 0 };
        bool set{ false };
    };
    
    class HbpHook : public HookBase {
    public:
        /// <summary>
        /// Creates a and optionally enables it immediately.
        /// The hardware-breakpoint hook will divert execution attempts at a target address to the specified hook routine.
        /// </summary>
        /// <param name='target'>The function address to intercept.</param>
        /// <param name='hook'>The function address to route execution to.</param>
        /// <param name='enabled'>Whether to enable the hook during construction.</param>
        HbpHook(std::byte* target, std::byte* hook, bool enabled = true)
            : HookBase(target, hook) {
            if (enabled) {
                Enable(true);
            }
        }
        /// <summary>Disables the hook if it is still active.</summary>
        ~HbpHook() {
            if (applied) {
                Enable(false);
            }
        }

        /// <summary>Enables or disables the hardware-breakpoint hook.</summary>
        /// <param name='state'><c>true</c> to enable; <c>false</c> to disable.</param>
        void Enable(bool state = true);

    private:
        static std::array<std::pair<std::byte*, std::byte*>, 4> targetHookPairs;
        std::unique_ptr<Trace> trace = nullptr;
        static PVOID vehHandle;

        static LONG NTAPI VehHandler(struct _EXCEPTION_POINTERS* ExceptionInfo);
    };

    class Hook {
    public:
        /// <summary>
        /// Creates either a detour or hardware-breakpoint hook wrapper.
        /// </summary>
        /// <param name='target'>The function address to intercept.</param>
        /// <param name='hook'>The function address to route execution to.</param>
        /// <param name='useHbp'>When <c>true</c>, use <see cref="HbpHook"/>; otherwise use <see cref="Detour"/>.</param>
        /// <param name='enabled'>Whether to enable the selected hook during construction.</param>
        Hook(std::byte* target, std::byte* hook, bool useHbp = false, bool enabled = true)
            : useHbp(useHbp) {
            if (useHbp) {
                hbpHook = std::make_unique<HbpHook>(target, hook, enabled);
            } else {
                detour = std::make_unique<Detour>(target, hook, enabled);
            }
        }

        /// <summary>Enables or disables the wrapped hook implementation.</summary>
        /// <param name='state'><c>true</c> to enable; <c>false</c> to disable.</param>
        void Enable(bool state = true) {
            (useHbp) ? hbpHook->Enable(state) : detour->Enable(state);
        }

    private:
        std::unique_ptr<Detour> detour;
        std::unique_ptr<HbpHook> hbpHook;
        bool useHbp;
    };

    /// <summary>
    /// Assemble opcodes for the current process's architecture that may be used to divert execution to a specified address.
    /// </summary>
    /// <param name='hook'>The address that execution should be diverted to.</param>
    /// <returns>The opcodes that may be used to divert execution.</returns>
    /// <seealso cref="Trace"/>
    std::vector<uint8_t> AssembleTrampoline(std::byte* hook);
}
