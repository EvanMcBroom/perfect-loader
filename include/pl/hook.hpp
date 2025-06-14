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
    /// <summary>
    /// The base class for which hook implementations are derived.
    /// </summary>
    class HookBase {
    public:
        HookBase(std::byte* target, std::byte* hook)
            : target(target), hook(hook) {
        }

        auto Applied() const {
            return applied;
        }

        virtual void Enable(bool state) = 0;

        auto Target() const {
            return target;
        }

    protected:
        bool applied{ false };
        std::byte* hook;
        std::byte* target;
    };

    /// <summary>
    /// Overwrite a target address to divert its execution to a specified hook routine.
    /// </summary>
    class Detour : public HookBase {
    public:
        Detour(std::byte* target, std::byte* hook, bool enabled = true)
            : HookBase(target, hook) {
            if (enabled) {
                Enable(true);
            }
        }
        ~Detour() {
            if (applied) {
                Enable(false);
            }
        }

        void Enable(bool state = true);

    private:
        std::vector<uint8_t> originalBytes;
    };

    /// <summary>
    /// Trace attempts to read, write, or fetch an instruction for a specified memory address.
    /// </summary>
    /// <remarks>
    /// A hardware interrupt will be generated for any access attempt that meets the specified tracing conditions.
    /// A vectored exception handler may be used to catch and handle the exception.
    ///
    /// Please refer the following reference for information on software tracing:
    ///   Intel (2022) Subsection 18.2, Debug Registers. Intel 64 and IA-32 Architectures Software Developer's Manual:
    ///   System Programming Guide, Volume 3 (3A, 3B, 3C &amp; 3D).
    /// </remarks>
    class Trace {
    public:
        Trace(std::byte* address, bool locally = true);
        ~Trace();

        auto Address() const {
            return address;
        }

        auto DebugRegister() const {
            return reg;
        }

        auto Set() const {
            return set;
        }

    private:
        std::byte* address;
        size_t reg;
        bool set{ false };
    };

    /// <summary>
    /// Set a hardware breakpoint at a target address and divert its execution to a specified hook routine.
    /// </summary>
    class HbpHook : public HookBase {
    public:
        HbpHook(std::byte* target, std::byte* hook, bool enabled = true)
            : HookBase(target, hook) {
            if (enabled) {
                Enable(true);
            }
        }
        ~HbpHook() {
            if (applied) {
                Enable(false);
            }
        }

        void Enable(bool state = true);

    private:
        static std::array<std::pair<std::byte*, std::byte*>, 4> targetHookPairs;
        std::unique_ptr<Trace> trace = nullptr;
        static PVOID vehHandle;

        static LONG NTAPI VehHandler(struct _EXCEPTION_POINTERS* ExceptionInfo);
    };

    /// <summary>
    /// A convenience class for setting a detour or hardware breakpoint based hook.
    /// </summary>
    class Hook {
    public:
        Hook(std::byte* target, std::byte* hook, bool useHbp = false, bool enabled = true)
            : useHbp(useHbp) {
            if (useHbp) {
                hbpHook = std::make_unique<HbpHook>(target, hook, enabled);
            } else {
                detour = std::make_unique<Detour>(target, hook, enabled);
            }
        }

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
