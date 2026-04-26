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
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <string>
#include <utility>

namespace Pl {
    /// <summary>
    /// Resolves a procedure address from an already loaded module.
    /// </summary>
    /// <typeparam name='Function'>The function signature type to cast the resolved export to.</typeparam>
    /// <param name='library'>The loaded module handle that exports the target procedure.</param>
    /// <param name='procName'>The exported procedure name.</param>
    /// <returns>The typed function pointer, or <c>nullptr</c> if resolution fails.</returns>
    template<typename Function>
    inline auto LazyLoad(HMODULE library, const std::string& procName) {
        return (library) ? reinterpret_cast<Function*>(GetProcAddress(library, procName.data())) : nullptr;
    }

    /// <summary>
    /// Loads a module by name and resolves a procedure address from it.
    /// </summary>
    /// <typeparam name='Function'>The function signature type to cast the resolved export to.</typeparam>
    /// <param name='libraryName'>The module name (for example, <c>L"ntdll.dll"</c>).</param>
    /// <param name='procName'>The exported procedure name.</param>
    /// <returns>A pair containing the module handle and resolved function pointer (or <c>nullptr</c>).</returns>
    template<typename Function>
    [[nodiscard]] inline std::pair<HMODULE, Function*> LazyLoad(const std::wstring& libraryName, const std::string& procName) {
        auto library{ LoadLibraryW(libraryName.data()) };
        return { library, (library) ? reinterpret_cast<Function*>(GetProcAddress(library, procName.data())) : nullptr };
    }
}

#define PL_LAZY_LOAD_NATIVE_PROC(PROC) \
    auto Lazy##PROC{ Pl::LazyLoad<decltype(PROC)>(GetModuleHandleW(L"ntdll.dll"), #PROC) };

#define PL_LAZY_LOAD_LIBRARY_AND_PROC(LIBRARY, PROC) \
    HMODULE Lazy##LIBRARY;                           \
    decltype(PROC)* Lazy##PROC;                      \
    std::tie(Lazy##LIBRARY, Lazy##PROC) = Pl::LazyLoad<decltype(PROC)>(_CRT_WIDE(_CRT_STRINGIZE(LIBRARY##.dll)), #PROC);

#define PL_LAZY_LOAD_PROC(LIBRARY, PROC) \
    auto Lazy##PROC{ Pl::LazyLoad<decltype(PROC)>(LIBRARY, #PROC) };