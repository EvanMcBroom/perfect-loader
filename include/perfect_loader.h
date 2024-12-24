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

#pragma once
#define WIN32_LEAN_AND_MEAN
#ifndef _WIN32_WINNT
    #define _WIN32_WINNT _WIN32_WINNT_VISTA
#endif
#include <Windows.h>
#include <sal.h>

// Macro defines for the Pl::LoadFlags options. Refer to the Pl::LoadFlags
// documentation for a description of what each value means.

#define PL_LOAD_FLAGS_NO_HEADER  0x01
#define PL_LOAD_FLAGS_NO_MODLIST 0x02
#define PL_LOAD_FLAGS_NO_NOTIFS  0x04
#define PL_LOAD_FLAGS_NO_THDCALL 0x08
#define PL_LOAD_FLAGS_OVRHDRS    0x10
#define PL_LOAD_FLAGS_USEHBP     0x20
#define PL_LOAD_FLAGS_USETXF     0x40

// clang-format off
/// <summary>
///     Loads the provided module bytes into the address space of the calling process.
///     The process of loading the module may cause other modules to be loaded.
/// </summary>
/// <param name='DllBase'>
///     The address to the bytes of the module to load.
/// </param>
/// <param name='DllSize'>
///     The size in bytes of the module to load.
/// </param>
/// <param name='Flags'>
///     The action to be taken when loading the module.
///     Refer to the LoadLibraryEx* documentation for a full list of accepted values.
/// </param>
/// <param name='FileName'>
///     Refer to the Pl::LoadLibrary documentation for detailed information.
/// </param>
/// <param name='PlFlags'>
///     The approach and post processing options for loading the module.
///     Refer to the Pl::LoadFlags documentation for a full list of accepted values.
/// </param>
/// <param name='ModListName'>
///     An optional name to use as the DLL name in the module list.
///     fileName will be used if nothing is specified.
///     Only valid when used with the Pl::UseTxf flag.
/// </param>
/// <returns>
///     If the function succeeds, the return value is a handle to the loaded module.
///     If the function fails, the return value is NULL. To get extended error information, call GetLastError.
/// </returns>
extern "C" HMODULE WINAPI LoadDllFromMemory(
    _In_ LPVOID DllBase,
    _In_ SIZE_T DllSize,
    _In_opt_ DWORD Flags,
    _In_opt_ LPCWSTR FileName,
    _In_opt_ DWORD PlFlags,
    _In_opt_ LPCWSTR ModListName
);
// clang-format on