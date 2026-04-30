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
#ifndef _WIN32_WINNT
    #define _WIN32_WINNT _WIN32_WINNT_VISTA
#endif
// clang-format off
#include <windows.h>
#include <sal.h>
// clang-format on

// Macro defines for the Pl::RedirectorFlags options. Refer to the Pl::RedirectorFlags
// documentation for a description of what each value means.

#define PL_LOAD_FLAGS_USETXF 0x01
#define PL_LOAD_FLAGS_USESEC 0x02
#define PL_LOAD_FLAGS_USEHBP 0x10
#if defined(_M_AMD64) && !defined(_M_ARM64EC)
    #define PL_LOAD_FLAGS_USEPIC 0x20
#endif


// clang-format off
/// <summary>
/// Finds a usable dll path to pass to LoadLibrary to start its loading process.
/// Unless manual mapping is done, this dll will act as a "host" for the in-memory
/// module. For module doppelganging, the in-memory module will be written to the
/// dll in a transaction. For section hollowing, the in-memory module will be mapped
/// over the section for the dll. If malicious software implements a perfect loading
/// approach, the dll should be viewed as a "decoy" for the in-memory module.
///
/// For manual mapping, the following requirements are needed:
/// - The dll must not be currently loaded in your process. If it is,
///   LoadLibrary will exit early and return a handle to the already
///   loaded dll.
/// - The dll must not be in KnownDlls. If it is, LoadLibrary will exit
///   early and return a handle to the seciton in the KnownDlls directory.
///
/// For module doppelgänging, the manual mapping requirements and the following
/// additional requirements are needed:
/// - The effective thread which calls the perfect loader api must be
///   allowed to write to the file. The file's contents will only be
///   modified in memory, but it will be done in a temporary file
///   transaction which will require write access to succeed.
/// - On Windows 11 24H2, you should provide a dll as the path. On
///   prior Windows releases, any file type may be supplied (ex. a
///   plain text file).
/// 
/// For section hollowing, the manual mapping requirements and the following
/// additional requirements are needed:
/// - The dll's image should be the same size or larger than the in-memory
///   module so that the resultant section is large enough to store the map
///   of the in-memory module.
/// - The dll should not have cfg enabled. If it does, the function
///   addresses for the in-memory module will not match the portion of the
///   cfg bitmap for the hollowed section it was mapped into. If they do
///   not match, then the cfg checks in the native loader will terminate the
///   process whenever the native loader calls a function for the in-memory
///   module (ex. DllMain).
/// This function checks for both requirements.
/// </summary>
/// <param name='SearchDir'>
///     The directory to search in.
/// </param>
/// <param name='PlFlags'>
///     The intended approach for using the dll to load a module. Refer to the
///     Pl::RedirectorFlags documentation for a full list of accepted values.
/// </param>
/// <param name='DllSize'>
///     The size of the in-memory module to load. This parameter is required if
///     PlFlags includes PL_LOAD_FLAGS_USESEC.
/// </param>
/// <param name='HostDllPath'>
///     A pointer to a buffer that receives the found path.
/// </param>
/// <param name='HostDllPathSize'>
///     The size of the buffer pointed to by the DllPath parameter in bytes.
/// </param>
/// <returns>
///     If the function succeeds, the return value is the number of characters
///     stored in the buffer pointed to by DllPath, not including the terminating
///     null character.
/// 
///     If DllPath is not large enough to hold the data, the return value is the
///     buffer size, in characters, required to hold the string and its terminating
///     null character and the contents of DllPath are undefined.
/// 
///     If the function fails, the return value is zero.
/// </returns>
extern "C" __declspec(dllexport)
DWORD FindUsableHostDll(
    _In_ LPCWSTR SearchDir,
    _In_opt_ DWORD PlFlags,
    _In_opt_ SIZE_T DllSize,
    _Outptr_ LPWSTR HostDllPath,
    _In_ DWORD HostDllPathSize
);

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
///     The approach and for loading the module.
///     Refer to the Pl::RedirectorFlags documentation for a full list of accepted values.
/// </param>
/// <param name='ModListName'>
///     An optional name to use as the dll name in the module list.
///     fileName will be used if nothing is specified.
///     Only valid when used with the Pl::UseTxf flag.
/// </param>
/// <returns>
///     If the function succeeds, the return value is a handle to the loaded module.
///     If the function fails, the return value is NULL. To get extended error information, call GetLastError.
/// </returns>
extern "C" __declspec(dllexport)
HMODULE WINAPI LoadDllFromMemory(
    _In_ LPVOID DllBase,
    _In_ SIZE_T DllSize,
    _In_opt_ DWORD Flags,
    _In_opt_ LPCWSTR FileName,
    _In_opt_ DWORD PlFlags,
    _In_opt_ LPCWSTR ModListName
);
// clang-format on