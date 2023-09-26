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

#include "pl/hook.hpp"
#include "pl/lazy.hpp"
#include "pl/mmap.hpp"
#include "pl/pe.hpp"
#include "pl/types.hpp"
#include <memory>
#include <mutex>
#include <vector>

// Although this macro does cause a side effect when the header is included
// we ignore the side effect because people should not be using TCHARs anymore
#undef LoadLibrary

namespace Pl {
    enum LoadFlags {
        NoFlags = 0x00, // No flags
        NoHeaders = 0x01, // Remove image headers
        NoModList = 0x02, // Remove from the loader data table entries (e.g., the module list)
        NoNotifs = 0x04, // Remove notifications of new library loads before loading the library
        NoThdCall = 0x08, // Disable thread attach and detachs callbacks
        OvrHdrs = 0x10, // Overwrite the in-memory headers with the headers of the specified file
        UseHbp = 0x20, // Hook functions using hardware breakpoints
        UseTxf = 0x40, // Map the module in a transaction
        AllFlags = 0xFF // Enable everything
    };

    /// <summary>
    ///     Replaces any request to load fileName as a library with the provided bytes.
    /// </summary>
    /// <returns>
    ///     LoadLibraryRedirector uses an internal lock to prevent multiple instances from being created at the same time
    /// </returns>
    class LoadLibraryRedirector {
    public:
        LoadLibraryRedirector(std::wstring fileName, const std::vector<std::byte>& bytes, DWORD flags = 0, const std::wstring& modListName = L"");
        ~LoadLibraryRedirector();

    private:
        // Data that may be used by the function hooks
        static std::byte* baseAddress; // Not used with LoadFlags::UseTxf
        static std::wstring fileName;
        static std::vector<std::byte> libraryBytes; // Only used with LoadFlags::UseTxf
        static size_t mappedSize; // Not used with LoadFlags::UseTxf
        static std::wstring modListName;
        static bool redirectSection;
        static HANDLE section;
        static HANDLE transaction;
        static bool useHbp;
        static bool useTxf;

        // Hook information
        static std::unique_ptr<Hook> ntCreateSectionHook;
        static std::unique_ptr<Hook> ntMapViewOfSectionHook;
        static std::unique_ptr<Hook> ntOpenFileHook;

        // Ensure only 1 instance of the class is instantiated at a time
        // Do not use the normal singleton pattern because it'd cause LoadLibraryRedirector to always be instantiated
        static std::mutex lock;
        const std::lock_guard<std::mutex> lockGuard{ lock };
        LoadLibraryRedirector(const LoadLibraryRedirector&) = delete;
        LoadLibraryRedirector& operator=(const LoadLibraryRedirector&) = delete;

        static NTSTATUS NTAPI NtCreateSectionHook(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PLARGE_INTEGER MaximumSize, ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle);
        static NTSTATUS NTAPI NtOpenFileHook(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess, ULONG OpenOptions);
        static NTSTATUS NTAPI NtMapViewOfSectionHook(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Win32Protect);
    };

    /// <summary>Disable thread attach and detachs callbacks for a module.</summary>
    /// <param name='peBase'>The address of the start of the module.</param>
    bool DisableThreadCallbacks(std::byte* peBase);

    /// <summary>Get the address of the LDR_DATA_TABLE_ENTRY data for a module.</summary>
    /// <param name='peBase'>The address of the start of the module.</param>
    PLDR_DATA_TABLE_ENTRY GetLdrDataTableEntry(std::byte* peBase);

    /// <summary>
    ///     Loads the provided module bytes into the address space of the calling process.
    ///     The process of loading the module may cause other modules to be loaded.
    /// </summary>
    /// <param name='fileName'>
    ///     The name of a valid file that will be supplied to LoadLibraryW during the loading process.
    ///     The file may not be a file that is included in \KnownDlls or \KnownDlls32.
    ///     The file contents will be replaced by the contents of the bytes parameter during the loading process.
    ///     The file does not need to be a valid DLL if the UseTxf flag is specified and the OvrHdrs flag is not specified.
    ///     If the UseTxf flag is specified then the user will need GENERIC_WRITE access to the file.
    /// </param>
    /// <param name='bytes'>
    ///     The bytes of the module to load.
    /// </param>
    /// <param name='flags'>
    ///     The action to be taken when loading the module.
    ///     Refer to the LoadLibraryEx* documentation for a full list of accepted values.
    /// </param>
    /// <param name='modListName'>
    ///     An optional name to use as the DLL name in the module list.
    ///     fileName will be used if nothing is specified.
    ///     Only valid when used with the UseTxf flag.
    /// </param>
    /// <param name='nativeFlags'>
    ///     The action to be taken by LoadLibraryExW when loading the module.
    ///     Refer to the LoadLibraryExW documentation for a full list of accepted values.
    /// </param>
    /// <returns>
    ///     If the function succeeds, the return value is a handle to the loaded module.
    ///     If the function fails, the return value is NULL. To get extended error information, call GetLastError.
    /// </returns>
    HMODULE LoadLibrary(const std::wstring& fileName, const std::vector<std::byte>& bytes, DWORD flags = 0, const std::wstring& modListName = L"", DWORD nativeFlags = 0);

    /// <summary>Locks the loader lock.</summary>
    /// <returns>
    ///     If the function succeeds, the return value is a cookie that may be used to unlock the loader lock using <see cref="UnlockLoaderLock"/>.
    ///     If the function fails, the return value is zero.
    /// </returns>
    /// <seealso cref="LockLoaderLock"/>
    inline auto LockLoaderLock() noexcept {
        PL_LAZY_LOAD_NATIVE_PROC(LdrLockLoaderLock);
        size_t cookie;
        return (NT_SUCCESS(LazyLdrLockLoaderLock(0, nullptr, &cookie))) ? cookie : 0;
    }

    /// <summary>Overwrites the header data with the starting bytes of the specified file.</summary>
    /// <param name='fileName'>The name of a file whose bytes should be used to overwrite the headers.</param>
    bool OverwriteHeaders(std::byte* peBase, const std::wstring& fileName);

    /// <summary>Removes all callbacks registered using LdrRegisterDllNotification.</summary>
    /// <remarks>
    ///     The callback list is identified as described by Michael Maltsev's LdrDllNotificationHook project:
    ///     https://github.com/m417z/LdrDllNotificationHook
    /// </remarks>
    bool RemoveDllNotifications();

    /// <summary>Sets all header data to zero.</summary>
    /// <param name='peBase'>The address of the start of the module.</param>
    bool RemoveHeaders(std::byte* peBase);

    /// <summary>Removes the module from each LDR_DATA_TABLE_ENTRY list and the HashLinks list.</summary>
    /// <param name='peBase'>The address of the start of the module.</param>
    bool UnlinkModule(std::byte* peBase);

    /// <summary>Unlocks the loader lock using a cookie obtained using <see cref="LockLoaderLock"/>.</summary>
    /// <param name='cookie'>The value to use to unlock the loader lock.</param>
    /// <seealso cref="LockLoaderLock"/>
    inline auto UnlockLoaderLock(size_t cookie) noexcept {
        PL_LAZY_LOAD_NATIVE_PROC(LdrUnlockLoaderLock);
        return SUCCEEDED(LazyLdrUnlockLoaderLock(0, cookie));
    }
}