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
#define UNICODE
#include "perfect_loader.hpp"
#include <algorithm>
#include <fstream>
#include <iterator>
#include <ktmw32.h>
#include <mutex>
#include <stack>
#include <string>

#include <iostream>
#include <ktmw32.h>
#include <processthreadsapi.h>

namespace {
    // Loader-option state persisted for the lifetime of a redirect session.
    std::wstring modListName;
    SIZE_T addVectoredHandlerProtectionPolicy;
    bool useHbp;

    // State used by the manual mapping redirection path (non-TxF mode).
    LARGE_INTEGER fileSize;
    std::byte* baseAddress = nullptr;
    size_t mappedSize = 0;
    std::unique_ptr<Pl::Hook> ntManageHotPatch;
    std::unique_ptr<Pl::Hook> ntMapViewOfSectionHook;
    std::unique_ptr<Pl::Hook> ntQueryVirtualMemoryHook;

    // State used by the Transactional NTFS (TxF) redirection path (e.g. module doppelgänging).
    std::wstring fileName;
    std::vector<std::byte> libraryBytes;
    std::unique_ptr<Pl::Hook> ntCreateSectionHook;
    std::unique_ptr<Pl::Hook> ntOpenFileHook;
    bool redirectCreateSection;
    HANDLE transaction;
}

namespace Pl {
    std::mutex LoadLibraryRedirector::lock;

// Disables a warning that the constructor does not release a lock.
// That is intended and the lock is released via RAII on deconstruction.
#pragma warning(push)
#pragma warning(disable : 26115)
    LoadLibraryRedirector::LoadLibraryRedirector(std::wstring fileName, const std::vector<std::byte>& bytes, DWORD flags, const std::wstring& modListName) {
        ::modListName = modListName;
        useHbp = flags & LoadFlags::UseHbp;
        if (useHbp) {
            PL_LAZY_LOAD_NATIVE_PROC(RtlSetProtectedPolicy);
            if (LazyRtlSetProtectedPolicy) {
                (void)LazyRtlSetProtectedPolicy(&__uuidof(RtlpAddVectoredHandler), 0, &addVectoredHandlerProtectionPolicy);
            }
        }
        if (flags & LoadFlags::UseTxf) {
            ::fileName = fileName;
            libraryBytes = bytes;
            redirectCreateSection = false;
            transaction = INVALID_HANDLE_VALUE;
            PL_LAZY_LOAD_NATIVE_PROC(NtCreateSection);
            PL_LAZY_LOAD_NATIVE_PROC(NtOpenFile);
            ntCreateSectionHook = std::make_unique<Hook>(reinterpret_cast<std::byte*>(LazyNtCreateSection), reinterpret_cast<std::byte*>(NtCreateSectionHook), useHbp);
            ntOpenFileHook = std::make_unique<Hook>(reinterpret_cast<std::byte*>(LazyNtOpenFile), reinterpret_cast<std::byte*>(NtOpenFileHook), useHbp);
        } else {
            auto file{ CreateFileW(fileName.data(), FILE_READ_ATTRIBUTES, 0, nullptr, OPEN_ALWAYS, 0, nullptr) };
            if (file == INVALID_HANDLE_VALUE) {
                throw std::exception("Could not open the path specified in the fileName argument to LoadLibraryRedirector.");
            }
            (void)GetFileSizeEx(file, &fileSize);
            CloseHandle(file);
            if (!MapModule(bytes, &baseAddress, &mappedSize)) {
                throw std::exception("Could not map the library specified in the bytes argument to LoadLibraryRedirector.");
            }
            // Windows 11 24H2 introduced a hotpatch query path that can interfere with redirecting
            // LoadLibrary to an in-memory module. This path is only present in amd64/arm64 ntdll,
            // not i386 ntdll (ex. SysWOW64). For those architectures on 24H2+ with hotpatching
            // enabled, install compatibility hooks.
            // Reference: https://github.com/EvanMcBroom/perfect-loader/issues/1
            auto ntdllArchitecture{ Pe(reinterpret_cast<std::byte*>(GetModuleHandleW(L"ntdll.dll"))).PeHeader()->Machine };
            if (ntdllArchitecture == IMAGE_FILE_MACHINE_AMD64 || ntdllArchitecture == IMAGE_FILE_MACHINE_ARM64) {
                auto ntdllVersion{ GetNtdllVersion() };
                if (ntdllVersion >= 0x000a000065f40000) { // Version 24H2 (OS Build 26100.0) and higher
                    if (IsHotPatchingEnabled()) {
                        PL_LAZY_LOAD_NATIVE_PROC(NtManageHotPatch);
                        ntManageHotPatch = std::make_unique<Hook>(reinterpret_cast<std::byte*>(LazyNtManageHotPatch), reinterpret_cast<std::byte*>(NtManageHotPatchHook), useHbp, false);
                        PL_LAZY_LOAD_NATIVE_PROC(NtQueryVirtualMemory);
                        ntQueryVirtualMemoryHook = std::make_unique<Hook>(reinterpret_cast<std::byte*>(LazyNtQueryVirtualMemory), reinterpret_cast<std::byte*>(NtQueryVirtualMemoryHook), useHbp);
                    }
                }
            }
            PL_LAZY_LOAD_NATIVE_PROC(NtMapViewOfSection);
            ntMapViewOfSectionHook = std::make_unique<Hook>(reinterpret_cast<std::byte*>(LazyNtMapViewOfSection), reinterpret_cast<std::byte*>(NtMapViewOfSectionHook), useHbp);
        }
    }
#pragma warning(pop)

    LoadLibraryRedirector::~LoadLibraryRedirector() {
        ntCreateSectionHook = nullptr;
        ntOpenFileHook = nullptr;
        ntMapViewOfSectionHook = nullptr;
        ntQueryVirtualMemoryHook = nullptr;
        if (useHbp) {
            PL_LAZY_LOAD_NATIVE_PROC(RtlSetProtectedPolicy);
            if (LazyRtlSetProtectedPolicy) {
                (void)LazyRtlSetProtectedPolicy(&__uuidof(RtlpAddVectoredHandler), addVectoredHandlerProtectionPolicy, 0);
            }
        }
        PL_LAZY_LOAD_NATIVE_PROC(RtlSetCurrentTransaction);
        if (transaction != INVALID_HANDLE_VALUE) {
            LazyRtlSetCurrentTransaction(0);
            RollbackTransaction(transaction);
        }
        libraryBytes.clear(); // Explicitly clear in case the in-memory dll is large
    }

    NTSTATUS NTAPI LoadLibraryRedirector::NtOpenFileHook(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess, ULONG OpenOptions) {
        // Temporarily remove the NtOpenFile detour
        PL_LAZY_LOAD_NATIVE_PROC(NtOpenFile);
        ntOpenFileHook->Enable(false);
        // Check if the path of the file to open ends with the expected library name
        std::wstring fileNameToOpen{ ObjectAttributes->ObjectName->Buffer };
        bool fileNameMatches{ std::equal(fileName.rbegin(), fileName.rend(), fileNameToOpen.rbegin()) };
        NTSTATUS status{ 0 };
        if (fileNameMatches) {
            // Open the requested file in a transaction and overwrite it
            transaction = CreateTransaction(nullptr, 0, 0, 0, 0, 0, nullptr);
            // Keep the transaction active for the entire LoadLibrary call, then roll it back in the destructor.
            PL_LAZY_LOAD_NATIVE_PROC(RtlSetCurrentTransaction);
            LazyRtlSetCurrentTransaction(transaction);
            // Set modListName to the default of fileName if modListName was not specified
            if (::modListName.empty()) {
                modListName = fileName;
            }
            HANDLE writer{ CreateFileW(modListName.data(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr) };
            if (writer == INVALID_HANDLE_VALUE && GetLastError() == ERROR_FILE_EXISTS) {
                writer = CreateFileW(modListName.data(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            }
            // Write the payload to the transacted file handle so the loader reads our in-memory bytes.
            size_t totalBytesWritten{ 0 };
            bool lastWriteSucceeded{ true };
            while (totalBytesWritten < libraryBytes.size() && lastWriteSucceeded) {
                DWORD bytesWritten;
                lastWriteSucceeded = WriteFile(writer, libraryBytes.data() + totalBytesWritten, libraryBytes.size() - totalBytesWritten, &bytesWritten, nullptr);
                totalBytesWritten += bytesWritten;
            }
            CloseHandle(writer);
            *FileHandle = CreateFileW(modListName.data(), GENERIC_READ, ShareAccess, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            redirectCreateSection = true;
        } else {
            // Open the requested file then re-enable the detour for future opens with file name matches.
            status = LazyNtOpenFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions);
            ntOpenFileHook->Enable(true);
        }
        return status;
    }

    NTSTATUS NTAPI LoadLibraryRedirector::NtCreateSectionHook(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PLARGE_INTEGER MaximumSize, ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle) {
        ntCreateSectionHook->Enable(false);
        PL_LAZY_LOAD_NATIVE_PROC(NtCreateSection);
        NTSTATUS status;
        if (redirectCreateSection) {
            status = LazyNtCreateSection(SectionHandle, SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE, nullptr, 0, PAGE_READONLY, SEC_IMAGE, FileHandle);
        } else {
            status = LazyNtCreateSection(SectionHandle, DesiredAccess, ObjectAttributes, MaximumSize, SectionPageProtection, AllocationAttributes, FileHandle);
            ntCreateSectionHook->Enable(true);
        }
        return status;
    }

    NTSTATUS NTAPI LoadLibraryRedirector::NtManageHotPatchHook(HOT_PATCH_INFORMATION_CLASS HotPatchInformationClass, PVOID HotPatchInformation, ULONG HotPatchInformationLength, PULONG ReturnLength) {
        ntManageHotPatch->Enable(false);
        if (HotPatchInformationClass == ManageHotPatchQuerySinglePatch) {
            std::memset(HotPatchInformation, '\0', HotPatchInformationLength);
            if (ReturnLength) {
                *ReturnLength = 0;
            }
            return STATUS_SUCCESS;
        }
        PL_LAZY_LOAD_NATIVE_PROC(NtManageHotPatch);
        auto status{ LazyNtManageHotPatch(HotPatchInformationClass, HotPatchInformation, HotPatchInformationLength, ReturnLength) };
        ntManageHotPatch->Enable(true);
        return status;
    }

    NTSTATUS NTAPI LoadLibraryRedirector::NtMapViewOfSectionHook(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Win32Protect) {
        PL_LAZY_LOAD_NATIVE_PROC(NtQuerySection);
        SECTION_IMAGE_INFORMATION information = { 0 };
        SIZE_T length;
        if (NT_SUCCESS(LazyNtQuerySection(SectionHandle, SectionImageInformation, &information, sizeof(information), &length))) {
            if (information.ImageFileSize == fileSize.QuadPart) {
                *BaseAddress = baseAddress;
                *ViewSize = mappedSize;
                return STATUS_IMAGE_NOT_AT_BASE;
            }
        }
        ntMapViewOfSectionHook->Enable(false);
        PL_LAZY_LOAD_NATIVE_PROC(NtMapViewOfSection);
        auto status{ LazyNtMapViewOfSection(SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Win32Protect) };
        ntMapViewOfSectionHook->Enable(true);
        return status;
    }

    NTSTATUS NTAPI LoadLibraryRedirector::NtQueryVirtualMemoryHook(HANDLE ProcessHandle, PVOID BaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength) {
        ntQueryVirtualMemoryHook->Enable(false);
        if (BaseAddress == baseAddress && MemoryInformationClass == MemoryImageExtensionInformation) {
            ntManageHotPatch->Enable(true);
            return STATUS_NOT_SUPPORTED;
        }
        PL_LAZY_LOAD_NATIVE_PROC(NtQueryVirtualMemory);
        auto status{ LazyNtQueryVirtualMemory(ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation, MemoryInformationLength, ReturnLength) };
        ntQueryVirtualMemoryHook->Enable(true);
        return status;
    }

    PLDR_DATA_TABLE_ENTRY GetLdrDataTableEntry(std::byte* peBase) {
        auto moduleList{ &(reinterpret_cast<Pl::PPEB>(NtCurrentTeb()->ProcessEnvironmentBlock)->Ldr->InLoadOrderModuleList) };
        auto iter{ moduleList };
        do {
            auto ldrDataTableEntry{ reinterpret_cast<LDR_DATA_TABLE_ENTRY*>(iter) };
            if (ldrDataTableEntry->DllBase == peBase) {
                return ldrDataTableEntry;
            }
            iter = iter->Flink;
        } while (iter != moduleList);
        return nullptr;
    }
    
    HMODULE LoadLibrary(const std::wstring& fileName, const std::vector<std::byte>& bytes, DWORD flags, const std::wstring& modListName, DWORD nativeFlags) {
        LoadLibraryRedirector redirector{ fileName, bytes, flags };
        if (flags & LoadFlags::NoNotifs) {
            (void)RemoveDllNotifications();
        }
        auto library{ LoadLibraryExW(fileName.data(), nullptr, nativeFlags) };
        if (library) {
            auto peBase{ reinterpret_cast<std::byte*>(library) };
            if (flags & LoadFlags::NoThdCall) {
                DisableThreadCallbacks(peBase);
            }
            // Skip header overwrite if headers will be zeroed out immediately afterwards.
            if (flags & LoadFlags::OvrHdrs && !(flags & LoadFlags::NoHeaders)) {
                // First attempt to overwrite the file using the DLL name from the loader data table entry
                // That allows users to originally supply the name of an API set which the loader will resolve
                auto cookie{ LockLoaderLock() };
                if (cookie) {
                    auto ldrDataTableEntry{ GetLdrDataTableEntry(peBase) };
                    if (!OverwriteHeaders(peBase, std::wstring{ ldrDataTableEntry->FullDllName.Buffer })) {
                        // If that failed it is likely due to the file not existing
                        // That could be due to the user specifying modListName to be a non-existing file
                        // In that situation, reattempt to overwrite the file using fileName
                        (void)OverwriteHeaders(peBase, fileName);
                    }
                    (void)UnlockLoaderLock(cookie);
                }
            }
            if (flags & LoadFlags::NoModList) {
                (void)UnlinkModule(peBase);
            }
            if (flags & LoadFlags::NoHeaders) {
                (void)RemoveHeaders(peBase);
            }
        }
        return library;
    }
}
