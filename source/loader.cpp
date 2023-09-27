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

#include "perfect_loader.hpp"
#include <algorithm>
#include <fstream>
#include <iterator>
#include <ktmw32.h>
#include <mutex>
#include <stack>
#include <string>

#include <iostream>
#include <processthreadsapi.h>

namespace Pl {
    // Static member variable definitions
    std::byte* LoadLibraryRedirector::baseAddress = nullptr;
    std::wstring LoadLibraryRedirector::fileName;
    std::mutex LoadLibraryRedirector::lock;
    std::vector<std::byte> LoadLibraryRedirector::libraryBytes;
    size_t LoadLibraryRedirector::mappedSize = 0;
    std::wstring LoadLibraryRedirector::modListName;
    std::unique_ptr<Hook> LoadLibraryRedirector::ntCreateSectionHook;
    std::unique_ptr<Hook> LoadLibraryRedirector::ntMapViewOfSectionHook;
    std::unique_ptr<Hook> LoadLibraryRedirector::ntOpenFileHook;
    std::unique_ptr<Hook> LoadLibraryRedirector::ntQueryInformationThreadHook;
    bool LoadLibraryRedirector::redirectSection = false;
    HANDLE LoadLibraryRedirector::section = INVALID_HANDLE_VALUE;
    HANDLE LoadLibraryRedirector::transaction = INVALID_HANDLE_VALUE;
    bool LoadLibraryRedirector::useHbp;
    bool LoadLibraryRedirector::useTxf;

    LoadLibraryRedirector::LoadLibraryRedirector(std::wstring fileName, const std::vector<std::byte>& bytes, DWORD flags, const std::wstring& modListName) {
        // Setup the information that may be used by the hooks
        useHbp = flags & LoadFlags::UseHbp;
        useTxf = flags & LoadFlags::UseTxf;
        bool enableMainHooks{ true };
        // Get OS version info
        PL_LAZY_LOAD_KERNEL_AND_PROC(RtlGetVersion);
        RTL_OSVERSIONINFOW versionInfo = { 0 };
        if (LazyNtoskrnl) {
            LazyRtlGetVersion(&versionInfo);
            (void)FreeLibrary(LazyNtoskrnl);
        }
        // Chech for if useHbp was requested and this platform supports parallel loading (NT > 10)
        if (useHbp && versionInfo.dwMajorVersion >= 10) {
            // If so, NtQueryInformationThread needs to be handled first to disable parallel loading
            // Then the main hooks may be enabled
            PL_LAZY_LOAD_NATIVE_PROC(NtQueryInformationThread);
            ntQueryInformationThreadHook = std::make_unique<Hook>(reinterpret_cast<std::byte*>(LazyNtQueryInformationThread), reinterpret_cast<std::byte*>(NtQueryInformationThreadHook), useHbp);
            enableMainHooks = false;
        }
        if (useTxf) {
            this->libraryBytes = bytes;
        } else {
            MapModule(bytes, &this->baseAddress, &this->mappedSize);
        }
        this->fileName = fileName;
        this->modListName = modListName;
        // Setup the hooks
        PL_LAZY_LOAD_NATIVE_PROC(NtMapViewOfSection);
        PL_LAZY_LOAD_NATIVE_PROC(NtOpenFile);
        ntMapViewOfSectionHook = std::make_unique<Hook>(reinterpret_cast<std::byte*>(LazyNtMapViewOfSection), reinterpret_cast<std::byte*>(NtMapViewOfSectionHook), useHbp, enableMainHooks);
        ntOpenFileHook = std::make_unique<Hook>(reinterpret_cast<std::byte*>(LazyNtOpenFile), reinterpret_cast<std::byte*>(NtOpenFileHook), useHbp, enableMainHooks);
        if (useTxf) {
            PL_LAZY_LOAD_NATIVE_PROC(NtCreateSection);
            ntCreateSectionHook = std::make_unique<Hook>(reinterpret_cast<std::byte*>(LazyNtCreateSection), reinterpret_cast<std::byte*>(NtCreateSectionHook), useHbp, enableMainHooks);
        }
    }

    LoadLibraryRedirector::~LoadLibraryRedirector() {
        ntCreateSectionHook = nullptr;
        ntMapViewOfSectionHook = nullptr;
        ntOpenFileHook = nullptr;
        PL_LAZY_LOAD_NATIVE_PROC(RtlSetCurrentTransaction);
        LazyRtlSetCurrentTransaction(0);
        RollbackTransaction(transaction);
    }

    NTSTATUS NTAPI LoadLibraryRedirector::NtOpenFileHook(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess, ULONG OpenOptions) {
        // Temporarily remove the NtOpenFile detour
        PL_LAZY_LOAD_NATIVE_PROC(NtOpenFile);
        ntOpenFileHook->Enable(false);
        // Check if the path of the file to open ends with the expected library name
        std::wstring fileNameToOpen{ ObjectAttributes->ObjectName->Buffer };
        bool fileNameMatches{ std::equal(fileName.rbegin(), fileName.rend(), fileNameToOpen.rbegin()) };
        NTSTATUS status{ 0 };
        if (useTxf && fileNameMatches) {
            // Open the requested file in a transaction and overwrite it
            transaction = CreateTransaction(nullptr, 0, 0, 0, 0, 0, nullptr);
            // Set the transaction manually because it needs to stay open until LoadLibrary completes
            PL_LAZY_LOAD_NATIVE_PROC(RtlSetCurrentTransaction);
            LazyRtlSetCurrentTransaction(transaction);
            // Set modListName to the default of fileName if useTxf or modListName was not specified
            if (!useTxf || modListName.empty()) {
                modListName = fileName;
            }
            HANDLE writer{ CreateFileW(modListName.data(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr) };
            if (writer == INVALID_HANDLE_VALUE && GetLastError() == ERROR_FILE_EXISTS) {
                writer = CreateFileW(modListName.data(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            }
            // Overwrite the file with the current bytes of the library to load
            size_t totalBytesWritten{ 0 };
            bool lastWriteSucceeded{ true };
            while (totalBytesWritten < libraryBytes.size() && lastWriteSucceeded) {
                DWORD bytesWritten;
                lastWriteSucceeded = WriteFile(writer, libraryBytes.data() + totalBytesWritten, libraryBytes.size() - totalBytesWritten, &bytesWritten, nullptr);
                totalBytesWritten += bytesWritten;
            }
            CloseHandle(writer);
            *FileHandle = CreateFileW(modListName.data(), GENERIC_READ, ShareAccess, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            redirectSection = true;
        } else {
            // Open the requested file then re-enable the detour if its still needed
            status = LazyNtOpenFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions);
            if (fileNameMatches) {
                redirectSection = true;
                status = STATUS_IMAGE_NOT_AT_BASE;
            } else {
                ntOpenFileHook->Enable(true);
            }
        }
        return status;
    }

    NTSTATUS NTAPI LoadLibraryRedirector::NtCreateSectionHook(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PLARGE_INTEGER MaximumSize, ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle) {
        ntCreateSectionHook->Enable(false);
        PL_LAZY_LOAD_NATIVE_PROC(NtCreateSection);
        NTSTATUS status;
        if (redirectSection) {
            status = LazyNtCreateSection(SectionHandle, SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE, nullptr, 0, PAGE_READONLY, SEC_IMAGE, FileHandle);
        } else {
            status = LazyNtCreateSection(SectionHandle, DesiredAccess, ObjectAttributes, MaximumSize, SectionPageProtection, AllocationAttributes, FileHandle);
            ntCreateSectionHook->Enable(true);
        }
        return status;
    }

    NTSTATUS NTAPI LoadLibraryRedirector::NtMapViewOfSectionHook(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Win32Protect) {
        ntMapViewOfSectionHook->Enable(false);
        if (!redirectSection || (redirectSection && useTxf)) {
            PL_LAZY_LOAD_NATIVE_PROC(NtMapViewOfSection);
            auto status{ LazyNtMapViewOfSection(SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Win32Protect) };
            if (!redirectSection) {
                ntMapViewOfSectionHook->Enable(true);
            }
            return status;
        } else {
            *BaseAddress = baseAddress;
            *ViewSize = mappedSize;
            return STATUS_IMAGE_NOT_AT_BASE;
        }
    }

    NTSTATUS NTAPI LoadLibraryRedirector::NtQueryInformationThreadHook(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength, PULONG ReturnLength) {
        ntQueryInformationThreadHook->Enable(false);
        auto ThreadDynamicCodePolicyInfo{ static_cast<THREADINFOCLASS>(42) };
        if (ThreadInformationClass != ThreadDynamicCodePolicyInfo) {
            // Although this hook may technically query a seperate thread if a psuedo thread handle was used that's ok for our purposes
            PL_LAZY_LOAD_NATIVE_PROC(NtQueryInformationThread);
            auto status{ LazyNtQueryInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength, ReturnLength) };
            ntQueryInformationThreadHook->Enable(true);
            return status;
        } else {
            *reinterpret_cast<DWORD*>(ThreadInformation) = 1;
            if (ReturnLength) {
                *ReturnLength = ThreadInformationLength;
            }
            ntMapViewOfSectionHook->Enable(true);
            ntOpenFileHook->Enable(true);
            if (useTxf) {
                ntCreateSectionHook->Enable(true);
            }
            return 0;
        }
    }
    bool DisableThreadCallbacks(std::byte* peBase) {
        __try {
            auto ldrDataTableEntry{ GetLdrDataTableEntry(peBase) };
            if (ldrDataTableEntry) {
                ldrDataTableEntry->Flags |= LDRP_DONT_CALL_FOR_THREADS;
                return true;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
        }
        return false;
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
            // There is no point in replacing the headers if they're going to be removed
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

    bool OverwriteHeaders(std::byte* peBase, const std::wstring& fileName) {
        bool succeeded{ false };
        __try {
            auto file{ CreateFileW(fileName.data(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr) };
            if (file != INVALID_HANDLE_VALUE) {
                ULONG protection;
                auto sizeOfHeaders{ Pe(peBase).OptionalHeader()->SizeOfHeaders };
                VirtualProtect(peBase, sizeOfHeaders, PAGE_READWRITE, &protection);
                size_t totalBytesRead{ 0 };
                bool lastReadSucceeded{ true };
                while (totalBytesRead < sizeOfHeaders && lastReadSucceeded) {
                    DWORD bytesRead;
                    ReadFile(file, peBase + totalBytesRead, sizeOfHeaders - totalBytesRead, &bytesRead, nullptr);
                    totalBytesRead += bytesRead;
                }
                VirtualProtect(peBase, sizeOfHeaders, protection, &protection);
                CloseHandle(file);
                succeeded = true;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
        }
        return succeeded;
    }

    bool RemoveDllNotifications() {
        bool succeeded{ false };
        // Get the address of an entry in the notification block list
        PL_LAZY_LOAD_NATIVE_PROC(LdrRegisterDllNotification);
        auto callback{ [](ULONG NotificationReason, PVOID NotificationData, PVOID Context) {} };
        PLDRP_DLL_NOTIFICATION_BLOCK initialBlock;
        if (NT_SUCCESS(LazyLdrRegisterDllNotification(0, callback, nullptr, reinterpret_cast<PVOID*>(&initialBlock)))) {
            // Enumerate all entries in the notification block list
            std::vector<PLDRP_DLL_NOTIFICATION_BLOCK> notificationBlocks;
            auto cookie{ LockLoaderLock() };
            if (cookie) {
                auto iter{ initialBlock };
                do {
                    // Only add notification blocks that were not registered by NTDLL
                    notificationBlocks.emplace_back(iter);
                    iter = reinterpret_cast<PLDRP_DLL_NOTIFICATION_BLOCK>(iter->Links.Flink);
                } while (iter != initialBlock);
                (void)UnlockLoaderLock(cookie);
                // Remove all registered notifications
                PL_LAZY_LOAD_NATIVE_PROC(LdrUnregisterDllNotification);
                for (auto notificationBlock : notificationBlocks) {
                    LazyLdrUnregisterDllNotification(notificationBlock);
                }
                succeeded = true;
            }
        }
        return succeeded;
    }

    bool RemoveHeaders(std::byte* peBase) {
        __try {
            ULONG protection;
            auto sizeOfHeaders{ Pe(peBase).OptionalHeader()->SizeOfHeaders };
            VirtualProtect(peBase, sizeOfHeaders, PAGE_READWRITE, &protection);
            std::memset(peBase, 0, sizeOfHeaders);
            VirtualProtect(peBase, sizeOfHeaders, protection, &protection);
            return true;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
        }
        return false;
    }

    bool UnlinkModule(std::byte* peBase) {
        bool succeeded{ false };
        __try {
            auto cookie{ LockLoaderLock() };
            if (cookie) {
                auto ldrDataTableEntry{ GetLdrDataTableEntry(peBase) };
                if (ldrDataTableEntry) {
                    auto unlinkEntry = [](LIST_ENTRY* listEntry) {
                        listEntry->Blink->Flink = listEntry->Flink;
                        listEntry->Flink->Blink = listEntry->Blink;
                    };
                    unlinkEntry(&ldrDataTableEntry->InLoadOrderLinks);
                    unlinkEntry(&ldrDataTableEntry->InMemoryOrderLinks);
                    unlinkEntry(&ldrDataTableEntry->InInitializationOrderLinks);
                    unlinkEntry(&ldrDataTableEntry->HashLinks);
                    succeeded = true;
                }
                (void)UnlockLoaderLock(cookie);
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
        }
        return succeeded;
    }
}