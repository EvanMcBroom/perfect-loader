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
#include <filesystem>
#include <fstream>
#include <iterator>
#include <ktmw32.h>
#include <mutex>
#include <processthreadsapi.h>
#include <shlwapi.h>
#include <stack>
#include <string>

namespace {
    // Loader-option state persisted for the lifetime of a redirect session.
    std::wstring modListName;
    SIZE_T addVectoredHandlerProtectionPolicy;
    DWORD redirectorFlags;

    // State used by the manual mapping redirection path.
    std::wstring fileName;
    LARGE_INTEGER fileSize;
    std::unique_ptr<Pl::Hook> ntManageHotPatch;
    std::unique_ptr<Pl::Hook> ntMapViewOfSectionHook;
    std::unique_ptr<Pl::Hook> ntQueryVirtualMemoryHook;

    // State used by the Transactional NTFS (TxF) redirection path (e.g. module doppelgänging).
    std::unique_ptr<Pl::Hook> ntCreateSectionHook;
    std::unique_ptr<Pl::Hook> ntOpenFileHook;
    std::unique_ptr<Pl::Hook> ntQueryInformationThreadHook;
    bool redirectCreateSectionForTxf;
    HANDLE transaction;

    // State used by the section hollowing redirection path.
    std::wstring baseHostDllName;
    std::byte* ntMapViewOfSectionAddress;
    std::byte* ntQueryVirtualMemoryAddress;
    size_t expectedViewSize;
    
    // State used by the manual mapping and section hollowing redirection paths.
    std::byte* baseAddress = nullptr;
    size_t mappedSize = 0;

    
    // State used by the Transactional NTFS and section hollowing redirection paths.
    std::vector<std::byte> libraryBytes;
}

#if defined(_M_AMD64) && !defined(_M_ARM64EC)
extern "C" void __stdcall CallbackThunk();

extern "C" size_t PicHandler(void* originalReturnAddress, size_t* originalStackAddress, size_t originalReturnValue) {
    // Check if the called function was NtMapViewOfSection.
    // Each x64 syscall stub is 0x17 bytes. If the difference between
    // the return address and function address is less than 0x17, then
    // then we know that function address was called.
    if ((size_t(originalReturnAddress) - size_t(ntMapViewOfSectionAddress)) < 0x17) {
        // Process return from NtMapViewOfSection
        auto returnValue{ originalReturnValue };
        // Due to the x64 calling convention, the first 4 arguments to NtMapViewOfSection are
        // volatile and may be trashed. We can recover arguments 5-10 which includes the ViewSize
        // parameter. We can compare the ViewSize argument to our known dll size to identify if
        // the call to NtMapViewOfSection was for our module.
        auto viewSizePtr{ PSIZE_T(*(PSIZE_T(originalStackAddress) + 7)) };
        auto viewSize{ *viewSizePtr };
        if (viewSize == expectedViewSize) {
            // When loading a module, LoadLibrary will create a temporary LDR_DATA_TABLE_ENTRY
            // structure and fully populate it before its placed in the in-memory module lists.
            // This will exist in one of the process heaps.
            //
            // Enumerate all process heaps looking for the temporary ldr structure. LoadLibrary
            // will internally set NtMapViewOfSection to write its BaseAddress parameter to this
            // structure. This should be in the default heap, but enumerate all heaps in case
            // Microsoft reverts its loader code to using a private heap for allocations. This
            // behavior was determined through auditing ntdll on Windows 10 and testing on
            // Windows 11. If the structure is located, overwrite its DllBase member with the
            // address of the in-memory module.
            bool foundDllBase{ false };
            // Walk the heap
            HANDLE heap{ reinterpret_cast<Pl::PPEB>(NtCurrentTeb()->ProcessEnvironmentBlock)->ProcessHeap };
            PROCESS_HEAP_ENTRY heapEntry;
            std::memset(&heapEntry, 0, sizeof(heapEntry));
            bool endOfHeap{ true };
            Pl::LDR_DATA_TABLE_ENTRY* foundEntry{ nullptr };
            HeapLock(heap);
            while (HeapWalk(heap, &heapEntry)) {
                // Skip uncommitted allocations and allocations smaller than a LDR_DATA_TABLE_ENTRY
                if (!(heapEntry.wFlags & PROCESS_HEAP_UNCOMMITTED_RANGE)) {
                    if (heapEntry.cbData >= sizeof(Pl::LDR_DATA_TABLE_ENTRY)) {
                        auto possibleEntry = reinterpret_cast<Pl::LDR_DATA_TABLE_ENTRY*>(heapEntry.lpData);
                        // Check data that should be valid at this point for the LDR_DATA_TABLE_ENTRY:
                        // - DllBase: The field that needs modifying
                        // - FullDllName: The absolute path of the host dll
                        // - BaseDllName: The base name of the host dll with its extension
                        // - Flags: This should only be ImageDll (e.g. 4)
                        // - LoadCount: Was observed in testing as being set to 6
                        // - HashLinks: Should be set to itself (e.g. HashLinks->Flink = &HashLinks)
                        // No other data should not be populated in the LDR_DATA_TABLE_ENTRY at this point.
                        if (!possibleEntry->InLoadOrderLinks.Flink && !possibleEntry->InLoadOrderLinks.Blink &&
                            !possibleEntry->InMemoryOrderLinks.Flink && !possibleEntry->InMemoryOrderLinks.Blink &&
                            !possibleEntry->InInitializationOrderLinks.Flink && !possibleEntry->InInitializationOrderLinks.Blink &&
                            possibleEntry->DllBase &&
                            !possibleEntry->EntryPoint &&
                            !possibleEntry->SizeOfImage &&
                            possibleEntry->Flags & 4 && // ImageDll
                            possibleEntry->LoadCount > 0 && possibleEntry->LoadCount < 20 && // Set to a reasonable but low value
                            !possibleEntry->TlsIndex &&
                            possibleEntry->HashLinks.Flink == &possibleEntry->HashLinks && possibleEntry->HashLinks.Blink == &possibleEntry->HashLinks) {
                            // Assume the LDR_DATA_TABLE_ENTRY is valid and check that FullDllName and BaseDllName is the host dll
                            auto fullDllNameLength{ possibleEntry->FullDllName.Length };
                            auto fullDllNameMaximumLength{ possibleEntry->FullDllName.MaximumLength };
                            auto fullDllNameMaximumBuffer{ possibleEntry->FullDllName.Buffer };
                            auto baseDllNameLength{ possibleEntry->BaseDllName.Length };
                            auto baseDllNameMaximumLength{ possibleEntry->BaseDllName.MaximumLength };
                            auto baseDllNameMaximumBuffer{ possibleEntry->BaseDllName.Buffer };
                            if (fullDllNameLength > 0 && baseDllNameLength > 0 &&
                                fullDllNameMaximumLength < MAX_PATH * 2 && baseDllNameMaximumLength < MAX_PATH * 2 &&
                                fullDllNameLength <= fullDllNameMaximumLength && baseDllNameLength <= baseDllNameMaximumLength &&
                                fullDllNameMaximumBuffer && baseDllNameMaximumBuffer &&
                                StrStrIW(fullDllNameMaximumBuffer, baseHostDllName.data()) && StrStrIW(baseDllNameMaximumBuffer, baseHostDllName.data())) {
                                foundEntry = possibleEntry;
                                break;
                            }
                        }
                    }
                }
            }
            HeapUnlock(heap);
            if (foundEntry) {
                if (redirectorFlags & Pl::RedirectorFlags::UseSec) {
                    DWORD protection;
                    if (VirtualProtect(foundEntry->DllBase, *viewSizePtr, PAGE_READWRITE, &protection)) {
                        returnValue = STATUS_IMAGE_NOT_AT_BASE;
                        std::memset(foundEntry->DllBase, 0, *viewSizePtr);
                        (void)Pl::MapModule((std::byte*)foundEntry->DllBase, libraryBytes);
                    }
                } else {
                    returnValue = STATUS_IMAGE_NOT_AT_BASE;
                    foundEntry->DllBase = baseAddress;
                    *viewSizePtr = mappedSize;
                }
            }
        }
        return returnValue;
    } else if ((size_t(originalReturnAddress) - size_t(ntQueryVirtualMemoryAddress)) < 0x17) {
        // Process return from NtQueryVirtualMemory
        return NT_SUCCESS(originalReturnValue) ? originalReturnValue : STATUS_NOT_SUPPORTED;
    }
    return originalReturnValue;
}
#endif

namespace Pl {
    std::mutex LoadLibraryRedirector::lock;

// Disables a warning that the constructor does not release a lock.
// That is intended and the lock is released via RAII on deconstruction.
#pragma warning(push)
#pragma warning(disable : 26115)
    LoadLibraryRedirector::LoadLibraryRedirector(std::wstring fileName, const std::vector<std::byte>& bytes, DWORD flags, const std::wstring& modListName) {
        ::modListName = modListName;
        redirectorFlags = flags;
        auto useHbp{ flags & RedirectorFlags::UseHbp };
        if (flags & RedirectorFlags::UseHbp) {
            PL_LAZY_LOAD_NATIVE_PROC(RtlSetProtectedPolicy);
            if (LazyRtlSetProtectedPolicy) {
                (void)LazyRtlSetProtectedPolicy(&__uuidof(RtlpAddVectoredHandler), 0, &addVectoredHandlerProtectionPolicy);
            }
        }
        if (flags & RedirectorFlags::UseTxf || flags & RedirectorFlags::UseSec) {
            libraryBytes = bytes;
        }
        if (flags & RedirectorFlags::UseTxf) {
            ::fileName = fileName;
            redirectCreateSectionForTxf = false;
            transaction = INVALID_HANDLE_VALUE;
            PL_LAZY_LOAD_NATIVE_PROC(NtCreateSection);
            PL_LAZY_LOAD_NATIVE_PROC(NtOpenFile);
            ntCreateSectionHook = std::make_unique<Hook>(reinterpret_cast<std::byte*>(LazyNtCreateSection), reinterpret_cast<std::byte*>(NtCreateSectionHook), useHbp);
            ntOpenFileHook = std::make_unique<Hook>(reinterpret_cast<std::byte*>(LazyNtOpenFile), reinterpret_cast<std::byte*>(NtOpenFileHook), useHbp);
        } else {
            // Open the file to get needed information about the file (ex. its size)
            // When UsePic is set, the FILE_READ_DATA access is needed to get the expected view size of the section
            auto file{ CreateFileW(fileName.data(), FILE_READ_ATTRIBUTES | FILE_READ_DATA, 0, nullptr, OPEN_ALWAYS, 0, nullptr) };
            if (file == INVALID_HANDLE_VALUE) {
                throw std::exception("Could not open the path specified in the fileName argument to LoadLibraryRedirector.");
            }
            (void)GetFileSizeEx(file, &fileSize);
#if defined(_M_AMD64) && !defined(_M_ARM64EC)
            if (flags & RedirectorFlags::UsePic) {
                PL_LAZY_LOAD_NATIVE_PROC(NtMapViewOfSection);
                PL_LAZY_LOAD_NATIVE_PROC(NtQueryVirtualMemory);
                ntMapViewOfSectionAddress = (std::byte*)(LazyNtMapViewOfSection);
                ntQueryVirtualMemoryAddress = (std::byte*)(LazyNtQueryVirtualMemory);
                baseHostDllName = std::filesystem::path(fileName).filename();
                // Call NtCreateSection and NtMapViewOfSection with parameters that match what LoadLibrary
                // uses (ex. SEC_IMAGE). Save the resultant viewSize to filter calls to MapViewOfSection
                // that are NtCreateSection that are inspected by PicHandler.
                HANDLE section{ 0 };
                PL_LAZY_LOAD_NATIVE_PROC(NtCreateSection);
                if (NT_SUCCESS(LazyNtCreateSection(&section, SECTION_MAP_READ, nullptr, nullptr, PAGE_READONLY, SEC_IMAGE, file))) {
                    LPVOID baseAddress{ nullptr };
                    SIZE_T viewSize{ 0 };
                    if (NT_SUCCESS(LazyNtMapViewOfSection(section, GetCurrentProcess(), &baseAddress, 0, 0, 0, &viewSize, SECTION_INHERIT::ViewShare, MEM_DIFFERENT_IMAGE_BASE_OK, PAGE_READONLY))) {
                        expectedViewSize = viewSize;
                        PL_LAZY_LOAD_NATIVE_PROC(NtUnmapViewOfSection);
                        (void)LazyNtUnmapViewOfSection(GetCurrentProcess(), baseAddress);
                    }
                    CloseHandle(section);
                }
            }
#endif
            CloseHandle(file);
            if (flags & RedirectorFlags::UseSec) {
                PL_LAZY_LOAD_NATIVE_PROC(NtCreateSection);
                ntCreateSectionHook = std::make_unique<Hook>(reinterpret_cast<std::byte*>(LazyNtCreateSection), reinterpret_cast<std::byte*>(NtCreateSectionHook), useHbp);
            }
            else if (!MapModule(bytes, &baseAddress, &mappedSize)) {
                throw std::exception("Could not map the library specified in the bytes argument to LoadLibraryRedirector.");
            }
#if defined(_M_AMD64) && !defined(_M_ARM64EC)
            if (flags & RedirectorFlags::UsePic) {
                PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION picInfo;
                picInfo.Callback = (PVOID)(ULONG_PTR)CallbackThunk;
                picInfo.Version = 0;
                picInfo.Reserved = 0;
                PL_LAZY_LOAD_NATIVE_PROC(NtSetInformationProcess);
                LazyNtSetInformationProcess(GetCurrentProcess(), ProcessInstrumentationCallback, &picInfo, sizeof(picInfo));
            } else {
#endif
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
#if defined(_M_AMD64) && !defined(_M_ARM64EC)
        }
#endif
    }
#pragma warning(pop)

    LoadLibraryRedirector::~LoadLibraryRedirector() {
        ntCreateSectionHook = nullptr;
        ntOpenFileHook = nullptr;
        ntMapViewOfSectionHook = nullptr;
        ntQueryVirtualMemoryHook = nullptr;
#if defined(_M_AMD64) && !defined(_M_ARM64EC)
        if (redirectorFlags & RedirectorFlags::UsePic) {
            RemoveNirvanaCallbacks();
        }
#endif
        if (redirectorFlags & RedirectorFlags::UseHbp) {
            PL_LAZY_LOAD_NATIVE_PROC(RtlSetProtectedPolicy);
            if (LazyRtlSetProtectedPolicy) {
                (void)LazyRtlSetProtectedPolicy(&__uuidof(RtlpAddVectoredHandler), addVectoredHandlerProtectionPolicy, 0);
            }
        }
        if (transaction != INVALID_HANDLE_VALUE) {
            PL_LAZY_LOAD_NATIVE_PROC(RtlSetCurrentTransaction);
            LazyRtlSetCurrentTransaction(0);
            PL_LAZY_LOAD_LIBRARY_AND_PROC(Ktmw32, RollbackTransaction);
            (void)LazyRollbackTransaction(transaction);
            FreeLibrary(LazyKtmw32);
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
            PL_LAZY_LOAD_LIBRARY_AND_PROC(Ktmw32, CreateTransaction);
            transaction = LazyCreateTransaction(nullptr, 0, 0, 0, 0, 0, nullptr);
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
            redirectCreateSectionForTxf = true;
            FreeLibrary(LazyKtmw32);
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
        if (redirectCreateSectionForTxf || redirectorFlags & RedirectorFlags::UseSec) {
            // The Transactional NTFS (TxF) redirection path needs RWX and the section
            // hollowing path needs RWX+Query. It's simplest to allow all access.
            status = LazyNtCreateSection(SectionHandle, SECTION_ALL_ACCESS, nullptr, 0, PAGE_READONLY, SEC_IMAGE, FileHandle);
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
        auto a = LazyNtQuerySection(SectionHandle, SectionImageInformation, &information, sizeof(information), &length);
        if (NT_SUCCESS(a)) {
            if (information.ImageFileSize == fileSize.QuadPart) {
                if (redirectorFlags & RedirectorFlags::UseSec) {
                    ntMapViewOfSectionHook->Enable(false);
                    PL_LAZY_LOAD_NATIVE_PROC(NtMapViewOfSection);
                    auto status{ LazyNtMapViewOfSection(SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Win32Protect) };
                    ntMapViewOfSectionHook->Enable(true);
                    DWORD protection;
                    if (VirtualProtect(*BaseAddress, *ViewSize, PAGE_READWRITE, &protection)) {
                        std::memset(*BaseAddress, 0, *ViewSize);
                        (void)MapModule((std::byte*)*BaseAddress, libraryBytes);
                        return STATUS_IMAGE_NOT_AT_BASE;
                    }
                } else {
                    *BaseAddress = baseAddress;
                    *ViewSize = mappedSize;
                }
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
        return LoadLibraryExW(fileName.data(), nullptr, nativeFlags);
    }
}
