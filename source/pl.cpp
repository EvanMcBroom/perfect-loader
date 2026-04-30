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
#include "perfect_loader.hpp"
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <ktmw32.h>
#include <mutex>
#include <stack>
#include <string>

[[maybe_unused]] NTSTATUS NTAPI NtOpenSection(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);

HANDLE GetKnownDllSection(const std::wstring& dllName) {
    HANDLE section{ INVALID_HANDLE_VALUE };
    auto dllPath{ std::wstring{ L"\\KnownDlls\\" } + dllName };
    UNICODE_STRING unicodePath;
    PL_LAZY_LOAD_NATIVE_PROC(RtlInitUnicodeString)
    LazyRtlInitUnicodeString(&unicodePath, dllPath.data());
    OBJECT_ATTRIBUTES attributes;
    InitializeObjectAttributes(&attributes, &unicodePath, OBJ_CASE_INSENSITIVE, nullptr, nullptr);
    PL_LAZY_LOAD_NATIVE_PROC(NtOpenSection)
    if (NT_ERROR(LazyNtOpenSection(&section, SECTION_MAP_READ | SECTION_MAP_EXECUTE, &attributes)) || section == INVALID_HANDLE_VALUE) {
        dllPath = std::wstring{ L"\\KnownDlls32\\" } + dllName;
        LazyRtlInitUnicodeString(&unicodePath, dllPath.data());
        if (NT_ERROR(LazyNtOpenSection(&section, SECTION_MAP_READ | SECTION_MAP_EXECUTE, &attributes))) {
            section = INVALID_HANDLE_VALUE;
        }
    }
    return section;
}

extern "C" {
__declspec(dllexport) DWORD FindUsableHostDll(LPCWSTR SearchDir, DWORD PlFlags, SIZE_T DllSize, LPWSTR HostDllPath, DWORD HostDllPathSize) {
    if (!SearchDir || (PlFlags & PL_LOAD_FLAGS_USESEC && !DllSize) || !HostDllPath || !HostDllPathSize) {
        return 0;
    }
    bool windows24H2OrGreater{ Pl::GetNtdllVersion() >= 0x000a000065f40000 }; // Version 24H2 (OS Build 26100.0) and higher
    std::wstring usablePath;
    for (auto const& entry : std::filesystem::directory_iterator{ SearchDir, std::filesystem::directory_options::skip_permission_denied }) {
        auto path{ entry.path().wstring() };
        // Check that the module is not loaded in the current process
        auto moduleHandle{ GetModuleHandleW(path.data()) };
        if (moduleHandle) {
            continue;
        }
        // Check that the module is not in KnownDlls
        auto sectionHandle{ GetKnownDllSection(entry.path().filename()) };
        if (sectionHandle != INVALID_HANDLE_VALUE) {
            CloseHandle(sectionHandle);
            continue;
        }
        // For module doppelgänging, check that the current thread can write to the file
        if (PlFlags & PL_LOAD_FLAGS_USETXF) {
            HANDLE file{ CreateFileW(path.data(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr) };
            if (file == INVALID_HANDLE_VALUE && GetLastError() == ERROR_FILE_EXISTS) {
                file = CreateFileW(path.data(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            }
            if (file != INVALID_HANDLE_VALUE) {
                CloseHandle(file);
            } else {
                continue;
            }
            // For module doppelgänging prior to Windows 11 24H2, any file you could write to would work
            if (!windows24H2OrGreater) {
                usablePath = path;
            }
        }
        // Check for module doppelgänging after Windows 11 24H2 and for section hollowing that the path is a dll
        if (usablePath.empty() && !entry.path().extension().compare(L".dll")) {
            // For module doppelgänging, no more checks are needed
            if (PlFlags & PL_LOAD_FLAGS_USETXF) {
                usablePath = path;
            } else {
                // For section hollowing, check that the dll can be mapped
                auto file{ CreateFileW(path.data(), FILE_READ_DATA | SYNCHRONIZE, FILE_SHARE_READ, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr) };
                if (file != INVALID_HANDLE_VALUE) {
                    auto map{ CreateFileMappingW(file, nullptr, PAGE_READONLY | SEC_IMAGE, 0, 0, nullptr) };
                    if (map) {
                        auto view{ MapViewOfFile(map, FILE_MAP_READ, 0, 0, 0) };
                        if (view) {
                            Pl::Pe pe{ reinterpret_cast<std::byte*>(view) };
                            if (Pl::VerifyImage(pe)) {
                                // Check that the image is large enough to map the in-memory module into
                                if (pe.NtHeaders()->OptionalHeader.SizeOfImage >= DllSize) {
                                    // Check that the dll does not have cfg enabled
                                    auto dataDirectory{ pe.OptionalHeader()->DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG] };
                                    if (!dataDirectory.VirtualAddress) {
                                        usablePath = path;
                                    } else {
                                        auto loadConfig{ reinterpret_cast<const IMAGE_LOAD_CONFIG_DIRECTORY*>(pe.base + dataDirectory.VirtualAddress) };
                                        if (loadConfig->Size < offsetof(IMAGE_LOAD_CONFIG_DIRECTORY, GuardFlags) || !loadConfig->GuardCFFunctionCount) {
                                            usablePath = path;
                                        }
                                    }
                                }
                            }
                            UnmapViewOfFile(view);
                        }
                        CloseHandle(map);
                    }
                    CloseHandle(file);
                }
            }
        }
        if (usablePath.size()) {
            break;
        }
    }
    if (!usablePath.empty()) {
        if (HostDllPathSize > usablePath.size()) {
            std::wcscpy(HostDllPath, usablePath.data());
            return usablePath.length();
        }
        return usablePath.length() + 1;
    }
    return 0;
}

__declspec(dllexport) HMODULE WINAPI LoadDllFromMemory(LPVOID DllBase, SIZE_T DllSize, DWORD Flags, LPCWSTR FileName, DWORD PlFlags, LPCWSTR ModListName) {
    std::vector<std::byte> bytes(DllSize);
    std::memcpy(bytes.data(), DllBase, DllSize);
    return Pl::LoadLibrary(std::wstring((FileName) ? FileName : L""), bytes, PlFlags, std::wstring((ModListName) ? ModListName : L""), Flags);
}
}