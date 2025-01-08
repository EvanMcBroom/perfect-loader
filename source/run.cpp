#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include "perfect_loader.hpp"
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <vector>

/// <summary>
/// Finds a usable dll path to pass to LoadLibrary to start its loading process.
/// The approach that is used to identify a dll path was taking from Alex Short's
/// (rbmm's) excellent ARL project. Please checkout their work as well:
/// https://github.com/rbmm/ARL
/// 
/// For manual mapping, the following requirements are needed:
/// - The dll must not be currently loaded in your process. If it is,
///   LoadLibrary will exit early and return a handle to the already
///   loaded dll.
/// - The dll must not be in KnownDlls. If it is, LoadLibrary will exit
///   early and return the handle in the KnownDlls directory.
/// - The dll should be larger than the mapped in-memory dll and it should
///   not have cfg enabled. Such a dll skips additional post processing
///   that is done in LdrpProcessMappedModule which could be problematic
///   on some Windows releases.
/// This function checks for requirements 1 and 3.
/// 
/// For module doppelgänging, the following requirments are needed:
/// - The effective thread which calls the perfect loader API must be
///   allowed to write to the file. The file's contents will only be
///   modified in memory, but it will be done in a temporary file
///   transaction which will require write access to succeed.
/// - On Windows 11 24H2, you should provide a DLL as the path. On
///   prior Windows releases, any file type may be supplied (ex. a
///   plain text file).
/// This function does not implement these checks.
/// </summary>
std::wstring FindUsableDll(const std::wstring& searchDir, size_t minimumSize) {
    std::wstring usablePath;
    for (auto const& entry : std::filesystem::directory_iterator{ searchDir, std::filesystem::directory_options::skip_permission_denied }) {
        auto path{ entry.path().wstring() };
        if (!entry.path().extension().compare(L".dll") && entry.file_size() >= minimumSize) {
            auto moduleHandle{ GetModuleHandleW(path.data()) };
            if (moduleHandle) {
                continue;
            }
            auto file{ CreateFileW(path.data(), FILE_READ_DATA | SYNCHRONIZE, FILE_SHARE_READ, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr) };
            if (file != INVALID_HANDLE_VALUE) {
                auto map{ CreateFileMappingW(file, nullptr, PAGE_READONLY | SEC_IMAGE, 0, 0, nullptr) };
                if (map) {
                    auto view{ MapViewOfFile(map, FILE_MAP_READ, 0, 0, 0) };
                    if (view) {
                        Pl::Pe pe{ reinterpret_cast<std::byte*>(view) };
                        if (Pl::VerifyImage(pe)) {
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
                        UnmapViewOfFile(view);
                    }
                    CloseHandle(map);
                }
                CloseHandle(file);
            }
        }
        if (usablePath.size()) {
            break;
        }
    }
    return usablePath;
}

std::vector<std::byte> ReadFile(const std::wstring& path) {
    std::ifstream file{ path, std::ios_base::in | std::ios::binary };
    // Get it's size
    file.seekg(0, file.end);
    int size = file.tellg();
    file.seekg(0, file.beg);
    // Then read it
    std::vector<std::byte> bytes(size);
    file.read(reinterpret_cast<char*>(bytes.data()), size);
    bytes.resize(file.tellg());
    return bytes;
}

/// <summary>
/// Demonstrates loading an in-memory library via perfect loader's C++ api.
///
/// Perfect loader's C api offers equivalent functionality. To use the
/// C api, first include perfect_loader.h then call LoadDllFromMemory.
/// Example:
///   LoadDllFromMemory(dllBytes, dllSize, 0, filePath, PL_LOAD_FLAGS_USEHBP, L"");
/// </summary>
int wmain(int argc, wchar_t** argv) {
    if (argc > 1) {
        auto bytes{ ReadFile(argv[1]) };
        auto filePath{ FindUsableDll(L"C:\\Windows\\System32", bytes.size()) };
        auto library{ Pl::LoadLibrary(filePath, bytes, Pl::UseHbp) };
        std::wcout << L"Loaded module at address: 0x" << library << std::endl;
        std::wcout << L"Waiting for user input to exit..." << std::endl;
        (void)std::getchar();
    } else {
        std::wcout << argv[0] << L" <pe to load>" << std::endl;
    }
}