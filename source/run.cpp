#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include "perfect_loader.hpp"
#include <cstddef>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <vector>

std::vector<std::byte> ReadFile(const std::wstring& path) {
    std::ifstream file{ path, std::ios::binary };
    if (file) {
        file.seekg(0, std::ios::end);
        const auto size{ file.tellg() };
        if (size > 0) {
            file.seekg(0, std::ios::beg);
            std::vector<std::byte> bytes(static_cast<size_t>(size));
            file.read(reinterpret_cast<char*>(bytes.data()), size);
            bytes.resize(static_cast<size_t>(file.gcount()));
            return bytes;
        }
    }
    return {};
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
        if (!bytes.empty()) {
            std::vector<wchar_t> filePath(MAX_PATH, L'\0');
            auto result{ FindUsableHostDll(L"C:\\Windows\\System32", PL_LOAD_FLAGS_USEHBP, bytes.size(), filePath.data(), filePath.size() * sizeof(wchar_t)) };
            if (result && !filePath.empty()) {
                // Test pre-load evasions
                Pl::RemoveDllNotifications();
                // Load the library
                auto library{ Pl::LoadLibrary(filePath.data(), bytes, Pl::UseHbp) };
                // Test select post-load evasions
                // Attempt to overwrite the file using the DLL name from the loader data table entry.
                // If filePath for Pl::LoadLibrary was an API set, the loader will resolve that to a
                // file path and store that file path in the ldr data table entry.
                auto cookie{ Pl::LockLoaderLock() };
                if (cookie) {
                    auto peBase{ reinterpret_cast<std::byte*>(library) };
                    auto ldrDataTableEntry{ Pl::GetLdrDataTableEntry(peBase) };
                    (void)Pl::OverwriteHeaders(peBase, std::wstring{ ldrDataTableEntry->FullDllName.Buffer });
                    (void)Pl::UnlockLoaderLock(cookie);
                }
                std::wcout << L"Loaded module at address: 0x" << library << std::endl;
                std::wcout << L"Waiting for user input to exit..." << std::endl;
                (void)std::getchar();
            } else {
                std::wcerr << L"Could not find a usable path to pass to LoadLibrary." << std::endl;
            }
        } else {
            std::wcerr << L"Could not read the file to load." << std::endl;
        }
    } else {
        std::wcout << argv[0] << L" <pe to load>" << std::endl;
    }
}