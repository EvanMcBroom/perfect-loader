#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include "perfect_loader.h"
#include <cstddef>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <vector>

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
/// Demonstrates loading an in-memory library via perfect loader's C api.
/// 
/// Perfect loader's C++ api offers equivalent functionality. To use the
/// C++ api, first include perfect_loader.hpp then call Pl::LoadLibrary.
/// Example:
///   Pl::LoadLibrary(fileName, bytes, Pl::UseHbp);
/// </summary>
int wmain(int argc, wchar_t** argv) {
    if (argc > 1) {
        std::wstring fileName{ L"C:\\Windows\\System32\\AppVTerminator.dll" };
        auto bytes{ ReadFile(argv[1]) };
        auto library = LoadDllFromMemory(bytes.data(), bytes.size(), 0, fileName.data(), PL_LOAD_FLAGS_USEHBP, L"");
        std::wcout << L"Loaded module at address: 0x" << library << std::endl;
        std::wcout << L"Waiting for user input to exit..." << std::endl;
        std::getchar();
    } else {
        std::wcout << argv[0] << L" <pe to load>" << std::endl;
    }
}