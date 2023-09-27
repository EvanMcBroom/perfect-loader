#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include "perfect_loader.hpp"
#include <cstddef>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <iterator>

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

int wmain(int argc, wchar_t** argv) {
    if (argc > 1) {
        std::wstring fileName{ L"C:\\Program Files (x86)\\Windows Defender\\MpClient.dll" };
        auto bytes{ ReadFile(argv[1]) };
        auto library = Pl::LoadLibrary(fileName, bytes, Pl::UseHbp);
        std::wcout << L"Loaded module at address: 0x" << library << std::endl;
        Sleep(5000);
    } else {
        std::wcout << argv[0] << L" <pe to load>" << std::endl;
    }
}