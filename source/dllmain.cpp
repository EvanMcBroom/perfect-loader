#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

DWORD WINAPI CreateMessageBox(LPVOID lpParam) {
    return MessageBoxW(nullptr, L"Library loaded successfully.", L"Test Dll", MB_ICONINFORMATION | MB_OK);
}

DWORD WINAPI DllMain(HINSTANCE hInstance, DWORD dwReason, LPVOID lpReserved) {
    switch (dwReason) {
    case DLL_PROCESS_ATTACH:
        CreateThread(0, 0, CreateMessageBox, 0, 0, 0);
        break;
    default:
        break;
    }
    return TRUE;
}