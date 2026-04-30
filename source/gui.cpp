#define NOMINMAX
#define UNICODE
#include "backends/imgui_impl_dx11.h"
#include "backends/imgui_impl_win32.h"
#include "imgui.h"
#include "misc/cpp/imgui_stdlib.h"
#include "perfect_loader.hpp"
#include "pl/mmap.hpp"
#include <algorithm>
#include <codecvt>
#include <commdlg.h>
#include <d3d11.h>
#include <filesystem>
#include <fstream>
#include <locale>
#include <sstream>
#include <string>
#include <tchar.h>
#include <vector>

class Gui {
public:
    void Close();
    void Open();
    bool Run(HINSTANCE instance, int cmdShow);

private:
    enum class LoadMethod {
        ManualMapping = 0,
        ModuleDoppelganging,
        SectionHollowing
    };

    enum class HookMethod {
        Detour = 0,
        HardwareBreakpoint,
#if defined(_M_AMD64) && !defined(_M_ARM64EC)
        Nirvana
#endif
    };

    struct ModuleInfo {
        std::wstring baseFileName;
        HMODULE loadAddress{ nullptr };
    };

    // Helper functions to use DirectX11
    bool CreateDeviceD3D(HWND hWnd);
    void CreateRenderTarget();
    void CleanupDeviceD3D();
    void CleanupRenderTarget();

    // Window message pump dispatch routine
    static LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

    DWORD BuildLoadFlags();
    bool Draw();
    void DrawWindow();
    void Load();

    bool isOpen{ true };
    LoadMethod loadMethod{ LoadMethod::ManualMapping };
    HookMethod hookMethod{ HookMethod::Detour };

    // Pre/post processing flags
    bool autoPickHostFile{ true };
    bool overwriteHeaders{ false };
    bool removeDllNotifications{ false };
    bool removeHeaders{ false };
    bool removeNirvanaCallbacks{ false };
    bool removeVeh{ false };
    bool unlinkModule{ false };

    std::wstring libraryPath;
    std::wstring hostDllPath;
    std::wstring moduleListName;
    std::wstring statusText{ L"Ready." };
    HMODULE loadedModule{ nullptr };
    std::vector<ModuleInfo> loadedModules;

    HWND window{ nullptr };
    ID3D11Device* d3dDevice{ nullptr };
    ID3D11DeviceContext* d3dDeviceContext{ nullptr };
    IDXGISwapChain* swapChain{ nullptr };
    ID3D11RenderTargetView* mainRenderTargetView{ nullptr };
};

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
extern "C" IMAGE_DOS_HEADER __ImageBase;

inline auto UtfConverter() {
    return std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>>();
}

inline std::wstring Utf16(const std::string& utf8) {
    return UtfConverter().from_bytes(utf8);
}

inline std::string Utf8(const std::wstring& utf16) {
    return UtfConverter().to_bytes(utf16);
}

std::wstring BrowseForFile(HWND owner, const wchar_t* filter);
std::wstring FindUsableDll(const std::wstring& searchDir);
std::vector<std::byte> ReadFileBytes(const std::wstring& filePath);

namespace {
    Gui* gGuiInstance = nullptr;
}

void Gui::Close() {
    isOpen = false;
}

void Gui::Open() {
    isOpen = true;
}

bool Gui::Run(HINSTANCE instance, int cmdShow) {
    gGuiInstance = this;

    // Setup window
    WNDCLASSEXW windowClass = {
        sizeof(windowClass), CS_CLASSDC, WndProc, 0, 0, HINSTANCE(&__ImageBase),
        LoadIcon(HINSTANCE(&__ImageBase), MAKEINTRESOURCE(101)), // ICON_GEAR_SOLID
        nullptr, nullptr, nullptr, L"PerfectLoaderGuiWindowClass", nullptr
    };
    RegisterClassExW(&windowClass);

    // Define the WS_OVERLAPPEDWINDOW style minus WS_THICKFRAME to prevent window resizing
    window = CreateWindowExW(0, windowClass.lpszClassName, L"Perfect Loader", WS_OVERLAPPEDWINDOW, 100, 100, 600, 500, nullptr, nullptr, windowClass.hInstance, nullptr);
    
    // Initialize Direct3D
    if (!CreateDeviceD3D(window)) {
        CleanupDeviceD3D();
        UnregisterClassW(windowClass.lpszClassName, windowClass.hInstance);
        return false;
    }
    ShowWindow(window, cmdShow);
    UpdateWindow(window);

    // Setup Dear ImGui context
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGui::StyleColorsDark();

    // Setup Direct3D11 backend
    ImGui_ImplWin32_Init(window);
    ImGui_ImplDX11_Init(d3dDevice, d3dDeviceContext);

    // Main loop
    while (Draw()) {
    }

    // Cleanup
    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
    CleanupDeviceD3D();
    DestroyWindow(window);
    UnregisterClassW(windowClass.lpszClassName, windowClass.hInstance);
    return true;
}

bool Gui::CreateDeviceD3D(HWND hWnd) {
    // Setup swap chain
    DXGI_SWAP_CHAIN_DESC swapChainDesc = {};
    swapChainDesc.BufferCount = 2;
    swapChainDesc.BufferDesc.Width = 0;
    swapChainDesc.BufferDesc.Height = 0;
    swapChainDesc.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    swapChainDesc.BufferDesc.RefreshRate.Numerator = 60;
    swapChainDesc.BufferDesc.RefreshRate.Denominator = 1;
    swapChainDesc.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
    swapChainDesc.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    swapChainDesc.OutputWindow = hWnd;
    swapChainDesc.SampleDesc.Count = 1;
    swapChainDesc.SampleDesc.Quality = 0;
    swapChainDesc.Windowed = TRUE;
    swapChainDesc.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

    // Create device
    UINT createDeviceFlags = 0;
    D3D_FEATURE_LEVEL featureLevel;
    const D3D_FEATURE_LEVEL featureLevelArray[2] = { D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0 };
    auto result{ D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, createDeviceFlags, featureLevelArray, 2, D3D11_SDK_VERSION, &swapChainDesc, &swapChain, &d3dDevice, &featureLevel, &d3dDeviceContext) };
    if (result == DXGI_ERROR_UNSUPPORTED) { // Try high-performance WARP software driver if hardware is not available.
        result = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_WARP, nullptr, createDeviceFlags, featureLevelArray, 2, D3D11_SDK_VERSION, &swapChainDesc, &swapChain, &d3dDevice, &featureLevel, &d3dDeviceContext);
    }
    if (result == S_OK) {
        CreateRenderTarget();
        return true;
    }
    return false;
}

void Gui::CreateRenderTarget() {
    ID3D11Texture2D* backBuffer;
    (void)swapChain->GetBuffer(0, IID_PPV_ARGS(&backBuffer));
    d3dDevice->CreateRenderTargetView(backBuffer, nullptr, &mainRenderTargetView);
    backBuffer->Release();
}

void Gui::CleanupDeviceD3D() {
    CleanupRenderTarget();
    if (swapChain) {
        swapChain->Release();
        swapChain = nullptr;
    }
    if (d3dDeviceContext) {
        d3dDeviceContext->Release();
        d3dDeviceContext = nullptr;
    }
    if (d3dDevice) {
        d3dDevice->Release();
        d3dDevice = nullptr;
    }
}

void Gui::CleanupRenderTarget() {
    if (mainRenderTargetView) {
        mainRenderTargetView->Release();
        mainRenderTargetView = nullptr;
    }
}

DWORD Gui::BuildLoadFlags() {
    DWORD flags{ Pl::RedirectorFlags::NoFlags };
    if (loadMethod == LoadMethod::ModuleDoppelganging) {
        flags |= Pl::RedirectorFlags::UseTxf;
    }
    if (loadMethod == LoadMethod::SectionHollowing) {
        flags |= Pl::RedirectorFlags::UseSec;
    }
    if (hookMethod == HookMethod::HardwareBreakpoint) {
        flags |= Pl::RedirectorFlags::UseHbp;
    }
#if defined(_M_AMD64) && !defined(_M_ARM64EC)
    if (hookMethod == HookMethod::Nirvana) {
        flags |= Pl::RedirectorFlags::UsePic;
    }
#endif
    return flags;
}

bool Gui::Draw() {
    // Main window message pump
    MSG msg;
    while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
        if (msg.message == WM_QUIT) {
            return false;
        }
    }

    // Start the Dear ImGui frame
    ImGui_ImplDX11_NewFrame();
    ImGui_ImplWin32_NewFrame();
    ImGui::NewFrame();
    DrawWindow();

    // Rendering
    ImGui::Render();
    const float clearColor[4] = { 0.10f, 0.10f, 0.10f, 1.00f };
    d3dDeviceContext->OMSetRenderTargets(1, &mainRenderTargetView, nullptr);
    d3dDeviceContext->ClearRenderTargetView(mainRenderTargetView, clearColor);
    ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
    swapChain->Present(1, 0);
    return isOpen;
}

void Gui::DrawWindow() {
    // Set the Dear ImGui window to fill the OS window
    ImGui::SetNextWindowPos(ImVec2(0.0f, 0.0f));
    ImGui::SetNextWindowSize(ImGui::GetIO().DisplaySize);
    // Draw the Dear ImGui window
    if (ImGui::Begin("Perfect Loader", &isOpen, ImGuiWindowFlags_NoDecoration)) {
        const float buttonWidth{ 90.0f };

        // First line
        ImGui::TextUnformatted("Library");
        ImGui::SameLine();
        ImGui::SetNextItemWidth(std::max(1.0f, ImGui::GetContentRegionAvail().x - ImGui::GetStyle().ItemSpacing.x - buttonWidth));
        std::string libraryPathInput{ Utf8(libraryPath) };
        if (ImGui::InputText("##library", &libraryPathInput)) {
            libraryPath = Utf16(libraryPathInput);
        }
        ImGui::SameLine();
        if (ImGui::Button("Browse##library", { buttonWidth, 0.0f })) {
            auto path = BrowseForFile(window, L"DLL Files\0*.dll\0All Files\0*.*\0");
            if (!path.empty()) {
                libraryPath = path;
            }
        }

        // Separator and next line
        ImGui::Separator();
        ImGui::TextUnformatted("Load method");
        ImGui::SameLine();
        ImGui::SetNextItemWidth(-1);
        const char* loadMethods[] = {
            "Manual mapping",
            "Module doppelganging",
            "Section hollowing"
        };
        auto loadMethodIndex{ static_cast<int>(loadMethod) };
        if (ImGui::Combo("##loadMethod", &loadMethodIndex, loadMethods, IM_ARRAYSIZE(loadMethods))) {
            loadMethod = static_cast<LoadMethod>(loadMethodIndex);
        }

        // Next line
        ImGui::TextUnformatted("Hook method");
        ImGui::SameLine();
        ImGui::SetNextItemWidth(-1);
        const char* hookMethods[] = {
            "Detour patching",
            "Hardware breakpoints",
#if defined(_M_AMD64) && !defined(_M_ARM64EC)
            "Nirvana"
#endif
        };
        auto hookMethodIndex = static_cast<int>(hookMethod);
        if (ImGui::Combo("##hookMethod", &hookMethodIndex, hookMethods, IM_ARRAYSIZE(hookMethods))) {
            hookMethod = static_cast<HookMethod>(hookMethodIndex);
        }

        // Next line
        ImGui::Checkbox("Auto-pick host file from C:\\Windows\\System32", &autoPickHostFile);

        // Next line
        if (!autoPickHostFile) {
            ImGui::TextUnformatted("Host file");
            ImGui::SameLine();
            ImGui::SetNextItemWidth(std::max(1.0f, ImGui::GetContentRegionAvail().x - ImGui::GetStyle().ItemSpacing.x - buttonWidth));
            std::string hostDllPathInput{ Utf8(hostDllPath) };
            if (ImGui::InputText("##hostDllPath", &hostDllPathInput)) {
                hostDllPath = Utf16(hostDllPathInput);
            }
            ImGui::SameLine();
            if (ImGui::Button("Browse##hostDllPath", { buttonWidth, 0.0f })) {
                auto path = BrowseForFile(window, L"DLL Files\0*.dll\0All Files\0*.*\0");
                if (!path.empty()) {
                    hostDllPath = path;
                    autoPickHostFile = false;
                }
            }
        }

        // Next line
        if (loadMethod == LoadMethod::ModuleDoppelganging) {
            ImGui::TextUnformatted("Module list name (optional)");
            ImGui::SameLine();
            ImGui::SetNextItemWidth(-1);
            std::string moduleListNameInput{ Utf8(moduleListName) };
            if (ImGui::InputText("##modListName", &moduleListNameInput)) {
                moduleListName = Utf16(moduleListNameInput);
            }
        }

        // Processing flags area
        if (ImGui::CollapsingHeader("Pre/post processing flags", ImGuiTreeNodeFlags_DefaultOpen)) {
            ImGui::Checkbox("Overwrite headers with host file after load", &overwriteHeaders);
            ImGui::Checkbox("Remove DLL notifications before load", &removeDllNotifications);
            ImGui::Checkbox("Remove headers after load", &removeHeaders);
            ImGui::Checkbox("Remove process instrumentation callbacks before load", &removeNirvanaCallbacks);
            ImGui::Checkbox("Remove vectored exception handlers before load", &removeVeh);
            ImGui::Checkbox("Unlink from module list after load", &unlinkModule);
        }

        // Load area: load button and status line
        ImGui::Separator();
        if (ImGui::Button("Load", { -1, 0 })) {
            Load();
        }
        ImGui::Spacing();
        ImGui::TextWrapped("%ls", statusText.c_str());
        ImGui::Separator();

        // Loaded modules table
        loadedModules.erase(std::remove_if(loadedModules.begin(), loadedModules.end(), [](const auto& library) {
            return GetModuleHandleW(library.baseFileName.c_str()) == nullptr;
        }),
            loadedModules.end());
        ImGui::TextUnformatted("Loaded modules");
        if (ImGui::BeginTable("LoadedModules", 3, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_SizingStretchProp)) {
            ImGui::TableSetupColumn("File name", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableSetupColumn("Base address", ImGuiTableColumnFlags_WidthFixed, 150.0f);
            ImGui::TableSetupColumn("Actions", ImGuiTableColumnFlags_WidthFixed, buttonWidth + ImGui::GetStyle().ItemSpacing.x * 2);
            ImGui::TableHeadersRow();

            for (size_t i{ 0 }; i < loadedModules.size();) {
                auto& library = loadedModules[i];

                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                ImGui::Text("%ls", library.baseFileName.c_str());

                ImGui::TableSetColumnIndex(1);
                ImGui::Text("0x%p", library.loadAddress);

                ImGui::TableSetColumnIndex(2);
                std::string buttonId = "Free##" + std::to_string(i);
                bool removeRow = false;
                if (ImGui::Button(buttonId.c_str(), { -1, 0 })) {
                    if (library.loadAddress && FreeLibrary(library.loadAddress)) {
                        removeRow = true;
                    } else {
                        statusText = L"FreeLibrary failed.";
                    }
                }

                if (removeRow) {
                    loadedModules.erase(loadedModules.begin() + static_cast<ptrdiff_t>(i));
                } else {
                    ++i;
                }
            }
            ImGui::EndTable();
        }
    }
    ImGui::End();
}

void Gui::Load() {
    if (libraryPath.empty()) {
        statusText = L"Select a library to load.";
        return;
    }
#if defined(_M_AMD64) && !defined(_M_ARM64EC)
    if (loadMethod != Gui::LoadMethod::ManualMapping && hookMethod == HookMethod::Nirvana) {
        statusText = L"Nirvana is currently only implemented for the manual mapping load method.";
        return;
    }
#endif

    auto bytes{ ReadFileBytes(libraryPath) };
    if (bytes.empty()) {
        statusText = L"Reading the library failed or the library is empty.";
        return;
    }

    std::wstring selectedHostFile{ hostDllPath };
    if (autoPickHostFile || selectedHostFile.empty()) {
        std::vector<wchar_t> filePath(MAX_PATH, L'\0');
        auto loadFlags{ BuildLoadFlags() };
        auto librarySize{ std::filesystem::file_size(libraryPath) };
        auto result{ FindUsableHostDll(L"C:\\Windows\\System32", loadFlags, librarySize, filePath.data(), filePath.size() * sizeof(wchar_t)) };
        if (result && !filePath.empty()) {
            selectedHostFile = std::wstring{ filePath.data() };
        }
    }
    if (selectedHostFile.empty()) {
        statusText = L"Could not find a usable host file path.";
        return;
    }

    // Pre-processing steps
    if (removeDllNotifications) {
        Pl::RemoveDllNotifications();
    }
    if (removeNirvanaCallbacks) {
        Pl::RemoveNirvanaCallbacks();
    }
    if (removeVeh) {
        Pl::RemoveVectoredExceptionHandlers();
    }

    // Load the library
    auto flags{ BuildLoadFlags() };
    loadedModule = Pl::LoadLibrary(selectedHostFile, bytes, flags, moduleListName);
    if (!loadedModule) {
        std::wstringstream status;
        status << L"Load failed. LastError=" << GetLastError();
        statusText = status.str();
        return;
    }

    std::wstringstream status;
    status << L"Loaded module at 0x" << loadedModule;
    statusText = status.str();

    auto loadedBaseName{
        (!moduleListName.empty()) ? std::filesystem::path(moduleListName).filename().wstring() : std::filesystem::path(selectedHostFile).filename().wstring()
    };

    auto existing = std::find_if(loadedModules.begin(), loadedModules.end(), [&loadedBaseName](const auto& item) {
        return _wcsicmp(item.baseFileName.c_str(), loadedBaseName.c_str()) == 0;
    });
    if (existing != loadedModules.end()) {
        existing->loadAddress = loadedModule;
    } else {
        loadedModules.push_back({ loadedBaseName, loadedModule });
    }

    // Post-processing steps
    if (overwriteHeaders) {
        auto cookie{ Pl::LockLoaderLock() };
        if (cookie) {
            auto peBase{ reinterpret_cast<std::byte*>(loadedModule) };
            auto ldrDataTableEntry{ Pl::GetLdrDataTableEntry(peBase) };
            (void)Pl::OverwriteHeaders(peBase, std::wstring{ ldrDataTableEntry->FullDllName.Buffer });
            (void)Pl::UnlockLoaderLock(cookie);
        }
    }
    if (removeHeaders) {
        Pl::RemoveHeaders(reinterpret_cast<std::byte*>(loadedModule));
    }
    if (unlinkModule) {
        Pl::UnlinkModule(reinterpret_cast<std::byte*>(loadedModule));
    }
}

LRESULT WINAPI Gui::WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam)) {
        return true;
    }
    switch (msg) {
    case WM_SIZE:
        if (gGuiInstance && gGuiInstance->d3dDevice != nullptr && wParam != SIZE_MINIMIZED) {
            gGuiInstance->CleanupRenderTarget();
            gGuiInstance->swapChain->ResizeBuffers(0, (UINT)LOWORD(lParam), (UINT)HIWORD(lParam), DXGI_FORMAT_UNKNOWN, 0);
            gGuiInstance->CreateRenderTarget();
        }
        return 0;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    default:
        return DefWindowProcW(hWnd, msg, wParam, lParam);
    }
}

std::wstring BrowseForFile(HWND owner, const wchar_t* filter) {
    wchar_t pathBuffer[MAX_PATH] = { 0 };
    OPENFILENAMEW openFileName = {};
    openFileName.lStructSize = sizeof(openFileName);
    openFileName.hwndOwner = owner;
    openFileName.lpstrFile = pathBuffer;
    openFileName.nMaxFile = MAX_PATH;
    openFileName.lpstrFilter = filter;
    openFileName.nFilterIndex = 1;
    openFileName.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
    if (GetOpenFileNameW(&openFileName)) {
        return pathBuffer;
    }
    return L"";
}

std::vector<std::byte> ReadFileBytes(const std::wstring& filePath) {
    std::ifstream file{ filePath, std::ios::binary };
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

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int cmdShow) {
    Gui gui;
    gui.Open();
    return gui.Run(instance, cmdShow);
}