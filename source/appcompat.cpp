#define UNICODE
#include "perfect_loader.hpp"

namespace Pl {
    ULONGLONG GetNtdllVersion() {
        auto ntdll{ GetModuleHandleW(L"ntdll.dll") };
        if (ntdll) {
            auto hResource{ FindResourceW(ntdll, MAKEINTRESOURCEW(VS_VERSION_INFO), RT_VERSION) };
            if (hResource) {
                auto gResource{ LoadResource(ntdll, hResource) };
                auto verHead{ reinterpret_cast<VERHEAD*>(LockResource(gResource)) };
                return (ULONGLONG(verHead->vsf.dwFileVersionMS) << 32) | verHead->vsf.dwFileVersionLS;
            }
        }
        return 0;
    }

    bool IsHotPatchingEnabled() {
        PL_LAZY_LOAD_NATIVE_PROC(NtManageHotPatch);
        if (LazyNtManageHotPatch) {
            MANAGE_HOT_PATCH_CHECK_ENABLED information;
            information.Version = 1;
            information.Flags = 0;
            ULONG returnLength{ 0 };
            auto status{ LazyNtManageHotPatch(ManageHotPatchCheckEnabled, &information, sizeof(information), &returnLength) };
            if (status != STATUS_NOT_IMPLEMENTED && status != STATUS_NOT_SUPPORTED) {
                return true;
            }
        }
        return false;
    }

}