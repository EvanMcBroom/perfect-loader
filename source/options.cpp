#define UNICODE
#include "perfect_loader.hpp"
    
namespace {
    LONG NTAPI VehHandler(struct _EXCEPTION_POINTERS*) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
}

namespace Pl {
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
                    (void)ReadFile(file, peBase + totalBytesRead, sizeOfHeaders - totalBytesRead, &bytesRead, nullptr);
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
        // Register a temporary callback to obtain an entry in the notification list.
        PL_LAZY_LOAD_NATIVE_PROC(LdrRegisterDllNotification);
        auto callback{ [](ULONG NotificationReason, PVOID NotificationData, PVOID Context) {} };
        PLDRP_DLL_NOTIFICATION_BLOCK initialBlock;
        if (NT_SUCCESS(LazyLdrRegisterDllNotification(0, callback, nullptr, reinterpret_cast<PVOID*>(&initialBlock)))) {
            // Snapshot the circular notification list while the loader lock is held.
            std::vector<PLDRP_DLL_NOTIFICATION_BLOCK> notificationBlocks;
            auto cookie{ LockLoaderLock() };
            if (cookie) {
                auto iter{ initialBlock };
                do {
                    notificationBlocks.emplace_back(iter);
                    iter = reinterpret_cast<PLDRP_DLL_NOTIFICATION_BLOCK>(iter->Links.Flink);
                } while (iter != initialBlock);
                (void)UnlockLoaderLock(cookie);
                // Unregister each callback captured in the snapshot.
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

    bool RemoveNirvanaCallbacks() {
#if defined(_M_AMD64) && !defined(_M_ARM64EC)
        PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION picInfo;
        picInfo.Callback = nullptr;
        picInfo.Version = 0;
        picInfo.Reserved = 0;
        PL_LAZY_LOAD_NATIVE_PROC(NtSetInformationProcess);
        return NT_SUCCESS(LazyNtSetInformationProcess(GetCurrentProcess(), ProcessInstrumentationCallback, &picInfo, sizeof(picInfo)));
#else
        return true;
#endif
    }

    bool RemoveVectoredExceptionHandlers() {
        PL_LAZY_LOAD_NATIVE_PROC(RtlAddVectoredExceptionHandler);
        bool succeeded{ false };
        auto vehHandle{ LazyRtlAddVectoredExceptionHandler(TRUE, reinterpret_cast<PVECTORED_EXCEPTION_HANDLER>(VehHandler)) };
        if (vehHandle) {
            auto target{ LPVOID(PLIST_ENTRY(vehHandle)->Flink) };
            std::byte* ntdll;
            if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, L"ntdll.dll", (HMODULE*)&ntdll)) {
                Pe pe{ ntdll };
                auto sectionCount{ pe.PeHeader()->NumberOfSections };
                auto sizeOfHeaders{ (reinterpret_cast<const std::byte*>(pe.SectionHeaders()) - ntdll) + (sizeof(IMAGE_SECTION_HEADER) * sectionCount) };
                bool found{ false };
                for (size_t index{ 0 }; !found && index < sectionCount; index++) {
                    auto sectionHeader{ pe.SectionHeaders()[index] };
                    if (!std::string(".data").compare(reinterpret_cast<const char*>(sectionHeader.Name))) {
                        auto dataAddress{ ntdll + sectionHeader.VirtualAddress };
                        auto dataSize{ sectionHeader.Misc.VirtualSize };
                        while (target != vehHandle) {
                            if (target >= dataAddress && target <= ((PVOID*)dataAddress + dataSize)) {
                                found = true;
                                break;
                            }
                            target = LPVOID(PLIST_ENTRY(target)->Flink);
                        }
                    }
                }
            }
            PL_LAZY_LOAD_NATIVE_PROC(RtlRemoveVectoredExceptionHandler);
            LazyRtlRemoveVectoredExceptionHandler(vehHandle);
            auto ldrpVectorHandlerList{ PLIST_ENTRY(target) };
            while (ldrpVectorHandlerList->Flink != ldrpVectorHandlerList) {
                LazyRtlRemoveVectoredExceptionHandler(ldrpVectorHandlerList->Flink);
            }
            succeeded = true;
        }
        return succeeded;
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