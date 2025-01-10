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
#pragma once
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <winternl.h>

#define LDRP_DONT_CALL_FOR_THREADS 0x00040000
#define STATUS_SUCCESS             0x00000000
#define STATUS_IMAGE_NOT_AT_BASE   0x40000003
#define STATUS_NOT_SUPPORTED       0xC00000BB

namespace Pl {
    // Source: ntmmapi.h from phnt
    typedef enum _MEMORY_INFORMATION_CLASS {
        MemoryBasicInformation,
        MemoryWorkingSetInformation,
        MemoryMappedFilenameInformation,
        MemoryRegionInformation,
        MemoryWorkingSetExInformation,
        MemorySharedCommitInformation,
        MemoryImageInformation,
        MemoryRegionInformationEx,
        MemoryPrivilegedBasicInformation,
        MemoryEnclaveImageInformation,
        MemoryBasicInformationCapped,
        MemoryPhysicalContiguityInformation,
        MemoryBadInformation,
        MemoryBadInformationAllProcesses,
        MemoryImageExtensionInformation,
        MaxMemoryInfoClass
    } MEMORY_INFORMATION_CLASS;

    typedef enum _SECTION_INFORMATION_CLASS {
        SectionBasicInformation,
        SectionImageInformation
        // ...
    } SECTION_INFORMATION_CLASS;

    typedef enum _SECTION_INHERIT {
        ViewShare = 1,
        ViewUnmap = 2
    } SECTION_INHERIT;

    typedef VOID(NTAPI* PLDR_DLL_NOTIFICATION_FUNCTION)(ULONG NotificationReason, PVOID NotificationData, PVOID Context);

    typedef struct _LDR_DATA_TABLE_ENTRY {
        LIST_ENTRY InLoadOrderLinks;
        LIST_ENTRY InMemoryOrderLinks;
        LIST_ENTRY InInitializationOrderLinks;
        PVOID DllBase;
        PVOID EntryPoint;
        ULONG SizeOfImage;
        UNICODE_STRING FullDllName;
        UNICODE_STRING BaseDllName;
        ULONG Flags;
        USHORT LoadCount;
        USHORT TlsIndex;
        union {
            LIST_ENTRY HashLinks;
            struct {
                PVOID SectionPointer;
                ULONG CheckSum;
            };
        };
        // ...
    } LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

    typedef struct _LDRP_DLL_NOTIFICATION_BLOCK {
        LIST_ENTRY Links;
        PLDR_DLL_NOTIFICATION_FUNCTION NotificationFunction;
        PVOID Context;
    } LDRP_DLL_NOTIFICATION_BLOCK, *PLDRP_DLL_NOTIFICATION_BLOCK;

    typedef struct _SECTION_IMAGE_INFORMATION {
        PVOID TransferAddress;
        ULONG ZeroBits;
        SIZE_T MaximumStackSize;
        SIZE_T CommittedStackSize;
        ULONG SubSystemType;
        union {
            struct
            {
                USHORT SubSystemMinorVersion;
                USHORT SubSystemMajorVersion;
            };
            ULONG SubSystemVersion;
        };
        union {
            struct
            {
                USHORT MajorOperatingSystemVersion;
                USHORT MinorOperatingSystemVersion;
            };
            ULONG OperatingSystemVersion;
        };
        USHORT ImageCharacteristics;
        USHORT DllCharacteristics;
        USHORT Machine;
        BOOLEAN ImageContainsCode;
        union {
            UCHAR ImageFlags;
            struct
            {
                UCHAR ComPlusNativeReady : 1;
                UCHAR ComPlusILOnly : 1;
                UCHAR ImageDynamicallyRelocated : 1;
                UCHAR ImageMappedFlat : 1;
                UCHAR BaseBelow4gb : 1;
                UCHAR ComPlusPrefer32bit : 1;
                UCHAR Reserved : 2;
            };
        };
        ULONG LoaderFlags;
        ULONG ImageFileSize;
        ULONG CheckSum;
    } SECTION_IMAGE_INFORMATION, *PSECTION_IMAGE_INFORMATION;

    typedef struct _PEB_LDR_DATA {
        ULONG Length;
        BOOLEAN Initialized;
        HANDLE SsHandle;
        LIST_ENTRY InLoadOrderModuleList;
        LIST_ENTRY InMemoryOrderModuleList;
        LIST_ENTRY InInitializationOrderModuleList;
    } PEB_LDR_DATA, *PPEB_LDR_DATA;

    typedef struct _PEB {
        BOOLEAN InheritedAddressSpace;
        BOOLEAN ReadImageFileExecOptions;
        BOOLEAN BeingDebugged;
        union {
            UCHAR BitField;
            struct
            {
                UCHAR ImageUsesLargePages : 1;
                UCHAR IsProtectedProcess : 1;
                UCHAR IsImageDynamicallyRelocated : 1;
                UCHAR SkipPatchingUser32Forwarders : 1;
                UCHAR IsPackagedProcess : 1;
                UCHAR IsAppContainer : 1;
                UCHAR IsProtectedProcessLight : 1;
                UCHAR SpareBits : 1;
            };
        };
        HANDLE Mutant;
        PVOID ImageBaseAddress;
        Pl::PPEB_LDR_DATA Ldr;
        // ...
    } PEB, *PPEB;
    
    /// <summary>
    /// The protected policy guid for RtlpAddVectoredHandler. The policy guid was
    /// first documented by redplait and its use when performing a VEH based hook
    /// was first demonstrated by Alex Short's (rbmm's) ARL project.
    /// 
    /// Protected policies were introduced in NT 6.3. They allow software to
    /// dynamically enable or disable a GUID identified policy for the current
    /// process which other software may query the value of and handle as needed.
    /// 
    /// The RtlpAddVectoredHandler policy sets whether VEH registration should be
    /// disabled within the current process. That may be seen in its use within
    /// eShims.dll. Some Microsoft software will identify uses of VEH and report
    /// an error if the RtlpAddVectoredHandler policy is enabled. Disabling this
    /// policy will allow VEH based hooking to be used without errors being
    /// reported by such software.
    /// 
    /// Sources:
    /// https://redplait.blogspot.com/2017/04/ntdll-protectedpolicies.html
    /// https://github.com/rbmm/ARL
    /// </summary>
    struct DECLSPEC_UUID("1FC98BCA-1BA9-4397-93F9-349EAD41E057") RtlpAddVectoredHandler;

    [[maybe_unused]] NTSTATUS NTAPI LdrLockLoaderLock(ULONG Flags, ULONG* State, SIZE_T* Cookie);
    [[maybe_unused]] NTSTATUS NTAPI LdrRegisterDllNotification(ULONG Flags, PLDR_DLL_NOTIFICATION_FUNCTION NotificationFunction, PVOID Context, PVOID* Cookie);
    [[maybe_unused]] NTSTATUS NTAPI LdrUnlockLoaderLock(ULONG Flags, SIZE_T Cookie);
    [[maybe_unused]] NTSTATUS NTAPI LdrUnregisterDllNotification(PVOID Cookie);
    [[maybe_unused]] NTSTATUS NTAPI NtCreateSection(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PLARGE_INTEGER MaximumSize, ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle);
    [[maybe_unused]] NTSTATUS NTAPI NtManageHotPatch(ULONG Operation, PVOID SubmitBuffer, ULONG SubmitBufferLength, NTSTATUS* OperationStatus);
    [[maybe_unused]] NTSTATUS NTAPI NtMapViewOfSection(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Win32Protect);
    [[maybe_unused]] NTSTATUS NTAPI NtQuerySection(HANDLE SectionHandle, SECTION_INFORMATION_CLASS SectionInformationClass, PVOID SectionInformation, SIZE_T SectionInformationLength, PSIZE_T ReturnLength);
    [[maybe_unused]] NTSTATUS NTAPI NtQueryVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength);
    [[maybe_unused]] NTSTATUS NTAPI RtlGetVersion(PRTL_OSVERSIONINFOW lpVersionInformation);
    [[maybe_unused]] BOOL NTAPI RtlSetCurrentTransaction(HANDLE Transaction);
    [[maybe_unused]] NTSTATUS NTAPI RtlSetProtectedPolicy(const GUID* PolicyGuid, SIZE_T PolicyValue, PSIZE_T OldPolicyValue);
}