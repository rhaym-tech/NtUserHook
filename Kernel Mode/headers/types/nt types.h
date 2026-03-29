#pragma once
#include <ntddk.h>

#define DRIVER_TAG 'EFN'
typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER Reserved[3];
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    ULONG BasePriority;
    HANDLE ProcessId;
    HANDLE InheritedFromProcessId;
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation = 0,
    SystemPerformanceInformation = 2,
    SystemTimeOfDayInformation = 3,
    SystemProcessInformation = 5,
    SystemProcessorPerformanceInformation = 8,
    SystemInterruptInformation = 23,
    SystemExceptionInformation = 33,
    SystemRegistryQuotaInformation = 37,
    SystemLookasideInformation = 45,
    SystemCodeIntegrityInformation = 103,
    SystemPolicyInformation = 134,
} SYSTEM_INFORMATION_CLASS;

typedef struct _EPROCESS_EXTENDED {
    UCHAR Reserved[0x448];
    LIST_ENTRY ActiveProcessLinks;
} EPROCESS_EXTENDED, * PEPROCESS_EXTENDED;
typedef HANDLE HBITMAP;

// ntoskrnl types:
typedef LONG_PTR    (*ObfDereferenceObject_t)          (PVOID Object);
typedef NTSTATUS    (*ZwQuerySystemInformation_t)      (SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
typedef NTSTATUS    (*PsLookupProcessByProcessId_t)    (HANDLE ProcessId, PEPROCESS* Process);

typedef VOID    (*KeStackAttachProcess_t)   (PRKPROCESS PROCESS, PRKAPC_STATE ApcState);
typedef VOID    (*KeUnstackDetachProcess_t) (PRKAPC_STATE ApcState);

// win32k types:
typedef PVOID (__fastcall * NtUserGetPointerProprietaryId_t) (UINT32 magic, PVOID buffer);
typedef PVOID (*W32GetSessionState_t)();