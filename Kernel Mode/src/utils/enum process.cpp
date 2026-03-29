#include <includes.h>

HANDLE GetPidFromProcessName(const UNICODE_STRING* processName) {
    NTSTATUS status;
    ULONG bufferSize = 0;
    PVOID buffer = NULL;

    status = ntoskrnl::ZwQuerySystemInformation(SystemProcessInformation, NULL, 0, &bufferSize);
    if (status != STATUS_INFO_LENGTH_MISMATCH)
        return NULL;

    buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, bufferSize, DRIVER_TAG);
    if (!buffer)
        return NULL;

    status = ntoskrnl::ZwQuerySystemInformation(SystemProcessInformation, buffer, bufferSize, &bufferSize);
    if (!NT_SUCCESS(status))
    {
        ExFreePoolWithTag(buffer, DRIVER_TAG);
        return NULL;
    }

    PSYSTEM_PROCESS_INFORMATION pCurrent = (PSYSTEM_PROCESS_INFORMATION)buffer;

    while (TRUE) {
        if (pCurrent->ImageName.Buffer) {
            if (RtlEqualUnicodeString(&pCurrent->ImageName, processName, TRUE)) {
                HANDLE pid = pCurrent->ProcessId;
                ExFreePoolWithTag(buffer, DRIVER_TAG);
                return pid;
            }
        }

        if (pCurrent->NextEntryOffset == 0)
            break;

        pCurrent = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)pCurrent + pCurrent->NextEntryOffset);
    }

    ExFreePoolWithTag(buffer, DRIVER_TAG);
    return NULL;
}