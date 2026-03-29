#include "kernel_comm.h"
#include <Windows.h>
#include <stdlib.h>

struct _KernelComm {
    PVOID(__fastcall* NtUserGetPointerProprietaryId)(uint32_t, void*);
    int initialized;
};

KernelComm* KernelComm_Create(void) {
    KernelComm* h = (KernelComm*)malloc(sizeof(KernelComm));
    if (!h) return NULL;
    h->NtUserGetPointerProprietaryId = NULL;
    h->initialized = 0;
    return h;
}

void KernelComm_Destroy(KernelComm* handle) {
    if (!handle) return;
    free(handle);
}

int KernelComm_Initialize(KernelComm* handle) {
    if (!handle) return 0;
    MSG msg;
    PeekMessageW(&msg, NULL, 0, 0, PM_NOREMOVE);

    HMODULE hWin32u = LoadLibraryW(L"win32u.dll");
    if (!hWin32u) return 0;
    handle->NtUserGetPointerProprietaryId =
        (PVOID(__fastcall*)(uint32_t, void*))GetProcAddress(
            hWin32u, "NtUserGetPointerProprietaryId");
    if (!handle->NtUserGetPointerProprietaryId) return 0;

    handle->initialized = 1;
    return 1;
}

int KernelComm_SendCommand(KernelComm* handle, Operation op, uint64_t targetPID) {
    if (!handle || !handle->initialized || !handle->NtUserGetPointerProprietaryId) return 0;
    COMMAND_STRUCT cmd = { op, targetPID };
    handle->NtUserGetPointerProprietaryId(MAGIC_COMMAND, &cmd);
    return 1;
}

int KernelComm_AttachProcess(KernelComm* handle, uint64_t pid) {
    return KernelComm_SendCommand(handle, AttachToProcess, pid);
}

int KernelComm_TriggerBugCheck(KernelComm* handle) {
    return KernelComm_SendCommand(handle, TriggerBugCheck, 0);
}

int KernelComm_Unhook(KernelComm* handle) {
    return KernelComm_SendCommand(handle, Unhook, 0);
}