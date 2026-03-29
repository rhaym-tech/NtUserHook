#pragma once
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

    typedef enum _Operation {
        AttachToProcess = 0,
        TriggerBugCheck,
        Unhook
    } Operation;

    typedef struct _COMMAND_STRUCT {
        Operation operation;
        uint64_t targetPID;
    } COMMAND_STRUCT;

#define MAGIC_COMMAND 0x67676767

    typedef struct _KernelComm KernelComm;

    // C-compatible functions
    KernelComm* KernelComm_Create(void);
    void KernelComm_Destroy(KernelComm* handle);

    int KernelComm_Initialize(KernelComm* handle);
    int KernelComm_SendCommand(KernelComm* handle, Operation op, uint64_t targetPID);

    int KernelComm_AttachProcess(KernelComm* handle, uint64_t pid);
    int KernelComm_TriggerBugCheck(KernelComm* handle);
    int KernelComm_Unhook(KernelComm* handle);

#ifdef __cplusplus
}
#endif