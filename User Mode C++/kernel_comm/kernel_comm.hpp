#pragma once
#include <Windows.h>
#include <cstdint>

enum Operation : uint32_t {
    AttachToProcess = 0,
    TriggerBugCheck,
    Unhook
};

struct COMMAND_STRUCT {
    Operation operation;
    uint64_t targetPID;
};

#define MAGIC_COMMAND 0x67676767

class KernelComm {
private:
    using NtUserGetPointerProprietaryId_t = PVOID(__fastcall*)(UINT32, PVOID);
    NtUserGetPointerProprietaryId_t NtUserGetPointerProprietaryId;

    bool initialized;
public:
    KernelComm();
    ~KernelComm();

    bool Initialize();
    bool SendCommand(Operation op, uint64_t targetPID);
    void Cleanup();

    // Convenience APIs
    bool AttachProcess(uint64_t pid);
    void TriggerBugCheck();
    bool Unhook();
};