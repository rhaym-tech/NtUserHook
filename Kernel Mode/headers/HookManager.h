#pragma once
#include <includes.h>

#define HOOK_DBG 1
#if HOOK_DBG
#define PrintDbg(...) DbgPrint(__VA_ARGS__)
#else
#define PrintDbg(...)
#endif

#define OFF1 0x88
#define OFF2 0x270
#define OFF3 0x68

NTSTATUS ReplaceGuardPointerSafe(
    volatile LONG64* guardAddr,
    UINT64 expected,
    UINT64 newValue,
    UINT64* originalOut
);

PVOID GetSessionState();

class HookManager {
public:
    bool Initialize();
    bool ApplyPatch(bool setOriginal);
    bool RemovePatch();

private:
    volatile UINT64* m_GuardSlot = nullptr;
    NtUserGetPointerProprietaryId_t m_Original = nullptr;

    static HookManager* s_Instance;

    static PVOID __fastcall HookThunk(UINT32 magic, PVOID buffer);
    PVOID HandleCall(UINT32 magic, PVOID buffer);
};