#include <includes.h>

HookManager* HookManager::s_Instance = nullptr;

NTSTATUS ReplaceGuardPointerSafe(volatile LONG64* guardAddr, UINT64 expected, UINT64 newValue, UINT64* originalOut ) {
    if (!guardAddr)
        return STATUS_INVALID_PARAMETER;

    __try {
        LONG64 prev = InterlockedCompareExchange64(
            guardAddr,
            (LONG64)newValue,
            (LONG64)expected
        );

        if (prev != (LONG64)expected)
            return STATUS_ALREADY_COMMITTED;

        if (originalOut)
            *originalOut = (UINT64)expected;

        KeMemoryBarrier();
        return STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return STATUS_ACCESS_VIOLATION;
    }
}

PVOID GetSessionState() {
    UNICODE_STRING name;
    RtlInitUnicodeString(&name, KC_WSTR(L"explorer.exe"));

    HANDLE pid = GetPidFromProcessName(&name);
    if (!pid)
        return nullptr;

    PEPROCESS process;
    if (!NT_SUCCESS(ntoskrnl::PsLookupProcessByProcessId(pid, &process)))
        return nullptr;

    KAPC_STATE apc{};
    PVOID state = nullptr;

    ntoskrnl::KeStackAttachProcess(process, &apc);
    __try {
        state = win32k::W32GetSessionState();
    }
    __finally {
        ntoskrnl::KeUnstackDetachProcess(&apc);
    }

    ntoskrnl::ObfDereferenceObject(process);
    return state;
}

bool HookManager::Initialize() {
    s_Instance = this;
    return true;
}

PVOID __fastcall HookManager::HookThunk(UINT32 magic, PVOID buffer) {
    auto inst = s_Instance;
    if (!inst)
        return 0;

    return inst->HandleCall(magic, buffer);
}

PVOID HookManager::HandleCall(UINT32 magic, PVOID buffer) {
    PrintDbg("Hook: arg1: 0x%x, arg2: %p\n", magic, buffer);

    if (magic != MAGIC_COMMAND || !buffer)
        goto original;

    PCOMMAND_STRUCT cmd = nullptr;

    __try {
        cmd = (PCOMMAND_STRUCT)buffer;
        ProbeForRead(cmd, sizeof(COMMAND_STRUCT), __alignof(COMMAND_STRUCT));
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        goto original;
    }

    switch (cmd->operation) {
    case AttachToProcess:
        PrintDbg("Attach PID %llu\n", cmd->targetPID);
        break;

    case TriggerBugCheck:
        KeBugCheckEx(MANUALLY_INITIATED_CRASH, 0, 0, 0, 0);
        break;

    case Unhook:
        PrintDbg("Unhooking\n");
        RemovePatch();
        break;

    default:
        break;
    }

    return nullptr;

original:
    if (!m_Original)
        return nullptr;

    return m_Original(magic, buffer);
}

bool HookManager::ApplyPatch(bool setOriginal) {
    PVOID session = GetSessionState();
    if (!session)
        return false;

    volatile UINT64* slot = nullptr;

    __try {
        auto c1 = *reinterpret_cast<PUCHAR*>((PUCHAR)session + OFF1);
        if (!c1) return false;

        auto c2 = *reinterpret_cast<PUCHAR*>(c1 + OFF2);
        if (!c2) return false;

        slot = reinterpret_cast<volatile UINT64*>(c2 + OFF3);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }

    m_GuardSlot = slot;

    UINT64 original = 0;

    LONG64 current = InterlockedCompareExchange64((volatile LONG64*)slot, 0, 0);

    NTSTATUS st = ReplaceGuardPointerSafe(
        (volatile LONG64*)slot,
        current,
        (UINT64)HookThunk,
        &original
    );

    if (!NT_SUCCESS(st))
        return false;

    if (setOriginal && !m_Original)
        m_Original = (NtUserGetPointerProprietaryId_t)original;

	PrintDbg("Hook address replaced: %p -> %p (original was %p)\n", (PVOID)current, (PVOID)HookThunk, (PVOID)original);

    return (*slot == (UINT64)HookThunk);
}

bool HookManager::RemovePatch() {
    if (!m_GuardSlot || !m_Original)
        return false;

    if (*m_GuardSlot != (UINT64)HookThunk)
        return false;

    NTSTATUS st = ReplaceGuardPointerSafe(
        (volatile LONG64*)m_GuardSlot,
        (UINT64)HookThunk,
        (UINT64)m_Original,
        nullptr
    );

    return NT_SUCCESS(st) && (*m_GuardSlot == (UINT64)m_Original);
}