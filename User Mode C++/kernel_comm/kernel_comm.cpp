#include "kernel_comm.hpp"
#include <windows.h>
#include <iostream>

KernelComm::KernelComm() : NtUserGetPointerProprietaryId(nullptr), initialized(false) {}

KernelComm::~KernelComm() {
    Cleanup();
}

bool KernelComm::Initialize() {
    if (initialized)
        return true;

    MSG msg{};
    PeekMessage(&msg, nullptr, 0, 0, PM_NOREMOVE);

    HMODULE hWin32u = LoadLibraryW(L"win32u.dll");
    if (!hWin32u) {
        std::cerr << "[!] Failed to load win32u.dll\n";
        return false;
    }

    NtUserGetPointerProprietaryId =
        (NtUserGetPointerProprietaryId_t)GetProcAddress(hWin32u, "NtUserGetPointerProprietaryId");

    if (!NtUserGetPointerProprietaryId) {
        std::cerr << "[!] Failed to resolve NtUserGetPointerProprietaryId\n";
        FreeLibrary(hWin32u);
        return false;
    }

    initialized = true;
    return true;
}

bool KernelComm::SendCommand(Operation op, uint64_t targetPID) {
    if (!initialized || !NtUserGetPointerProprietaryId)
        return false;

    COMMAND_STRUCT cmd{};
    cmd.operation = op;
    cmd.targetPID = targetPID;

    NtUserGetPointerProprietaryId(MAGIC_COMMAND, &cmd);

    return true;
}

void KernelComm::Cleanup() {
    initialized = false;
    NtUserGetPointerProprietaryId = nullptr;
}

bool KernelComm::AttachProcess(uint64_t pid) { return SendCommand(Operation::AttachToProcess, pid); }
void KernelComm::TriggerBugCheck() { SendCommand(Operation::TriggerBugCheck, 0); }
bool KernelComm::Unhook() { return SendCommand(Operation::Unhook, 0); }