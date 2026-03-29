#pragma once
#define MAGIC_COMMAND 0x67676767

typedef enum _Operation {
    AttachToProcess = 0,
    TriggerBugCheck,
    Unhook
} Operation;

typedef struct _COMMAND_STRUCT {
    Operation operation;
    UINT64 targetPID;
} COMMAND_STRUCT, * PCOMMAND_STRUCT;