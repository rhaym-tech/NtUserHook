#pragma once
#include <includes.h>

extern "C" NTSTATUS DriverEntry() {
    ntoskrnl::Import();
    win32k::Import();

    if (!ntoskrnl::Validate() || !win32k::Validate())
        return STATUS_UNSUCCESSFUL;

    static HookManager mgr;

    if(!mgr.Initialize())
        return STATUS_UNSUCCESSFUL;

    if (mgr.ApplyPatch(true)) 
		DbgPrint("Patch applied successfully.\n");
	else {
        DbgPrint("Failed to apply patch.\n");
        return STATUS_UNSUCCESSFUL;
    }
	
    return STATUS_SUCCESS;
}