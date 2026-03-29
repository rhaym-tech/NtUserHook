#include <includes.h>

void ntoskrnl::Import() {
	baseAddr = reinterpret_cast<uintptr_t>(kernelcloak::security::get_module(KC_HASH_CI("ntoskrnl.exe")));

	ObfDereferenceObject		= static_cast<ObfDereferenceObject_t>		(KC_GET_PROC(ntoskrnl::baseAddr, "ObfDereferenceObject"));
	ZwQuerySystemInformation	= static_cast<ZwQuerySystemInformation_t>	(KC_GET_PROC(ntoskrnl::baseAddr, "ZwQuerySystemInformation"));
	PsLookupProcessByProcessId	= static_cast<PsLookupProcessByProcessId_t>	(KC_GET_PROC(ntoskrnl::baseAddr, "PsLookupProcessByProcessId"));
	KeStackAttachProcess		= static_cast<KeStackAttachProcess_t>		(KC_GET_PROC(ntoskrnl::baseAddr, "KeStackAttachProcess"));
	KeUnstackDetachProcess		= static_cast<KeUnstackDetachProcess_t>		(KC_GET_PROC(ntoskrnl::baseAddr, "KeUnstackDetachProcess"));
}

bool ntoskrnl::Validate() {
	return baseAddr &&
		ObfDereferenceObject &&
		ZwQuerySystemInformation &&
		PsLookupProcessByProcessId &&
		KeStackAttachProcess &&
		KeUnstackDetachProcess;;
}

void win32k::Import() {
	win32k::baseAddr = reinterpret_cast<uintptr_t>(kernelcloak::security::get_module(KC_HASH_CI("win32k.sys")));

	win32k::W32GetSessionState = static_cast<W32GetSessionState_t>(KC_GET_PROC(win32k::baseAddr, "W32GetSessionState"));
}

bool win32k::Validate() {
	return baseAddr && W32GetSessionState;
}