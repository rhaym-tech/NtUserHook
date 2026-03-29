#pragma once

namespace ntoskrnl {
	inline uintptr_t baseAddr = 0x0;
	inline ObfDereferenceObject_t			ObfDereferenceObject		= nullptr;
	inline ZwQuerySystemInformation_t		ZwQuerySystemInformation	= nullptr;
	inline PsLookupProcessByProcessId_t		PsLookupProcessByProcessId	= nullptr;
	inline KeStackAttachProcess_t			KeStackAttachProcess		= nullptr;
	inline KeUnstackDetachProcess_t			KeUnstackDetachProcess		= nullptr;
	void Import();
	bool Validate();
}

namespace win32k {
	inline uintptr_t baseAddr = 0x0;
	inline W32GetSessionState_t W32GetSessionState = nullptr;
	void Import();
	bool Validate();
}