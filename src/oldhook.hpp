#ifndef FREETPFIX_HOOK_HPP
#define FREETPFIX_HOOK_HPP

#include <windows.h>
#include "log.hpp"

// PE format uses RVAs (Relative Virtual Addresses) to save addresses relative
// to the base of the module More info:
// https://en.wikibooks.org/wiki/X86_Disassembly/Windows_Executable_Files#Relative_Virtual_Addressing_(RVA)
//
// This helper macro converts the saved RVA to a fully valid pointer to the data
// in the PE file
#define RVA2PTR(t, base, rva) ((t)(((PCHAR)(base)) + (rva)))

static BOOL hook(void* dll, char const* targetDll, void* targetFunction, void* detourFunction) {
	auto mz = (IMAGE_DOS_HEADER*)dll;
	IMAGE_NT_HEADERS* nt = RVA2PTR(IMAGE_NT_HEADERS*, mz, mz->e_lfanew);

	IMAGE_IMPORT_DESCRIPTOR* imports =
		RVA2PTR(IMAGE_IMPORT_DESCRIPTOR*, mz, nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	for (int i = 0; imports[i].Characteristics; ++i) {
		char* name = RVA2PTR(char*, mz, imports[i].Name);
		log("%s", name);

		if (lstrcmpiA(name, targetDll) != 0)
			continue;

		void** thunk = RVA2PTR(void**, mz, imports[i].FirstThunk);

		for (; *thunk; ++thunk) {
			void* import = *thunk;

			if (import != targetFunction)
				continue;

			DWORD oldState;
			if (!VirtualProtect(thunk, sizeof(void*), PAGE_READWRITE, &oldState))
				return FALSE;

			*thunk = detourFunction;

			VirtualProtect(thunk, sizeof(void*), oldState, &oldState);

			return TRUE;
		}
	}

	return FALSE;
}

#endif // FREETPFIX_HOOK_HPP