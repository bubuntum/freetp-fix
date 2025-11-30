#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <cstring>
#include <cstdint>
#include <string_view>
#include "proxy.hpp"
#include "log.hpp"

void* hookedFunc = {};

uint8_t data[] = { 0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0x50, 0xC3 };
uint8_t oldData[sizeof(data)] = {};

BOOL WINAPI HookedCreateProcessA(
	LPCSTR lpApplicationName,
	LPSTR lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL bInheritHandles,
	DWORD dwCreationFlags,
	LPVOID lpEnvironment,
	LPCSTR lpCurrentDirectory,
	LPSTARTUPINFOA lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation
) {
	log("HookedCreateProcessA(): cmdline = %s", lpCommandLine);

	if (std::string_view(lpCommandLine).starts_with("cmd.exe")) {
		log("HookedCreateProcessA(): attempt to open the site was intercepted. returning 1");
		return TRUE;
	}

	if (!WriteProcessMemory(GetCurrentProcess(), hookedFunc, oldData, sizeof(oldData), nullptr)) {
		log("HookedCreateProcessA(): WriteProcessMemory() [1] failed. returning 0");
		return FALSE;
	}

	auto result = CreateProcessA(
		lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles,
		dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);

	log("HookedCreateProcessA(): CreateProcessA() returned %d", result);

	if (!WriteProcessMemory(GetCurrentProcess(), hookedFunc, data, sizeof(data), nullptr)) {
		log("HookedCreateProcessA(): WriteProcessMemory() [2] failed. CreateProcessA() unhooked");
	}

	return result;
}

BOOL WINAPI DllMain(HINSTANCE, DWORD reason, void*) {
	if (reason == DLL_PROCESS_ATTACH) {
		if (!initProxy()) {
			log("DllMain(): initProxy() failed");
			return TRUE;
		}

		hookedFunc = reinterpret_cast<void*>(GetProcAddress(GetModuleHandleA("kernel32.dll"), "CreateProcessA"));

		if (!ReadProcessMemory(GetCurrentProcess(), hookedFunc, oldData, sizeof(oldData), nullptr)) {
			log("DllMain(): ReadProcessMemory() failed");
			return TRUE;
		}

		// result:
		//   mov rax, <address of hook>
		//   push rax
		//   ret
		auto hook = reinterpret_cast<void*>(&HookedCreateProcessA);
		std::memcpy(data + 2, &hook, sizeof(void*));

		if (!WriteProcessMemory(GetCurrentProcess(), hookedFunc, data, sizeof(data), nullptr)) {
			log("DllMain(): WriteProcessMemory() failed");
		}
	}

	return TRUE;
}