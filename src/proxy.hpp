#ifndef FREETPFIX_PROXY_HPP
#define FREETPFIX_PROXY_HPP

#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <string>
#include "log.hpp"

static FARPROC cxxFrameHandler4 = {};
static FARPROC nlgDispatch2 = {};
static FARPROC nlgReturn2 = {};

bool initProxy() {
	auto size = GetSystemDirectoryA(nullptr, 0);
	auto path = std::string(size - 1, '\0');
	GetSystemDirectoryA(path.data(), size);
	path += "\\vcruntime140_1.dll";
	log("initProxy(): original dll path: %s", path.c_str());

	auto module = LoadLibraryA(path.c_str());
	if (!module) {
		log("initProxy(): original dll load failed");
		return false;
	}

	cxxFrameHandler4 = GetProcAddress(module, "__CxxFrameHandler4");
	nlgDispatch2 = GetProcAddress(module, "__NLG_Dispatch2");
	nlgReturn2 = GetProcAddress(module, "__NLG_Return2");
	log("initProxy(): loaded function addresses:\n\t%#x\n\t%#x\n\t%#x", cxxFrameHandler4, nlgDispatch2, nlgReturn2);

	return cxxFrameHandler4 && nlgDispatch2 && nlgReturn2;
}

INT_PTR WINAPI __CxxFrameHandler4() {
	return cxxFrameHandler4();
}

INT_PTR WINAPI __NLG_Dispatch2() {
	return nlgDispatch2();
}

INT_PTR WINAPI __NLG_Return2() {
	return nlgReturn2();
}

#endif // FREETPFIX_PROXY_HPP