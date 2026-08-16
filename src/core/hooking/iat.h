#pragma once

#include <windows.h>

// Replaces a named import in one PE module and returns its former address.
void* patch_iat(HMODULE module, const char* imported_dll, const char* imported_name, void* replacement);
void* patch_iat_ordinal(HMODULE module, const char* imported_dll, WORD imported_ordinal, void* replacement);
