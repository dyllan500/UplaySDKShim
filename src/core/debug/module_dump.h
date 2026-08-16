#pragma once

#include <windows.h>

//F10 writes the live, unpacked image beside the shim without affecting networking policy.
void install_module_dump_hotkey(HMODULE module, const char* output_name);
