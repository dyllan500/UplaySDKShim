#pragma once
#include <windows.h>

FARPROC wrap_fc5_cng_symbol(HMODULE module, LPCSTR name, FARPROC resolved);
