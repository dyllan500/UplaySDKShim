#pragma once

#include <windows.h>

// Shared by the FC_m64 games, which consume the same Uplay C SDK surface. The game adapter remains responsible for opting into this callback.
FARPROC wrap_uplay_symbol(const char* game_id, HMODULE module, LPCSTR name, FARPROC resolved);
