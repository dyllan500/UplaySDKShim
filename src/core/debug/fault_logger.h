#pragma once

#include <windows.h>

// Diagnostic only: records first-chance fatal-class exceptions and then lets the game/Wine continue its normal exception search.
void install_fault_logger(HMODULE game_module, const char* game_id);
