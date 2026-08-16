#pragma once

#include <windows.h>

struct GameAdapter;

// The adapter describes where a title obtains networking functions. These functions install the shared networking behavior at those locations.
void configure_networking(const GameAdapter& adapter);
bool early_network_hooks_needed();
void install_early_network_hooks(HMODULE game_module);
void install_network_hooks(HMODULE game_module);
