#pragma once

#include <windows.h>

struct TlsHookDefinition;

void install_tls_bypass(HMODULE game_module, const TlsHookDefinition& definition);
