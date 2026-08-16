#pragma once

#include <windows.h>
#include <cstdint>

struct FcM64DebugDefinition {
    uint64_t ssl_read_rva;
    uint64_t ssl_write_rva;
    uint64_t game_log_thunk_rva;
    uint64_t game_log_real_rva;
    uint64_t game_log_channel_name_rva;
};

void install_fc_m64_debug_hooks(HMODULE module, const FcM64DebugDefinition& definition);
