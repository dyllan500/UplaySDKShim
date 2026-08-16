#include "core/config.h"
#include "core/debug/fault_logger.h"
#include "core/debug/module_dump.h"
#include "core/game_adapter.h"
#include "core/logging.h"
#include "games/newdawn/versions/current.h"
#include "games/common/fc_m64_debug.h"
#include "games/common/uplay_debug.h"

namespace {
FARPROC wrap_newdawn_symbol(HMODULE module, LPCSTR name, FARPROC resolved) {
    return wrap_uplay_symbol("newdawn", module, name, resolved);
}

void install_newdawn_debug_hooks(HMODULE module) {
    const HookConfig& c = hook_config();
    shim_log("[newdawn] diagnostics: uplay=%d ssl=%d game_log=%d invite=%d", static_cast<int>(c.capture_uplay),
             static_cast<int>(c.capture_ssl), static_cast<int>(c.trace_game_log), static_cast<int>(c.trace_invite_dostart));
    install_fault_logger(module, "farcrynewdawn");
    if (c.dump_module) install_module_dump_hotkey(module, "FC_m64_dump.bin");
    install_fc_m64_debug_hooks(module, newdawn::current::kDebug);
}
}

const GameAdapter& game_adapter() {
    static const GameAdapter adapter{
        "farcrynewdawn", "Far Cry New Dawn", newdawn::current::kVersion, "bink2w64.dll", "bink2w64_real.dll",
        newdawn::current::kModules, newdawn::current::kHosts,
        ResolverIat | ResolverGetProc,
        newdawn::current::kNetwork, std::size(newdawn::current::kNetwork),
        newdawn::current::kTls,
        wrap_newdawn_symbol, install_newdawn_debug_hooks
    };
    return adapter;
}
