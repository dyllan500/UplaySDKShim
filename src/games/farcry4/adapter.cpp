#include "core/config.h"
#include "core/debug/module_dump.h"
#include "core/game_adapter.h"
#include "core/logging.h"
#include "games/farcry4/versions/current.h"

namespace {
void install_fc4_debug_hooks(HMODULE module) {
    if (hook_config().dump_module) install_module_dump_hotkey(module, "FC64_dump.bin");
    shim_log("[fc4] adapter selected; redirect_all_dns=%d", static_cast<int>(hook_config().redirect_all_dns));
}
}

const GameAdapter& game_adapter() {
    static const GameAdapter adapter{
        "farcry4", "Far Cry 4", farcry4::current::kVersion, "bink2w64.dll", "bink2w64_real.dll",
        farcry4::current::kModules, farcry4::current::kHosts,
        ResolverIat | ResolverGetProc | ResolverExportDetour,
        farcry4::current::kNetwork, std::size(farcry4::current::kNetwork),
        farcry4::current::kTls,
        nullptr, install_fc4_debug_hooks
    };
    return adapter;
}
