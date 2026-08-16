#include "core/config.h"
#include "core/game_adapter.h"
#include "core/logging.h"
#include "games/farcry3/tracer.h"
#include "games/farcry3/versions/current.h"

namespace {
void install_fc3_debug_hooks(HMODULE module) {
    (void)module;
    install_trace_points();
    shim_log("[fc3] adapter selected (trace_points=%s)", hook_config().trace_points[0] ? hook_config().trace_points : "off");
}
}

const GameAdapter& game_adapter() {
    static const GameAdapter adapter{
        "farcry3", "Far Cry 3", farcry3::current::kVersion, "binkw32.dll", "binkw32_real.dll",
        farcry3::current::kModules, farcry3::current::kHosts,
        ResolverIat | ResolverGetProc,
        farcry3::current::kNetwork, std::size(farcry3::current::kNetwork),
        farcry3::current::kTls,
        nullptr, install_fc3_debug_hooks
    };
    return adapter;
}
