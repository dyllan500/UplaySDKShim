#include "core/config.h"
#include "core/debug/fault_logger.h"
#include "core/debug/module_dump.h"
#include "core/game_adapter.h"
#include "core/logging.h"
#include "games/farcry5/cng_debug.h"
#include "games/farcry5/versions/current.h"
#include "games/common/fc_m64_debug.h"
#include "games/common/uplay_debug.h"

namespace {
FARPROC wrap_fc5_symbol(HMODULE module, LPCSTR name, FARPROC resolved) {
    if (!name || reinterpret_cast<uintptr_t>(name) <= 0xffff) return resolved;
    if (FARPROC wrapped = wrap_fc5_cng_symbol(module, name, resolved); wrapped != resolved)
        return wrapped;
    return wrap_uplay_symbol("fc5", module, name, resolved);
}

void install_fc5_debug_hooks(HMODULE module) {
    const HookConfig& c = hook_config();
    shim_log("[fc5] diagnostics: uplay=%d ssl=%d cng=%d rdv=%d tcp=%d", static_cast<int>(c.capture_uplay),
             static_cast<int>(c.capture_ssl), static_cast<int>(c.trace_cng), static_cast<int>(c.log_rdv_full), static_cast<int>(c.log_tcp_full));
    install_fault_logger(module, "farcry5");
    if (c.dump_module) install_module_dump_hotkey(module, "FC_m64_dump.bin");
    install_fc_m64_debug_hooks(module, farcry5::current::kDebug);
}
}

const GameAdapter& game_adapter() {
    static const GameAdapter adapter{
        "farcry5", "Far Cry 5", farcry5::current::kVersion, "bink2w64.dll", "bink2w64_real.dll",
        farcry5::current::kModules, farcry5::current::kHosts,
        ResolverIat | ResolverGetProc,
        farcry5::current::kNetwork, std::size(farcry5::current::kNetwork),
        farcry5::current::kTls,
        wrap_fc5_symbol, install_fc5_debug_hooks
    };
    return adapter;
}
