#include "core/config.h"
#include "core/game_adapter.h"
#include "core/logging.h"
#include "core/networking/redirect.h"
#include "core/networking/tls.h"

namespace {
HMODULE g_real_proxy = nullptr;

HMODULE find_main_module(const GameAdapter& game) {
    for (const char* const* name = game.main_modules; name && *name; ++name)
        if (HMODULE module = GetModuleHandleA(*name)) return module;
    return nullptr;
}

void log_build_identity(HMODULE module, const GameAdapter& game) {
    auto* base = reinterpret_cast<BYTE*>(module);
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) { shim_log("[runtime] invalid DOS header for %s", game.display_name); return; }
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) { shim_log("[runtime] invalid PE header for %s", game.display_name); return; }
    shim_log("[runtime] %s profile=%s PE timestamp=0x%08lx image_size=0x%08lx",
             game.display_name, game.version_id, static_cast<unsigned long>(nt->FileHeader.TimeDateStamp),
             static_cast<unsigned long>(nt->OptionalHeader.SizeOfImage));
}

DWORD WINAPI initialize(LPVOID) {
    const GameAdapter& game = game_adapter();
    HMODULE main_module = nullptr;
    for (int attempt = 0; attempt < 200 && !main_module; ++attempt) {
        main_module = find_main_module(game);
        if (!main_module) Sleep(50);
    }
    if (!main_module) { shim_log("[runtime] main module did not appear; no hooks installed"); return 1; }
    set_hook_config(load_hook_config());
    log_hook_config(hook_config());
    shim_log("[runtime] %s main module at %p", game.id, main_module);
    log_build_identity(main_module, game);
    install_network_hooks(main_module);
    install_tls_bypass(main_module, game.tls);
    if (game.install_debug_hooks) game.install_debug_hooks(main_module);
    return 0;
}
}

extern "C" BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(instance);
        const GameAdapter& game = game_adapter();
        initialize_logging(instance, game.id);
        initialize_hook_config(instance);
        // Some titles (notably FC5) resolve Winsock almost immediately. Arm
        // dynamic resolution before the asynchronous full initialization
        // whenever the game module is already present.
        set_hook_config(load_hook_config());
        configure_networking(game);
        if (early_network_hooks_needed()) {
            if (HMODULE main_module = find_main_module(game)) {
                shim_log("[runtime] early network resolver setup for %s", game.id);
                install_early_network_hooks(main_module);
            } else {
                shim_log("[runtime] main module unavailable during early dynamic resolver setup");
            }
        }
        g_real_proxy = LoadLibraryA(game.real_proxy_dll);
        if (!g_real_proxy) shim_log("[runtime] cannot load %s: %lu", game.real_proxy_dll, GetLastError());
        HANDLE thread = CreateThread(nullptr, 0, initialize, nullptr, 0, nullptr);
        if (thread) CloseHandle(thread);
        else shim_log("[runtime] initialization worker creation failed: %lu", GetLastError());
    } else if (reason == DLL_PROCESS_DETACH) {
        if (g_real_proxy) FreeLibrary(g_real_proxy);
        shutdown_logging();
    }
    return TRUE;
}
