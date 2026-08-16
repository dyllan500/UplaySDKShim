#include "games/common/fc_m64_debug.h"

#include "core/config.h"
#include "core/logging.h"

#include <atomic>
#include <cstring>

namespace {
using SslIoFn = int (*)(void*, void*, int);
using GameLogFn = void (*)(void*, void*, uint32_t, void*, uint32_t, void*, void*);
using ChannelNameFn = const char* (*)(void*);
SslIoFn g_ssl_read = nullptr;
SslIoFn g_ssl_write = nullptr;
GameLogFn g_game_log = nullptr;
ChannelNameFn g_channel_name = nullptr;
std::atomic<int> g_game_log_count{0};

int hooked_ssl_read(void* ssl, void* buffer, int size) {
    const int result = g_ssl_read(ssl, buffer, size);
    if (result > 0 && buffer) shim_log_bytes("[ssl] read", buffer, result);
    return result;
}

int hooked_ssl_write(void* ssl, void* buffer, int size) {
    if (size > 0 && buffer) shim_log_bytes("[ssl] write", buffer, size);
    return g_ssl_write(ssl, buffer, size);
}

SslIoFn detour_ssl(uintptr_t target, void* replacement, const char* label) {
    if (IsBadReadPtr(reinterpret_cast<void*>(target), 5) || *reinterpret_cast<BYTE*>(target) != 0xB8) {
        shim_log("[ssl] %s signature mismatch at 0x%llx", label, static_cast<unsigned long long>(target));
        return nullptr;
    }
    auto* trampoline = static_cast<BYTE*>(VirtualAlloc(nullptr, 32, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if (!trampoline) return nullptr;
    memcpy(trampoline, reinterpret_cast<void*>(target), 5);
    trampoline[5] = 0xFF; trampoline[6] = 0x25;
    *reinterpret_cast<uint32_t*>(trampoline + 7) = 0;
    *reinterpret_cast<uint64_t*>(trampoline + 11) = target + 5;
    const intptr_t relative = reinterpret_cast<intptr_t>(replacement) - static_cast<intptr_t>(target + 5);
    if (relative < INT32_MIN || relative > INT32_MAX) { VirtualFree(trampoline, 0, MEM_RELEASE); return nullptr; }
    DWORD old = 0;
    if (!VirtualProtect(reinterpret_cast<void*>(target), 5, PAGE_EXECUTE_READWRITE, &old)) {
        VirtualFree(trampoline, 0, MEM_RELEASE); return nullptr;
    }
    *reinterpret_cast<BYTE*>(target) = 0xE9;
    *reinterpret_cast<int32_t*>(target + 1) = static_cast<int32_t>(relative);
    DWORD ignored = 0; VirtualProtect(reinterpret_cast<void*>(target), 5, old, &ignored);
    FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<void*>(target), 5);
    shim_log("[ssl] hooked %s", label);
    return reinterpret_cast<SslIoFn>(trampoline);
}

const char* game_string(void* object) {
    if (!object || IsBadReadPtr(object, 16)) return nullptr;
    void* storage = *reinterpret_cast<void**>(static_cast<char*>(object) + 8);
    if (!storage || IsBadReadPtr(storage, 16)) return nullptr;
    const char* text = static_cast<const char*>(storage) + 12;
    return IsBadReadPtr(text, 1) ? nullptr : text;
}

void copy_text(const char* input, char* output, size_t capacity) {
    output[0] = 0;
    if (!input) return;
    size_t index = 0;
    for (; index + 1 < capacity && !IsBadReadPtr(input + index, 1) && input[index]; ++index)
        output[index] = input[index] == '\r' || input[index] == '\n' ? ' ' : input[index];
    output[index] = 0;
}

void hooked_game_log(void* system, void* channel, uint32_t level, void* category,
                     uint32_t line, void* message, void* extra) {
    if (g_game_log_count.fetch_add(1) < 50000) {
        const char* channel_name = g_channel_name && channel && !IsBadReadPtr(channel, 8)
            ? g_channel_name(channel) : nullptr;
        if (channel_name && IsBadReadPtr(channel_name, 1)) channel_name = nullptr;
        char source[256], text[2048];
        copy_text(game_string(category), source, sizeof(source));
        copy_text(game_string(message), text, sizeof(text));
        shim_log("[gamelog] lvl=%u %s | %s:%u | %s", level, channel_name ? channel_name : "?",
                 source[0] ? source : "?", line, text[0] ? text : "?");
    }
    if (g_game_log) g_game_log(system, channel, level, category, line, message, extra);
}

void install_game_log(uintptr_t base, const FcM64DebugDefinition& definition) {
    const uintptr_t thunk = base + definition.game_log_thunk_rva;
    const uintptr_t expected = base + definition.game_log_real_rva;
    if (IsBadReadPtr(reinterpret_cast<void*>(thunk), 5) || *reinterpret_cast<BYTE*>(thunk) != 0xE9) {
        shim_log("[gamelog] thunk signature mismatch"); return;
    }
    const uintptr_t actual = thunk + 5 + *reinterpret_cast<int32_t*>(thunk + 1);
    if (actual != expected || IsBadReadPtr(reinterpret_cast<void*>(expected), 1)) {
        shim_log("[gamelog] build mismatch: thunk target=0x%llx expected=0x%llx",
                 static_cast<unsigned long long>(actual), static_cast<unsigned long long>(expected));
        return;
    }
    const uintptr_t channel_name = base + definition.game_log_channel_name_rva;
    if (IsBadReadPtr(reinterpret_cast<void*>(channel_name), 1)) return;
    const intptr_t relative = reinterpret_cast<intptr_t>(hooked_game_log) - static_cast<intptr_t>(thunk + 5);
    if (relative < INT32_MIN || relative > INT32_MAX) return;
    g_game_log = reinterpret_cast<GameLogFn>(expected);
    g_channel_name = reinterpret_cast<ChannelNameFn>(channel_name);
    DWORD old = 0;
    if (!VirtualProtect(reinterpret_cast<void*>(thunk), 5, PAGE_EXECUTE_READWRITE, &old)) return;
    *reinterpret_cast<int32_t*>(thunk + 1) = static_cast<int32_t>(relative);
    DWORD ignored = 0; VirtualProtect(reinterpret_cast<void*>(thunk), 5, old, &ignored);
    FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<void*>(thunk), 5);
    shim_log("[gamelog] native FC_m64 log capture active");
}
}

void install_fc_m64_debug_hooks(HMODULE module, const FcM64DebugDefinition& definition) {
    const uintptr_t base = reinterpret_cast<uintptr_t>(module);
    if (hook_config().capture_ssl) {
        if (!definition.ssl_read_rva || !definition.ssl_write_rva) {
            shim_log("[ssl] this version profile has no verified SSL I/O hooks");
        } else {
            g_ssl_read = detour_ssl(base + definition.ssl_read_rva, reinterpret_cast<void*>(hooked_ssl_read), "SSL_read");
            g_ssl_write = detour_ssl(base + definition.ssl_write_rva, reinterpret_cast<void*>(hooked_ssl_write), "SSL_write");
        }
    }
    if (hook_config().trace_game_log) install_game_log(base, definition);
}
