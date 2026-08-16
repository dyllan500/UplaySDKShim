#include "games/common/uplay_debug.h"

#include "core/config.h"
#include "core/logging.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace {
using UplayGetNextEvent = int (*)(void**);
using UplayGetConsumables = bool (*)(void*);
using UplayGeneric = int (*)(void*, void*, void*, void*);

UplayGetNextEvent g_get_next_event = nullptr;
UplayGetConsumables g_get_consumables = nullptr;
UplayGeneric g_set_game_session = nullptr;
UplayGeneric g_respond_friends = nullptr;
UplayGeneric g_respond_party = nullptr;
UplayGeneric g_get_full_members = nullptr;
UplayGeneric g_get_ingame_members = nullptr;
UplayGeneric g_set_user_data = nullptr;

bool readable(const void* value, size_t length) {
    return value && !IsBadReadPtr(value, length);
}

void log_caller(const char* name, void* return_address) {
    const uintptr_t base = reinterpret_cast<uintptr_t>(GetModuleHandleA("FC_m64.dll"));
    const uintptr_t caller = reinterpret_cast<uintptr_t>(return_address);
    if (base && caller >= base && caller < base + 0x20000000ULL)
        shim_log("[uplay] %s caller FC_m64+0x%llx", name,
                 static_cast<unsigned long long>(caller - base));
    else
        shim_log("[uplay] %s caller=%p", name, return_address);
}

void dump_deep(const char* label, void* value, int length = 128) {
    if (!readable(value, 8)) return;
    shim_log_bytes(label, value, length);
    auto* words = static_cast<uintptr_t*>(value);
    for (int i = 0; i < 8; ++i) {
        const uintptr_t candidate = words[i];
        if (candidate <= 0x10000 || candidate >= 0x7fffffffffffULL ||
            !readable(reinterpret_cast<void*>(candidate), 16)) continue;
        char nested[96] = {};
        snprintf(nested, sizeof(nested), "%s +0x%x ->", label, i * 8);
        shim_log_bytes(nested, reinterpret_cast<void*>(candidate), 128);
    }
}

void dump_session_blob(void* session_id, void* blob) {
    if (!hook_config().dump_session_blob || !readable(blob, 12)) return;
    void* data = *static_cast<void**>(blob);
    const uint32_t size = *reinterpret_cast<uint32_t*>(static_cast<uint8_t*>(blob) + 8);
    if (!data || !size || size >= (1u << 20) || !readable(data, size)) return;
    char path[MAX_PATH] = {};
    GetModuleFileNameA(GetModuleHandleA("bink2w64.dll"), path, MAX_PATH);
    if (char* slash = strrchr(path, '\\')) *slash = 0;
    strncat_s(path, "\\session_blob.bin", _TRUNCATE);
    FILE* file = nullptr;
    fopen_s(&file, path, "wb");
    if (!file) { shim_log("[uplay] cannot write %s", path); return; }
    const uint64_t id = reinterpret_cast<uintptr_t>(session_id);
    fwrite(&id, sizeof(id), 1, file);
    fwrite(data, 1, size, file);
    fclose(file);
    shim_log("[uplay] session blob saved to %s (id=0x%llx size=%u)", path,
             static_cast<unsigned long long>(id), size);
}

int hook_get_next_event(void** event_out) {
    const int result = g_get_next_event(event_out);
    if (hook_config().capture_uplay && result && readable(event_out, 16)) {
        const int32_t type = *reinterpret_cast<int32_t*>(event_out);
        void* event = *reinterpret_cast<void**>(reinterpret_cast<uint8_t*>(event_out) + 8);
        shim_log("[uplay] GetNextEvent type=%d event=%p", type, event);
        if (event) dump_deep("[uplay] event", event);
    }
    return result;
}

bool hook_get_consumables(void* output) {
    const bool result = g_get_consumables(output);
    shim_log("[uplay] GetConsumableItems -> %d output=%p", static_cast<int>(result), output);
    if (hook_config().capture_uplay) dump_deep("[uplay] consumables", output);
    return result;
}

int hook_set_game_session(void* a, void* b, void* c, void* d) {
    shim_log("[uplay] USER_SetGameSession id=%p blob=%p flags=%p", a, b, c);
    log_caller("SetGameSession", __builtin_return_address(0));
    dump_session_blob(a, b);
    if (hook_config().capture_uplay) dump_deep("[uplay] session", b, 256);
    return g_set_game_session(a, b, c, d);
}

int hook_respond_friends(void* a, void* b, void* c, void* d) {
    shim_log("[uplay] FRIENDS_RespondToGameInvite a=%p b=%p c=%p d=%p", a, b, c, d);
    if (hook_config().capture_uplay) dump_deep("[uplay] friends invite", a, 256);
    return g_respond_friends(a, b, c, d);
}

int hook_respond_party(void* a, void* b, void* c, void* d) {
    shim_log("[uplay] PARTY_RespondToGameInvite a=%p b=%p c=%p d=%p", a, b, c, d);
    if (hook_config().capture_uplay) dump_deep("[uplay] party invite", a, 256);
    return g_respond_party(a, b, c, d);
}

int hook_get_full_members(void* a, void* b, void* c, void* d) {
    const int result = g_get_full_members(a, b, c, d);
    shim_log("[uplay] PARTY_GetFullMemberList -> %d", result);
    if (hook_config().capture_uplay) { dump_deep("[uplay] full members a", a, 256); dump_deep("[uplay] full members b", b, 256); }
    return result;
}

int hook_get_ingame_members(void* a, void* b, void* c, void* d) {
    const int result = g_get_ingame_members(a, b, c, d);
    shim_log("[uplay] PARTY_GetInGameMemberList -> %d", result);
    if (hook_config().capture_uplay) { dump_deep("[uplay] in-game members a", a, 256); dump_deep("[uplay] in-game members b", b, 256); }
    return result;
}

int hook_set_user_data(void* a, void* b, void* c, void* d) {
    shim_log("[uplay] PARTY_SetUserData a=%p b=%p c=%p d=%p", a, b, c, d);
    if (hook_config().capture_uplay) { dump_deep("[uplay] user data a", a, 256); dump_deep("[uplay] user data b", b, 256); }
    return g_set_user_data(a, b, c, d);
}

void generic_call_log(const char* name, void* return_address) {
    shim_log("[uplay] CALL %s", name);
    log_caller(name, return_address);
}

void* make_log_thunk(const char* name, void* real) {
#if defined(_WIN64)
    char* saved_name = _strdup(name);
    auto* thunk = static_cast<uint8_t*>(VirtualAlloc(nullptr, 64, MEM_COMMIT | MEM_RESERVE,
                                                     PAGE_EXECUTE_READWRITE));
    if (!saved_name || !thunk) { free(saved_name); return real; }
    int cursor = 0;
    auto emit = [&](uint8_t byte) { thunk[cursor++] = byte; };
    auto emit64 = [&](const void* value) {
        const uint64_t immediate = reinterpret_cast<uintptr_t>(value);
        for (int i = 0; i < 8; ++i) thunk[cursor++] = static_cast<uint8_t>(immediate >> (i * 8));
    };
    emit(0x51); emit(0x52); emit(0x41); emit(0x50); emit(0x41); emit(0x51);
    emit(0x48); emit(0x83); emit(0xec); emit(0x28);
    emit(0x48); emit(0x8b); emit(0x54); emit(0x24); emit(0x48);
    emit(0x48); emit(0xb9); emit64(saved_name);
    emit(0x48); emit(0xb8); emit64(reinterpret_cast<void*>(&generic_call_log));
    emit(0xff); emit(0xd0);
    emit(0x48); emit(0x83); emit(0xc4); emit(0x28);
    emit(0x41); emit(0x59); emit(0x41); emit(0x58); emit(0x5a); emit(0x59);
    emit(0x48); emit(0xb8); emit64(real); emit(0xff); emit(0xe0);
    FlushInstructionCache(GetCurrentProcess(), thunk, cursor);
    return thunk;
#else
    return real;
#endif
}

void* known_wrapper(const char* name, void* real) {
    struct Entry { const char* name; void* hook; void** original; };
    static const Entry entries[] = {
        {"UPLAY_GetNextEvent", reinterpret_cast<void*>(&hook_get_next_event), reinterpret_cast<void**>(&g_get_next_event)},
        {"UPLAY_USER_GetConsumableItems", reinterpret_cast<void*>(&hook_get_consumables), reinterpret_cast<void**>(&g_get_consumables)},
        {"UPLAY_USER_SetGameSession", reinterpret_cast<void*>(&hook_set_game_session), reinterpret_cast<void**>(&g_set_game_session)},
        {"UPLAY_FRIENDS_RespondToGameInvite", reinterpret_cast<void*>(&hook_respond_friends), reinterpret_cast<void**>(&g_respond_friends)},
        {"UPLAY_PARTY_RespondToGameInvite", reinterpret_cast<void*>(&hook_respond_party), reinterpret_cast<void**>(&g_respond_party)},
        {"UPLAY_PARTY_GetFullMemberList", reinterpret_cast<void*>(&hook_get_full_members), reinterpret_cast<void**>(&g_get_full_members)},
        {"UPLAY_PARTY_GetInGameMemberList", reinterpret_cast<void*>(&hook_get_ingame_members), reinterpret_cast<void**>(&g_get_ingame_members)},
        {"UPLAY_PARTY_SetUserData", reinterpret_cast<void*>(&hook_set_user_data), reinterpret_cast<void**>(&g_set_user_data)},
    };
    for (const Entry& entry : entries) {
        if (strcmp(name, entry.name) != 0) continue;
        *entry.original = real;
        return entry.hook;
    }
    return nullptr;
}
}

FARPROC wrap_uplay_symbol(const char* game_id, HMODULE, LPCSTR name, FARPROC resolved) {
    if (!name || reinterpret_cast<uintptr_t>(name) <= 0xffff || strncmp(name, "UPLAY_", 6) != 0)
        return resolved;
    if (!resolved) {
        if (hook_config().trace_uplay) shim_log("[%s:uplay] %s not exported by SDK", game_id, name);
        return resolved;
    }
    if (!hook_config().capture_uplay && !hook_config().trace_uplay) return resolved;
    if (void* wrapper = known_wrapper(name, reinterpret_cast<void*>(resolved))) {
        shim_log("[%s:uplay] wrapped %s -> %p", game_id, name, reinterpret_cast<void*>(resolved));
        return reinterpret_cast<FARPROC>(wrapper);
    }
    shim_log("[%s:uplay] bound %s -> %p", game_id, name, reinterpret_cast<void*>(resolved));
    return hook_config().trace_uplay
        ? reinterpret_cast<FARPROC>(make_log_thunk(name, reinterpret_cast<void*>(resolved))) : resolved;
}
