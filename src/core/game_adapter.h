#pragma once

#include <windows.h>
#include <cstddef>
#include <cstdint>
#include <iterator>

enum class NetworkApi {
    AddrInfoLookup,
    GetHostByName,
    Socket,
    WSASocketW,
    Connect,
    Send,
    Recv,
    CloseSocket,
    SendTo,
    RecvFrom,
    WSASendTo,
    WSARecvFrom,
    WSASend,
    WSARecv,
    WSAGetOverlappedResult,
    WSAIoctl,
};

enum ResolverMethod : uint32_t {
    ResolverIat          = 1u << 0,
    ResolverGetProc      = 1u << 1,
    ResolverExportDetour = 1u << 2,
};

struct NetworkBindingDefinition {
    NetworkApi api;
    const char* name;
    WORD ordinal;
    uint32_t resolver_methods = ResolverIat;
};

enum class TlsHookMethod {
    None,
    Int3ReturnTrue,
    Int3ReturnTrueAndClearError,
    HardwareBreakpointReturnTrue,
};

struct TlsHookDefinition {
    uint64_t default_rva;
    TlsHookMethod method;
    uint32_t x86_stack_bytes;
    uint32_t error_field_offset;
};

using DynamicSymbolHook = FARPROC (*)(HMODULE module, LPCSTR name, FARPROC resolved);

struct GameAdapter {
    const char* id;
    const char* display_name;
    const char* version_id;
    const char* proxy_dll;
    const char* real_proxy_dll;
    const char* const* main_modules;
    const char* const* redirect_hosts;
    uint32_t resolver_methods;
    const NetworkBindingDefinition* network_bindings;
    size_t network_binding_count;
    TlsHookDefinition tls;

    DynamicSymbolHook wrap_dynamic_symbol;
    void (*install_debug_hooks)(HMODULE main_module);
};

const GameAdapter& game_adapter();
