#include "core/networking/redirect.h"

#include "core/config.h"
#include "core/game_adapter.h"
#include "core/hooking/iat.h"
#include "core/logging.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <cstdint>
#include <cstdio>
#include <cstring>

namespace {
using SocketFn = SOCKET (WSAAPI *)(int, int, int);
using WSASocketWFn = SOCKET (WSAAPI *)(int, int, int, LPWSAPROTOCOL_INFOW, GROUP, DWORD);
using ConnectFn = int (WSAAPI *)(SOCKET, const sockaddr*, int);
using SendFn = int (WSAAPI *)(SOCKET, const char*, int, int);
using RecvFn = int (WSAAPI *)(SOCKET, char*, int, int);
using CloseSocketFn = int (WSAAPI *)(SOCKET);
using SendToFn = int (WSAAPI *)(SOCKET, const char*, int, int, const sockaddr*, int);
using RecvFromFn = int (WSAAPI *)(SOCKET, char*, int, int, sockaddr*, int*);
using GetAddrInfoFn = int (WSAAPI *)(PCSTR, PCSTR, const ADDRINFOA*, PADDRINFOA*);
using GetHostByNameFn = hostent* (WSAAPI *)(const char*);
using WSASendToFn = int (WSAAPI *)(SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD, const sockaddr*, int,
                                    LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
using WSARecvFromFn = int (WSAAPI *)(SOCKET, LPWSABUF, DWORD, LPDWORD, LPDWORD, sockaddr*, LPINT,
                                      LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
using WSASendFn = int (WSAAPI *)(SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD, LPWSAOVERLAPPED,
                                  LPWSAOVERLAPPED_COMPLETION_ROUTINE);
using WSARecvFn = int (WSAAPI *)(SOCKET, LPWSABUF, DWORD, LPDWORD, LPDWORD, LPWSAOVERLAPPED,
                                  LPWSAOVERLAPPED_COMPLETION_ROUTINE);
using WSAGetOverlappedResultFn = BOOL (WSAAPI *)(SOCKET, LPWSAOVERLAPPED, LPDWORD, BOOL, LPDWORD);
using WSAIoctlFn = int (WSAAPI *)(SOCKET, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD,
                                   LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
using GetProcAddressFn = FARPROC (WINAPI *)(HMODULE, LPCSTR);

const GameAdapter* g_game = nullptr;
SocketFn g_socket = nullptr;
WSASocketWFn g_wsasocketw = nullptr;
ConnectFn g_connect = nullptr;
SendFn g_send = nullptr;
RecvFn g_recv = nullptr;
CloseSocketFn g_closesocket = nullptr;
SendToFn g_sendto = nullptr;
RecvFromFn g_recvfrom = nullptr;
GetAddrInfoFn g_getaddrinfo = nullptr;
GetHostByNameFn g_gethostbyname = nullptr;
WSASendToFn g_wsasendto = nullptr;
WSARecvFromFn g_wsarecvfrom = nullptr;
WSASendFn g_wsasend = nullptr;
WSARecvFn g_wsarecv = nullptr;
WSAGetOverlappedResultFn g_wsaoverlapped = nullptr;
WSAIoctlFn g_wsaioctl = nullptr;
LPFN_CONNECTEX g_connectex = nullptr;
LPFN_WSASENDMSG g_wsasendmsg = nullptr;
GetProcAddressFn g_getprocaddress = nullptr;
bool g_getproc_hooked = false;
bool g_export_hooks_installed = false;

SOCKET g_tracked[128] = {};
size_t g_tracked_count = 0;
SRWLOCK g_tracked_lock = SRWLOCK_INIT;

bool has_resolver(uint32_t resolver) { return g_game && (g_game->resolver_methods & resolver) != 0; }

const NetworkBindingDefinition* binding_definition(NetworkApi api) {
    if (!g_game) return nullptr;
    for (size_t i = 0; i < g_game->network_binding_count; ++i)
        if (g_game->network_bindings[i].api == api) return &g_game->network_bindings[i];
    return nullptr;
}

bool contains_ci(const char* value, const char* needle) {
    if (!value || !needle) return false;
    const size_t length = strlen(needle);
    for (const char* cursor = value; *cursor; ++cursor)
        if (_strnicmp(cursor, needle, length) == 0) return true;
    return false;
}

bool should_redirect(const char* host) {
    if (!host || !hook_config().redirect_ip_be || !g_game) return false;
    if (hook_config().redirect_all_dns) return true;
    for (const char* const* entry = g_game->redirect_hosts; entry && *entry; ++entry) {
        if ((*entry)[0] == '*' ? contains_ci(host, *entry + 1) : _stricmp(host, *entry) == 0) return true;
    }
    return false;
}

void format_address(const sockaddr* address, int length, char* output, size_t capacity) {
    if (address && length >= static_cast<int>(sizeof(sockaddr_in)) && address->sa_family == AF_INET) {
        const auto* ipv4 = reinterpret_cast<const sockaddr_in*>(address);
        const auto* bytes = reinterpret_cast<const unsigned char*>(&ipv4->sin_addr);
        snprintf(output, capacity, "%u.%u.%u.%u:%u", bytes[0], bytes[1], bytes[2], bytes[3], ntohs(ipv4->sin_port));
    } else {
        snprintf(output, capacity, "?fam=%d?", address ? address->sa_family : -1);
    }
}

bool is_redirect_address(const sockaddr* address, int length) {
    return address && length >= static_cast<int>(sizeof(sockaddr_in)) && address->sa_family == AF_INET &&
           reinterpret_cast<const sockaddr_in*>(address)->sin_addr.s_addr == hook_config().redirect_ip_be;
}

void track_socket(SOCKET socket) {
    AcquireSRWLockExclusive(&g_tracked_lock);
    bool found = false;
    for (size_t i = 0; i < g_tracked_count; ++i) if (g_tracked[i] == socket) { found = true; break; }
    if (!found && g_tracked_count < sizeof(g_tracked) / sizeof(g_tracked[0]))
        g_tracked[g_tracked_count++] = socket;
    ReleaseSRWLockExclusive(&g_tracked_lock);
}

bool is_tracked(SOCKET socket) {
    AcquireSRWLockShared(&g_tracked_lock);
    bool found = false;
    for (size_t i = 0; i < g_tracked_count; ++i) if (g_tracked[i] == socket) { found = true; break; }
    ReleaseSRWLockShared(&g_tracked_lock);
    return found;
}

void untrack_socket(SOCKET socket) {
    AcquireSRWLockExclusive(&g_tracked_lock);
    for (size_t i = 0; i < g_tracked_count; ++i) {
        if (g_tracked[i] == socket) { g_tracked[i] = g_tracked[--g_tracked_count]; break; }
    }
    ReleaseSRWLockExclusive(&g_tracked_lock);
}

void log_packet(const char* label, const sockaddr* address, int address_length, const void* data, int length, bool full) {
    char endpoint[64] = "?";
    format_address(address, address_length, endpoint, sizeof(endpoint));
    if (full && data && length > 0) {
        char prefix[128]; snprintf(prefix, sizeof(prefix), "[%s] %s", label, endpoint);
        shim_log_bytes(prefix, data, length);
    } else {
        shim_log("[net] %s %s len=%d", label, endpoint, length);
    }
}

int WSAAPI hooked_getaddrinfo(PCSTR node, PCSTR service, const ADDRINFOA* hints, PADDRINFOA* result) {
    if (!g_getaddrinfo) return EAI_FAIL;
    const int status = g_getaddrinfo(node, service, hints, result);
    if (!should_redirect(node) || status != 0 || !result || !*result) return status;
    int changed = 0;
    for (ADDRINFOA* item = *result; item; item = item->ai_next) {
        if (item->ai_family == AF_INET && item->ai_addr && item->ai_addrlen >= sizeof(sockaddr_in)) {
            reinterpret_cast<sockaddr_in*>(item->ai_addr)->sin_addr.s_addr = hook_config().redirect_ip_be;
            ++changed;
        }
    }
    shim_log("[redirect] %s -> %s (%d IPv4 result%s)", node, hook_config().redirect_ip, changed, changed == 1 ? "" : "s");
    return status;
}

hostent* WSAAPI hooked_gethostbyname(const char* name) {
    if (!g_gethostbyname) return nullptr;
    hostent* result = g_gethostbyname(name);
    if (!should_redirect(name) || !result || result->h_addrtype != AF_INET || !result->h_addr_list) return result;
    int changed = 0;
    for (char** item = result->h_addr_list; *item; ++item) {
        *reinterpret_cast<uint32_t*>(*item) = hook_config().redirect_ip_be;
        ++changed;
    }
    shim_log("[redirect] %s -> %s via gethostbyname (%d result%s)", name, hook_config().redirect_ip, changed,
             changed == 1 ? "" : "s");
    return result;
}

SOCKET WSAAPI hooked_socket(int family, int type, int protocol) {
    SOCKET result = g_socket(family, type, protocol);
    if (hook_config().log_rdv_full || hook_config().log_tcp_full)
        shim_log("[net] socket family=%d type=%d protocol=%d -> %llu", family, type, protocol,
                 static_cast<unsigned long long>(result));
    return result;
}

SOCKET WSAAPI hooked_wsasocketw(int family, int type, int protocol, LPWSAPROTOCOL_INFOW info, GROUP group, DWORD flags) {
    SOCKET result = g_wsasocketw(family, type, protocol, info, group, flags);
    if (hook_config().log_rdv_full || hook_config().log_tcp_full)
        shim_log("[net] WSASocketW family=%d type=%d protocol=%d -> %llu", family, type, protocol,
                 static_cast<unsigned long long>(result));
    return result;
}

int WSAAPI hooked_connect(SOCKET socket, const sockaddr* address, int length) {
    if (hook_config().capture_tcp && is_redirect_address(address, length)) track_socket(socket);
    if (hook_config().capture_tcp || hook_config().log_tcp_full) log_packet("connect", address, length, nullptr, 0, false);
    return g_connect(socket, address, length);
}

int WSAAPI hooked_send(SOCKET socket, const char* data, int length, int flags) {
    const int result = g_send(socket, data, length, flags);
    if (result > 0 && (hook_config().log_tcp_full || (hook_config().capture_tcp && is_tracked(socket))))
        shim_log_bytes("[tcp] send", data, result);
    return result;
}

int WSAAPI hooked_recv(SOCKET socket, char* data, int length, int flags) {
    const int result = g_recv(socket, data, length, flags);
    if (result > 0 && (hook_config().log_tcp_full || (hook_config().capture_tcp && is_tracked(socket))))
        shim_log_bytes("[tcp] recv", data, result);
    return result;
}

int WSAAPI hooked_closesocket(SOCKET socket) { untrack_socket(socket); return g_closesocket(socket); }

int WSAAPI hooked_sendto(SOCKET socket, const char* data, int length, int flags, const sockaddr* to, int to_length) {
    if (hook_config().log_rdv_full || hook_config().capture_tcp)
        log_packet("udp sendto", to, to_length, data, length, hook_config().log_rdv_full);
    return g_sendto(socket, data, length, flags, to, to_length);
}

int WSAAPI hooked_recvfrom(SOCKET socket, char* data, int length, int flags, sockaddr* from, int* from_length) {
    const int result = g_recvfrom(socket, data, length, flags, from, from_length);
    if (result > 0 && (hook_config().log_rdv_full || hook_config().capture_tcp))
        log_packet("udp recvfrom", from, from_length ? *from_length : 0, data, result, hook_config().log_rdv_full);
    return result;
}

int WSAAPI hooked_wsasendto(SOCKET socket, LPWSABUF buffers, DWORD count, LPDWORD sent, DWORD flags,
                            const sockaddr* to, int to_length, LPWSAOVERLAPPED overlap,
                            LPWSAOVERLAPPED_COMPLETION_ROUTINE completion) {
    if (buffers && count && (hook_config().log_rdv_full || hook_config().capture_tcp))
        log_packet("udp WSASendTo", to, to_length, buffers[0].buf, static_cast<int>(buffers[0].len), hook_config().log_rdv_full);
    return g_wsasendto(socket, buffers, count, sent, flags, to, to_length, overlap, completion);
}

int WSAAPI hooked_wsarecvfrom(SOCKET socket, LPWSABUF buffers, DWORD count, LPDWORD received, LPDWORD flags,
                              sockaddr* from, LPINT from_length, LPWSAOVERLAPPED overlap,
                              LPWSAOVERLAPPED_COMPLETION_ROUTINE completion) {
    const int status = g_wsarecvfrom(socket, buffers, count, received, flags, from, from_length, overlap, completion);
    if (status == 0 && received && *received && buffers && count && (hook_config().log_rdv_full || hook_config().capture_tcp))
        log_packet("udp WSARecvFrom", from, from_length ? *from_length : 0, buffers[0].buf,
                   static_cast<int>(*received), hook_config().log_rdv_full);
    return status;
}

int WSAAPI hooked_wsasend(SOCKET socket, LPWSABUF buffers, DWORD count, LPDWORD sent, DWORD flags,
                          LPWSAOVERLAPPED overlap, LPWSAOVERLAPPED_COMPLETION_ROUTINE completion) {
    if (buffers && count && hook_config().log_tcp_full) shim_log_bytes("[tcp] WSASend", buffers[0].buf, buffers[0].len);
    return g_wsasend(socket, buffers, count, sent, flags, overlap, completion);
}

int WSAAPI hooked_wsarecv(SOCKET socket, LPWSABUF buffers, DWORD count, LPDWORD received, LPDWORD flags,
                          LPWSAOVERLAPPED overlap, LPWSAOVERLAPPED_COMPLETION_ROUTINE completion) {
    const int status = g_wsarecv(socket, buffers, count, received, flags, overlap, completion);
    if (status == 0 && received && *received && buffers && count && hook_config().log_tcp_full)
        shim_log_bytes("[tcp] WSARecv", buffers[0].buf, *received);
    return status;
}

BOOL WSAAPI hooked_wsaoverlapped(SOCKET socket, LPWSAOVERLAPPED overlap, LPDWORD transferred, BOOL wait, LPDWORD flags) {
    return g_wsaoverlapped(socket, overlap, transferred, wait, flags);
}

BOOL PASCAL hooked_connectex(SOCKET socket, const sockaddr* name, int name_length, PVOID send_buffer,
                             DWORD send_length, LPDWORD sent, LPOVERLAPPED overlap) {
    if (is_redirect_address(name, name_length)) track_socket(socket);
    if (hook_config().log_tcp_full) log_packet("ConnectEx", name, name_length, send_buffer, send_length, true);
    return g_connectex(socket, name, name_length, send_buffer, send_length, sent, overlap);
}

INT WSAAPI hooked_wsasendmsg(SOCKET socket, LPWSAMSG message, DWORD flags, LPDWORD sent,
                             LPWSAOVERLAPPED overlap, LPWSAOVERLAPPED_COMPLETION_ROUTINE completion) {
    if (message && message->lpBuffers && message->dwBufferCount && hook_config().log_rdv_full)
        log_packet("udp WSASendMsg", message->name, message->namelen, message->lpBuffers[0].buf,
                   message->lpBuffers[0].len, true);
    return g_wsasendmsg(socket, message, flags, sent, overlap, completion);
}

int WSAAPI hooked_wsaioctl(SOCKET socket, DWORD code, LPVOID input, DWORD input_length, LPVOID output,
                           DWORD output_length, LPDWORD returned, LPWSAOVERLAPPED overlap,
                           LPWSAOVERLAPPED_COMPLETION_ROUTINE completion) {
    const int status = g_wsaioctl(socket, code, input, input_length, output, output_length, returned, overlap, completion);
    if (status == 0 && code == SIO_GET_EXTENSION_FUNCTION_POINTER && input && input_length >= sizeof(GUID) &&
        output && output_length >= sizeof(void*)) {
        const GUID& id = *static_cast<const GUID*>(input);
        if (IsEqualGUID(id, WSAID_CONNECTEX)) {
            g_connectex = *static_cast<LPFN_CONNECTEX*>(output);
            *static_cast<LPFN_CONNECTEX*>(output) = hooked_connectex;
            shim_log("[net] wrapped ConnectEx extension");
        } else if (IsEqualGUID(id, WSAID_WSASENDMSG)) {
            g_wsasendmsg = *static_cast<LPFN_WSASENDMSG*>(output);
            *static_cast<LPFN_WSASENDMSG*>(output) = hooked_wsasendmsg;
            shim_log("[net] wrapped WSASendMsg extension");
        }
    }
    return status;
}

struct Binding {
    NetworkApi api;
    const char* label;
    void* hook;
    void** original;
};

Binding kBindings[] = {
    {NetworkApi::AddrInfoLookup, "getaddrinfo", reinterpret_cast<void*>(hooked_getaddrinfo), reinterpret_cast<void**>(&g_getaddrinfo)},
    {NetworkApi::GetHostByName, "gethostbyname", reinterpret_cast<void*>(hooked_gethostbyname), reinterpret_cast<void**>(&g_gethostbyname)},
    {NetworkApi::Socket, "socket", reinterpret_cast<void*>(hooked_socket), reinterpret_cast<void**>(&g_socket)},
    {NetworkApi::WSASocketW, "WSASocketW", reinterpret_cast<void*>(hooked_wsasocketw), reinterpret_cast<void**>(&g_wsasocketw)},
    {NetworkApi::Connect, "connect", reinterpret_cast<void*>(hooked_connect), reinterpret_cast<void**>(&g_connect)},
    {NetworkApi::Send, "send", reinterpret_cast<void*>(hooked_send), reinterpret_cast<void**>(&g_send)},
    {NetworkApi::Recv, "recv", reinterpret_cast<void*>(hooked_recv), reinterpret_cast<void**>(&g_recv)},
    {NetworkApi::CloseSocket, "closesocket", reinterpret_cast<void*>(hooked_closesocket), reinterpret_cast<void**>(&g_closesocket)},
    {NetworkApi::SendTo, "sendto", reinterpret_cast<void*>(hooked_sendto), reinterpret_cast<void**>(&g_sendto)},
    {NetworkApi::RecvFrom, "recvfrom", reinterpret_cast<void*>(hooked_recvfrom), reinterpret_cast<void**>(&g_recvfrom)},
    {NetworkApi::WSASendTo, "WSASendTo", reinterpret_cast<void*>(hooked_wsasendto), reinterpret_cast<void**>(&g_wsasendto)},
    {NetworkApi::WSARecvFrom, "WSARecvFrom", reinterpret_cast<void*>(hooked_wsarecvfrom), reinterpret_cast<void**>(&g_wsarecvfrom)},
    {NetworkApi::WSASend, "WSASend", reinterpret_cast<void*>(hooked_wsasend), reinterpret_cast<void**>(&g_wsasend)},
    {NetworkApi::WSARecv, "WSARecv", reinterpret_cast<void*>(hooked_wsarecv), reinterpret_cast<void**>(&g_wsarecv)},
    {NetworkApi::WSAGetOverlappedResult, "WSAGetOverlappedResult", reinterpret_cast<void*>(hooked_wsaoverlapped), reinterpret_cast<void**>(&g_wsaoverlapped)},
    {NetworkApi::WSAIoctl, "WSAIoctl", reinterpret_cast<void*>(hooked_wsaioctl), reinterpret_cast<void**>(&g_wsaioctl)},
};

bool dynamic_interceptor_needed() {
    const HookConfig& config = hook_config();
    bool dynamic_network = false;
    if (config.redirect_ip_be && g_game) {
        for (size_t i = 0; i < g_game->network_binding_count; ++i) {
            if (g_game->network_bindings[i].resolver_methods & ResolverGetProc) {
                dynamic_network = true;
                break;
            }
        }
    }
    return dynamic_network || config.trace_getprocaddr || config.trace_cng || config.trace_cng_payload ||
           config.capture_uplay || config.trace_uplay;
}

FARPROC WINAPI hooked_getprocaddress(HMODULE module, LPCSTR requested) {
    FARPROC resolved = g_getprocaddress ? g_getprocaddress(module, requested) : GetProcAddress(module, requested);
    const uintptr_t value = reinterpret_cast<uintptr_t>(requested);
    const bool ordinal = value <= 0xffff;
    if (hook_config().trace_getprocaddr) {
        if (ordinal) shim_log("[getprocaddr] module=%p ordinal=%llu -> %p", module,
                              static_cast<unsigned long long>(value), reinterpret_cast<void*>(resolved));
        else shim_log("[getprocaddr] module=%p %s -> %p", module, requested, reinterpret_cast<void*>(resolved));
    }
    if (resolved && module == GetModuleHandleA("ws2_32.dll")) {
        for (Binding& binding : kBindings) {
            const NetworkBindingDefinition* definition = binding_definition(binding.api);
            if (!definition || !(definition->resolver_methods & ResolverGetProc)) continue;
            const bool matches = ordinal ? definition->ordinal && value == definition->ordinal
                                         : definition->name && _stricmp(requested, definition->name) == 0;
            if (!matches) continue;
            if (!*binding.original) *binding.original = reinterpret_cast<void*>(resolved);
            shim_log("[hook] dynamically bound ws2_32!%s%s", binding.label,
                     ordinal ? " by ordinal" : "");
            return reinterpret_cast<FARPROC>(binding.hook);
        }
    }
    if (g_game && g_game->wrap_dynamic_symbol)
        return g_game->wrap_dynamic_symbol(module, requested, resolved);
    return resolved;
}

void install_getproc_hook(HMODULE game_module) {
    if (g_getproc_hooked || !has_resolver(ResolverGetProc) || !dynamic_interceptor_needed()) return;
    const char* import_modules[] = {"KERNEL32.dll", "KERNELBASE.dll", nullptr};
    for (const char** imported = import_modules; *imported; ++imported) {
        if (void* original = patch_iat(game_module, *imported, "GetProcAddress", reinterpret_cast<void*>(hooked_getprocaddress))) {
            g_getprocaddress = reinterpret_cast<GetProcAddressFn>(original);
            g_getproc_hooked = true;
            shim_log("[hook] dynamic symbol interceptor installed through %s", *imported);
            return;
        }
    }
    shim_log("[hook] dynamic symbol interceptor unavailable in target IAT");
}

#if defined(_WIN64)
void* detour_export(void* target, void* replacement, const char* label) {
    if (!target || IsBadReadPtr(target, 5)) return nullptr;
    auto* trampoline = static_cast<BYTE*>(VirtualAlloc(nullptr, 32, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if (!trampoline) return nullptr;
    memcpy(trampoline, target, 5);
    trampoline[5] = 0xFF; trampoline[6] = 0x25;
    *reinterpret_cast<uint32_t*>(trampoline + 7) = 0;
    *reinterpret_cast<uint64_t*>(trampoline + 11) = reinterpret_cast<uintptr_t>(target) + 5;
    const intptr_t displacement = reinterpret_cast<intptr_t>(replacement) - (reinterpret_cast<intptr_t>(target) + 5);
    if (displacement < INT32_MIN || displacement > INT32_MAX) { VirtualFree(trampoline, 0, MEM_RELEASE); return nullptr; }
    DWORD old = 0;
    if (!VirtualProtect(target, 5, PAGE_EXECUTE_READWRITE, &old)) { VirtualFree(trampoline, 0, MEM_RELEASE); return nullptr; }
    static_cast<BYTE*>(target)[0] = 0xE9;
    *reinterpret_cast<int32_t*>(static_cast<BYTE*>(target) + 1) = static_cast<int32_t>(displacement);
    DWORD ignored = 0; VirtualProtect(target, 5, old, &ignored);
    FlushInstructionCache(GetCurrentProcess(), target, 5);
    shim_log("[hook] inline-hooked %s", label);
    return trampoline;
}
#endif

void install_export_hooks() {
    if (g_export_hooks_installed || !has_resolver(ResolverExportDetour)) return;
#if defined(_WIN64)
    HMODULE ws2 = GetModuleHandleA("ws2_32.dll");
    if (!ws2) { shim_log("[hook] ws2_32 unavailable for export detours"); return; }
    bool any = false;
    for (Binding& binding : kBindings) {
        const NetworkBindingDefinition* definition = binding_definition(binding.api);
        if (!definition || !(definition->resolver_methods & ResolverExportDetour) ||
            *binding.original || !definition->name) continue;
        void* target = reinterpret_cast<void*>(GetProcAddress(ws2, definition->name));
        if (void* trampoline = detour_export(target, binding.hook, definition->name)) {
            *binding.original = trampoline;
            any = true;
        }
    }
    g_export_hooks_installed = any;
    if (!any) shim_log("[hook] no ws2 export detours were installed");
#else
    shim_log("[hook] export detours requested for unsupported x86 profile");
#endif
}

void install_iat_hooks(HMODULE game_module) {
    if (!has_resolver(ResolverIat)) return;
    int installed = 0;
    for (Binding& binding : kBindings) {
        const NetworkBindingDefinition* definition = binding_definition(binding.api);
        if (!definition || !(definition->resolver_methods & ResolverIat) || *binding.original) continue;
        void* original = definition->name
            ? patch_iat(game_module, "WS2_32.dll", definition->name, binding.hook) : nullptr;
        if (!original && definition->ordinal)
            original = patch_iat_ordinal(game_module, "WS2_32.dll", definition->ordinal, binding.hook);
        if (original) { *binding.original = original; ++installed; }
    }
    shim_log("[hook] installed %d common Winsock IAT hook%s", installed, installed == 1 ? "" : "s");
}
}

void configure_networking(const GameAdapter& adapter) { g_game = &adapter; }

bool early_network_hooks_needed() {
    return g_game && has_resolver(ResolverGetProc) && dynamic_interceptor_needed();
}

void install_early_network_hooks(HMODULE game_module) {
    if (!g_game || !game_module) return;
    install_getproc_hook(game_module);
}

void install_network_hooks(HMODULE game_module) {
    if (!g_game || !game_module) return;
    install_iat_hooks(game_module);
    install_getproc_hook(game_module);
    install_export_hooks();
}
