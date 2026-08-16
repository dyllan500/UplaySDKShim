#include "core/config.h"
#include "core/logging.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace {
HookConfig g_config;
HINSTANCE g_shim_module = nullptr;

void trim(char* text) {
    char* start = text;
    while (*start && std::isspace(static_cast<unsigned char>(*start))) ++start;
    if (start != text) memmove(text, start, strlen(start) + 1);
    size_t length = strlen(text);
    while (length && std::isspace(static_cast<unsigned char>(text[length - 1]))) text[--length] = 0;
}

bool bool_value(const char* value) { return atoi(value) != 0; }

void assign_bool(const char* key, const char* value, HookConfig& c, bool& known) {
    const bool enabled = bool_value(value);
#define CONFIG_BOOL(name) if (_stricmp(key, #name) == 0) { c.name = enabled; known = true; return; }
    CONFIG_BOOL(bypass_tls_verify)
    CONFIG_BOOL(redirect_all_dns)
    CONFIG_BOOL(capture_tcp)
    CONFIG_BOOL(dump_module)
    CONFIG_BOOL(log_rdv_full)
    CONFIG_BOOL(log_tcp_full)
    CONFIG_BOOL(trace_getprocaddr)
    CONFIG_BOOL(trace_cng)
    CONFIG_BOOL(trace_cng_payload)
    CONFIG_BOOL(trace_stack)
    CONFIG_BOOL(capture_ssl)
    CONFIG_BOOL(capture_uplay)
    CONFIG_BOOL(dump_session_blob)
    CONFIG_BOOL(trace_uplay)
    CONFIG_BOOL(trace_tls_alert)
    CONFIG_BOOL(dump_ssl_jumptable)
    CONFIG_BOOL(trace_invite_dostart)
    CONFIG_BOOL(trace_game_log)
#undef CONFIG_BOOL
}
}

const HookConfig& hook_config() { return g_config; }
void initialize_hook_config(HINSTANCE shim_module) { g_shim_module = shim_module; }
void set_hook_config(const HookConfig& config) { g_config = config; }

HookConfig load_hook_config() {
    HookConfig config{};
    char path[MAX_PATH] = {};
    GetModuleFileNameA(g_shim_module ? g_shim_module : nullptr, path, MAX_PATH);
    if (char* slash = strrchr(path, '\\')) *slash = 0;
    char config_path[MAX_PATH] = {};
    snprintf(config_path, sizeof(config_path), "%s\\hook.config", path);

    FILE* file = nullptr;
    fopen_s(&file, config_path, "r");
    if (!file) {
        shim_log("[config] no hook.config at %s; redirects and optional hooks are disabled", config_path);
        return config;
    }

    char line[640];
    while (fgets(line, sizeof(line), file)) {
        if (char* comment = strchr(line, '#')) *comment = 0;
        line[strcspn(line, "\r\n")] = 0;
        trim(line);
        if (!line[0]) continue;
        char* separator = strchr(line, '=');
        if (!separator) { shim_log("[config] ignored malformed entry '%s'", line); continue; }
        *separator = 0;
        char* key = line;
        char* value = separator + 1;
        trim(key); trim(value);
        bool known = false;
        assign_bool(key, value, config, known);
        if (known) continue;
        if (_stricmp(key, "redirect_ip") == 0) {
            strncpy_s(config.redirect_ip, value, _TRUNCATE);
            in_addr address{};
            if (inet_pton(AF_INET, config.redirect_ip, &address) == 1) config.redirect_ip_be = address.s_addr;
            else shim_log("[config] redirect_ip '%s' is not a valid IPv4 address", value);
        } else if (_stricmp(key, "rva_tls_verify") == 0 || _stricmp(key, "rva_ssl_verify") == 0) {
            config.rva_tls_verify = strtoull(value, nullptr, 0);
        } else if (_stricmp(key, "tls_verify_stack_bytes") == 0 || _stricmp(key, "ssl_verify_stack_bytes") == 0) {
            config.tls_verify_stack_bytes = static_cast<uint32_t>(strtoul(value, nullptr, 0));
        } else if (_stricmp(key, "trace_points") == 0) {
            strncpy_s(config.trace_points, value, _TRUNCATE);
        } else {
            shim_log("[config] unknown key '%s' ignored", key);
        }
    }
    fclose(file);
    return config;
}

void log_hook_config(const HookConfig& c) {
    shim_log("[config] redirect_ip=%s redirect_all_dns=%d bypass_tls_verify=%d rva_tls_verify=0x%llx",
             c.redirect_ip[0] ? c.redirect_ip : "-", static_cast<int>(c.redirect_all_dns),
             static_cast<int>(c.bypass_tls_verify), static_cast<unsigned long long>(c.rva_tls_verify));
}
