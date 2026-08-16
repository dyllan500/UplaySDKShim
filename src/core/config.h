#pragma once

#include <cstdint>
#include <windows.h>

struct HookConfig {
    char redirect_ip[16] = {};
    uint32_t redirect_ip_be = 0;
    bool bypass_tls_verify = false;
    uint64_t rva_tls_verify = 0;
    uint32_t tls_verify_stack_bytes = 0;
    bool redirect_all_dns = false;
    bool capture_tcp = false;
    bool dump_module = false;

    // Optional diagnostics.  A game adapter decides which of these it uses.
    bool log_rdv_full = false;
    bool log_tcp_full = false;
    bool trace_getprocaddr = false;
    bool trace_cng = false;
    bool trace_cng_payload = false;
    bool trace_stack = false;
    bool capture_ssl = false;
    bool capture_uplay = false;
    bool dump_session_blob = false;
    bool trace_uplay = false;
    bool trace_tls_alert = false;
    bool dump_ssl_jumptable = false;
    bool trace_invite_dostart = false;
    bool trace_game_log = false;
    char trace_points[512] = {};
};

const HookConfig& hook_config();
void initialize_hook_config(HINSTANCE shim_module);
void set_hook_config(const HookConfig& config);
HookConfig load_hook_config();
void log_hook_config(const HookConfig& config);
