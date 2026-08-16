#include "games/farcry3/tracer.h"
#include "core/config.h"
#include "core/logging.h"

#include <cstdint>
#include <cstring>
#include <cstdio>
#include <cstdlib>

namespace {

struct TracePoint {
    uintptr_t address = 0;
    BYTE original = 0;
    char label[64] = {};
};

constexpr int kMaxTracePoints = 16;
TracePoint g_points[kMaxTracePoints];
int g_point_count = 0;

uintptr_t g_pending_rearm = 0;

bool write_byte(void* address, BYTE value) {
    DWORD old_protection = 0;
    if (!VirtualProtect(address, 1, PAGE_EXECUTE_READWRITE, &old_protection)) return false;
    *(BYTE*)address = value;
    DWORD ignored = 0;
    VirtualProtect(address, 1, old_protection, &ignored);
    FlushInstructionCache(GetCurrentProcess(), address, 1);
    return true;
}

void describe_maybe_pointer(const char* tag, uint32_t value, char* out, size_t cap) {
    void* p = (void*)(uintptr_t)value;
    if (value < 0x10000 || IsBadReadPtr(p, 1)) {
        snprintf(out, cap, "%s=0x%08x", tag, value);
        return;
    }
    char buf[48] = {};
    size_t n = 0;
    for (; n < sizeof(buf) - 1; ++n) {
        if (IsBadReadPtr((const char*)p + n, 1)) break;
        char c = ((const char*)p)[n];
        if (c == '\0') break;
        if ((unsigned char)c < 0x20 || (unsigned char)c > 0x7e) { n = 0; break; }
        buf[n] = c;
    }
    if (n > 1) {
        snprintf(out, cap, "%s=0x%08x \"%s\"", tag, value, buf);
    } else {
        snprintf(out, cap, "%s=0x%08x", tag, value);
    }
}

LONG WINAPI handler(EXCEPTION_POINTERS* exception) {
    DWORD code = exception->ExceptionRecord->ExceptionCode;
    uintptr_t addr = (uintptr_t)exception->ExceptionRecord->ExceptionAddress;
    CONTEXT* ctx = exception->ContextRecord;

    if (code == EXCEPTION_SINGLE_STEP) {
        if (g_pending_rearm == 0) return EXCEPTION_CONTINUE_SEARCH;
        for (int i = 0; i < g_point_count; ++i) {
            if (g_points[i].address == g_pending_rearm) {
                write_byte((void*)g_points[i].address, 0xCC);
                break;
            }
        }
        g_pending_rearm = 0;
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    if (code != EXCEPTION_BREAKPOINT) return EXCEPTION_CONTINUE_SEARCH;

    const TracePoint* hit = nullptr;
    for (int i = 0; i < g_point_count; ++i) {
        if (g_points[i].address == addr) { hit = &g_points[i]; break; }
    }
    if (!hit) return EXCEPTION_CONTINUE_SEARCH;

    uint32_t* stack = (uint32_t*)ctx->Esp;
    char a0[80], a1[80], a2[80], a3[80], a4[80];
    bool stack_ok = !IsBadReadPtr(stack, 6 * sizeof(uint32_t));
    if (stack_ok) {
        describe_maybe_pointer("arg1", stack[1], a0, sizeof(a0));
        describe_maybe_pointer("arg2", stack[2], a1, sizeof(a1));
        describe_maybe_pointer("arg3", stack[3], a2, sizeof(a2));
        describe_maybe_pointer("arg4", stack[4], a3, sizeof(a3));
        describe_maybe_pointer("arg5", stack[5], a4, sizeof(a4));
    }
    char eax[80], ecx[80], edx[80];
    describe_maybe_pointer("eax", (uint32_t)ctx->Eax, eax, sizeof(eax));
    describe_maybe_pointer("ecx", (uint32_t)ctx->Ecx, ecx, sizeof(ecx));
    describe_maybe_pointer("edx", (uint32_t)ctx->Edx, edx, sizeof(edx));

    if (stack_ok) {
        shim_log("[trace] %s @ 0x%llx | %s %s %s | ret=0x%08x %s %s %s %s %s",
                 hit->label, (unsigned long long)addr, eax, ecx, edx,
                 stack[0], a0, a1, a2, a3, a4);
    } else {
        shim_log("[trace] %s @ 0x%llx | %s %s %s | (stack unreadable)",
                 hit->label, (unsigned long long)addr, eax, ecx, edx);
    }

    write_byte((void*)hit->address, hit->original);
    g_pending_rearm = hit->address;
    ctx->EFlags |= 0x100;
    return EXCEPTION_CONTINUE_EXECUTION;
}

bool g_handler_installed = false;

}

void install_trace_points() {
    if (!hook_config().trace_points[0]) return;
    if (!g_handler_installed) {
        if (!AddVectoredExceptionHandler(1, handler)) {
            shim_log("[trace] AddVectoredExceptionHandler failed: %lu", GetLastError());
            return;
        }
        g_handler_installed = true;
    }

    char buf[512];
    strncpy_s(buf, hook_config().trace_points, sizeof(buf) - 1);

    char* ctx = nullptr;
    char* tok = strtok_s(buf, ",", &ctx);
    while (tok && g_point_count < kMaxTracePoints) {
        char* modctx = nullptr;
        char* module_name = strtok_s(tok, ":", &modctx);
        char* rva_str     = strtok_s(nullptr, ":", &modctx);
        char* label       = strtok_s(nullptr, ":", &modctx);
        tok = strtok_s(nullptr, ",", &ctx);
        if (!module_name || !rva_str) {
            shim_log("[trace] malformed trace point entry, skipping");
            continue;
        }

        HMODULE mod = GetModuleHandleA(module_name);
        if (!mod) {
            shim_log("[trace] module '%s' not loaded yet — skipping '%s'",
                     module_name, label ? label : rva_str);
            continue;
        }

        uintptr_t rva = (uintptr_t)strtoull(rva_str, nullptr, 0);
        uintptr_t address = (uintptr_t)mod + rva;
        if (IsBadReadPtr((void*)address, 1)) {
            shim_log("[trace] %s+0x%llx is unreadable — skipping", module_name, (unsigned long long)rva);
            continue;
        }

        TracePoint& p = g_points[g_point_count];
        p.address = address;
        p.original = *(BYTE*)address;
        strncpy_s(p.label, label ? label : rva_str, sizeof(p.label) - 1);

        if (write_byte((void*)address, 0xCC)) {
            shim_log("[trace] armed '%s' at %s+0x%llx (0x%llx, original 0x%02x)",
                     p.label, module_name, (unsigned long long)rva,
                     (unsigned long long)address, p.original);
            ++g_point_count;
        } else {
            shim_log("[trace] failed to arm '%s' at 0x%llx", p.label, (unsigned long long)address);
        }
    }
}
