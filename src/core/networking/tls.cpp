#include "core/networking/tls.h"

#include "core/config.h"
#include "core/game_adapter.h"
#include "core/logging.h"

#include <tlhelp32.h>
#include <cstdint>

namespace {
uintptr_t g_target = 0;
uintptr_t g_base = 0;
TlsHookDefinition g_definition{};
bool g_handler_installed = false;
#if defined(_WIN64)
DWORD g_armed_threads[1024] = {};
size_t g_armed_thread_count = 0;
#endif

bool write_byte(void* address, BYTE value) {
    DWORD old = 0;
    if (!VirtualProtect(address, 1, PAGE_EXECUTE_READWRITE, &old)) return false;
    *static_cast<BYTE*>(address) = value;
    DWORD ignored = 0; VirtualProtect(address, 1, old, &ignored);
    FlushInstructionCache(GetCurrentProcess(), address, 1);
    return true;
}

LONG WINAPI tls_handler(EXCEPTION_POINTERS* exception) {
    const DWORD code = exception->ExceptionRecord->ExceptionCode;
    const uintptr_t at = reinterpret_cast<uintptr_t>(exception->ExceptionRecord->ExceptionAddress);
    const bool software = code == EXCEPTION_BREAKPOINT && at == g_target;
#if defined(_WIN64)
    const bool hardware = code == EXCEPTION_SINGLE_STEP && at == g_target &&
                          (exception->ContextRecord->Dr6 & 1) != 0;
#else
    const bool hardware = false;
#endif
    if (!software && !hardware) return EXCEPTION_CONTINUE_SEARCH;

#if defined(_WIN64)
    CONTEXT* context = exception->ContextRecord;
    if (hardware) context->Dr6 = 0;
    if (g_definition.method == TlsHookMethod::Int3ReturnTrueAndClearError && context->Rcx &&
        !IsBadWritePtr(reinterpret_cast<void*>(context->Rcx + g_definition.error_field_offset), sizeof(int32_t)))
        *reinterpret_cast<int32_t*>(context->Rcx + g_definition.error_field_offset) = 0;
    const uintptr_t stack = context->Rsp;
    if (IsBadReadPtr(reinterpret_cast<void*>(stack), sizeof(uintptr_t))) return EXCEPTION_CONTINUE_SEARCH;
    context->Rax = 1;
    context->Rip = *reinterpret_cast<uintptr_t*>(stack);
    context->Rsp = stack + sizeof(uintptr_t);
#else
    CONTEXT* context = exception->ContextRecord;
    const uintptr_t stack = context->Esp;
    if (IsBadReadPtr(reinterpret_cast<void*>(stack), sizeof(uintptr_t))) return EXCEPTION_CONTINUE_SEARCH;
    const uint32_t argument_bytes = hook_config().tls_verify_stack_bytes
        ? hook_config().tls_verify_stack_bytes : g_definition.x86_stack_bytes;
    context->Eax = 1;
    context->Eip = *reinterpret_cast<uintptr_t*>(stack);
    context->Esp = stack + sizeof(uintptr_t) + argument_bytes;
#endif
    static LONG logged = 0;
    if (InterlockedExchange(&logged, 1) == 0)
        shim_log("[tls] verifier bypass active at RVA 0x%llx via %s",
                 static_cast<unsigned long long>(g_target - g_base), hardware ? "hardware breakpoint" : "INT3");
    return EXCEPTION_CONTINUE_EXECUTION;
}

#if defined(_WIN64)
bool thread_is_armed(DWORD id) {
    for (size_t i = 0; i < g_armed_thread_count; ++i) if (g_armed_threads[i] == id) return true;
    return false;
}

bool arm_thread(DWORD id) {
    if (id == GetCurrentThreadId() || thread_is_armed(id)) return false;
    HANDLE thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, id);
    if (!thread) return false;
    bool armed = false;
    if (SuspendThread(thread) != static_cast<DWORD>(-1)) {
        CONTEXT context{}; context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (GetThreadContext(thread, &context)) {
            context.Dr0 = g_target;
            context.Dr7 &= ~static_cast<DWORD64>(0xF << 16);
            context.Dr7 |= 1;
            context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            armed = SetThreadContext(thread, &context) != FALSE;
        }
        ResumeThread(thread);
    }
    CloseHandle(thread);
    if (armed && g_armed_thread_count < sizeof(g_armed_threads) / sizeof(g_armed_threads[0]))
        g_armed_threads[g_armed_thread_count++] = id;
    return armed;
}

int arm_process_threads() {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;
    THREADENTRY32 entry{}; entry.dwSize = sizeof(entry);
    const DWORD process = GetCurrentProcessId();
    int count = 0;
    if (Thread32First(snapshot, &entry)) {
        do {
            if (entry.th32OwnerProcessID == process && arm_thread(entry.th32ThreadID)) ++count;
        } while (Thread32Next(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return count;
}

DWORD WINAPI hardware_keepalive(LPVOID) {
    bool announced = false;
    for (int pass = 0; pass < 3600; ++pass) {
        const int count = arm_process_threads();
        if (count && !announced) {
            shim_log("[tls] hardware verifier breakpoint armed on %d thread%s", count, count == 1 ? "" : "s");
            announced = true;
        }
        Sleep(1000);
    }
    return 0;
}
#endif
}

void install_tls_bypass(HMODULE game_module, const TlsHookDefinition& definition) {
    if (!hook_config().bypass_tls_verify) { shim_log("[tls] verifier bypass disabled"); return; }
    const uint64_t rva = hook_config().rva_tls_verify ? hook_config().rva_tls_verify : definition.default_rva;
    if (!rva || definition.method == TlsHookMethod::None) {
        shim_log("[tls] no verified TLS hook definition for this build; bypass not armed");
        return;
    }
    g_base = reinterpret_cast<uintptr_t>(game_module);
    g_target = g_base + static_cast<uintptr_t>(rva);
    g_definition = definition;
    if (IsBadReadPtr(reinterpret_cast<void*>(g_target), 1)) {
        shim_log("[tls] configured verifier RVA 0x%llx is unreadable", static_cast<unsigned long long>(rva));
        return;
    }
    if (!g_handler_installed) {
        g_handler_installed = AddVectoredExceptionHandler(1, tls_handler) != nullptr;
        if (!g_handler_installed) { shim_log("[tls] vectored handler registration failed: %lu", GetLastError()); return; }
    }
    if (definition.method == TlsHookMethod::HardwareBreakpointReturnTrue) {
#if defined(_WIN64)
        HANDLE worker = CreateThread(nullptr, 0, hardware_keepalive, nullptr, 0, nullptr);
        if (worker) CloseHandle(worker);
        else shim_log("[tls] hardware-breakpoint worker creation failed: %lu", GetLastError());
#else
        shim_log("[tls] hardware breakpoint method is unavailable on x86");
#endif
        return;
    }
    const BYTE original = *reinterpret_cast<BYTE*>(g_target);
    if (write_byte(reinterpret_cast<void*>(g_target), 0xCC))
        shim_log("[tls] verifier trap armed at RVA 0x%llx (original=0x%02x)",
                 static_cast<unsigned long long>(rva), original);
    else
        shim_log("[tls] verifier page could not be patched at RVA 0x%llx", static_cast<unsigned long long>(rva));
}
