#include "core/debug/fault_logger.h"

#include "core/logging.h"

#include <cstdint>
#include <cstring>

namespace {
uintptr_t g_module_base = 0;
uintptr_t g_module_end = 0;
char g_game_id[32] = {};
LONG g_fault_count = 0;

const char* fault_name(DWORD code) {
    switch (code) {
    case EXCEPTION_ACCESS_VIOLATION: return "ACCESS_VIOLATION";
    case EXCEPTION_IN_PAGE_ERROR: return "IN_PAGE_ERROR";
    case EXCEPTION_ILLEGAL_INSTRUCTION: return "ILLEGAL_INSTRUCTION";
    case EXCEPTION_STACK_OVERFLOW: return "STACK_OVERFLOW";
    case EXCEPTION_INT_DIVIDE_BY_ZERO: return "DIVIDE_BY_ZERO";
    case EXCEPTION_PRIV_INSTRUCTION: return "PRIVILEGED_INSTRUCTION";
    default: return "OTHER";
    }
}

LONG WINAPI fault_handler(EXCEPTION_POINTERS* exception) {
    const DWORD code = exception->ExceptionRecord->ExceptionCode;
    if ((code & 0xf0000000u) != 0xc0000000u) return EXCEPTION_CONTINUE_SEARCH;
    const LONG number = InterlockedIncrement(&g_fault_count);
    if (number > 24) return EXCEPTION_CONTINUE_SEARCH;
    const uintptr_t address = reinterpret_cast<uintptr_t>(exception->ExceptionRecord->ExceptionAddress);
    const bool in_game = address >= g_module_base && address < g_module_end;
    shim_log("[fault] #%ld %s code=0x%08lx at=%p%s0x%llx tid=%lu", number,
             fault_name(code), static_cast<unsigned long>(code),
             exception->ExceptionRecord->ExceptionAddress,
             in_game ? " game_rva=" : " outside_game_rva=",
             static_cast<unsigned long long>(in_game ? address - g_module_base : 0),
             static_cast<unsigned long>(GetCurrentThreadId()));
    if ((code == EXCEPTION_ACCESS_VIOLATION || code == EXCEPTION_IN_PAGE_ERROR) &&
        exception->ExceptionRecord->NumberParameters >= 2) {
        const ULONG_PTR operation = exception->ExceptionRecord->ExceptionInformation[0];
        shim_log("[fault] %s of %p", operation == 0 ? "read" : operation == 1 ? "write" : "execute",
                 reinterpret_cast<void*>(exception->ExceptionRecord->ExceptionInformation[1]));
    }
    return EXCEPTION_CONTINUE_SEARCH;
}
}

void install_fault_logger(HMODULE game_module, const char* game_id) {
    auto* base = reinterpret_cast<BYTE*>(game_module);
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (!base || dos->e_magic != IMAGE_DOS_SIGNATURE) return;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;
    g_module_base = reinterpret_cast<uintptr_t>(base);
    g_module_end = g_module_base + nt->OptionalHeader.SizeOfImage;
    strncpy_s(g_game_id, game_id ? game_id : "game", _TRUNCATE);
    if (AddVectoredExceptionHandler(0, fault_handler))
        shim_log("[fault] first-chance fault logger installed for %s", g_game_id);
    else
        shim_log("[fault] first-chance fault logger registration failed: %lu", GetLastError());
}
