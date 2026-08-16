#include "core/debug/module_dump.h"

#include "core/logging.h"

#include <cstdio>
#include <cstring>

namespace {
struct DumpRequest { HMODULE module; char output_name[64]; };

void dump_module(const DumpRequest& request) {
    auto* base = reinterpret_cast<BYTE*>(request.module);
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (!base || dos->e_magic != IMAGE_DOS_SIGNATURE) { shim_log("[dump] invalid module image"); return; }
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) { shim_log("[dump] invalid PE header"); return; }

    char executable[MAX_PATH] = {};
    GetModuleFileNameA(nullptr, executable, MAX_PATH);
    if (char* slash = strrchr(executable, '\\')) *slash = 0;
    char path[MAX_PATH] = {};
    snprintf(path, sizeof(path), "%s\\%s", executable, request.output_name);
    FILE* output = nullptr;
    fopen_s(&output, path, "wb");
    if (!output) { shim_log("[dump] cannot open %s", path); return; }

    constexpr DWORD kPage = 0x1000;
    BYTE zero[kPage] = {};
    size_t readable = 0;
    const DWORD size = nt->OptionalHeader.SizeOfImage;
    for (DWORD offset = 0; offset < size; offset += kPage) {
        MEMORY_BASIC_INFORMATION memory{};
        const SIZE_T remaining = size - offset;
        const SIZE_T amount = remaining < kPage ? remaining : kPage;
        const bool accessible = VirtualQuery(base + offset, &memory, sizeof(memory)) &&
            memory.State == MEM_COMMIT && !(memory.Protect & (PAGE_GUARD | PAGE_NOACCESS));
        fwrite(accessible ? base + offset : zero, 1, amount, output);
        if (accessible) readable += amount;
    }
    fclose(output);
    shim_log("[dump] wrote %s (%zu/%lu readable bytes)", path, readable, static_cast<unsigned long>(size));
}

DWORD WINAPI dump_watcher(LPVOID parameter) {
    auto* request = static_cast<DumpRequest*>(parameter);
    bool was_down = false;
    for (;;) {
        const bool down = (GetAsyncKeyState(VK_F10) & 0x8000) != 0;
        if (down && !was_down) dump_module(*request);
        was_down = down;
        Sleep(100);
    }
}
}

void install_module_dump_hotkey(HMODULE module, const char* output_name) {
    auto* request = new DumpRequest{module, {}};
    strncpy_s(request->output_name, output_name, _TRUNCATE);
    HANDLE worker = CreateThread(nullptr, 0, dump_watcher, request, 0, nullptr);
    if (worker) {
        CloseHandle(worker);
        shim_log("[dump] F10 live-module dump enabled (%s)", output_name);
    } else {
        shim_log("[dump] watcher creation failed: %lu", GetLastError());
        delete request;
    }
}
