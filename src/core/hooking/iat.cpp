#include "core/hooking/iat.h"
#include "core/logging.h"

#include <cstring>

namespace {
void* patch_iat_impl(HMODULE module, const char* imported_dll, const char* imported_name,
                     WORD imported_ordinal, void* replacement) {
    auto* base = reinterpret_cast<BYTE*>(module);
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (!module || dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;
    const auto& directory = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!directory.VirtualAddress || !directory.Size) return nullptr;
    auto* descriptor = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(base + directory.VirtualAddress);
    for (; descriptor->Name; ++descriptor) {
        if (_stricmp(reinterpret_cast<const char*>(base + descriptor->Name), imported_dll) != 0) continue;
        auto* names = reinterpret_cast<IMAGE_THUNK_DATA*>(base + (descriptor->OriginalFirstThunk ? descriptor->OriginalFirstThunk : descriptor->FirstThunk));
        auto* slots = reinterpret_cast<IMAGE_THUNK_DATA*>(base + descriptor->FirstThunk);
        for (; names->u1.AddressOfData; ++names, ++slots) {
            bool matches = false;
            if (IMAGE_SNAP_BY_ORDINAL(names->u1.Ordinal)) {
                matches = imported_ordinal && IMAGE_ORDINAL(names->u1.Ordinal) == imported_ordinal;
            } else if (imported_name) {
                auto* name = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(base + names->u1.AddressOfData);
                matches = _stricmp(reinterpret_cast<const char*>(name->Name), imported_name) == 0;
            }
            if (!matches) continue;
            DWORD old_protection = 0;
            if (!VirtualProtect(&slots->u1.Function, sizeof(slots->u1.Function), PAGE_READWRITE, &old_protection)) {
                shim_log("[iat] cannot patch %s!%s: %lu", imported_dll,
                         imported_name ? imported_name : "ordinal", GetLastError());
                return nullptr;
            }
            void* original = reinterpret_cast<void*>(static_cast<UINT_PTR>(slots->u1.Function));
            slots->u1.Function = reinterpret_cast<ULONG_PTR>(replacement);
            DWORD ignored = 0; VirtualProtect(&slots->u1.Function, sizeof(slots->u1.Function), old_protection, &ignored);
            FlushInstructionCache(GetCurrentProcess(), &slots->u1.Function, sizeof(slots->u1.Function));
            if (imported_name) shim_log("[iat] %s!%s patched", imported_dll, imported_name);
            else shim_log("[iat] %s ordinal %u patched", imported_dll, imported_ordinal);
            return original;
        }
    }
    if (imported_name) shim_log("[iat] %s!%s not imported by target", imported_dll, imported_name);
    else shim_log("[iat] %s ordinal %u not imported by target", imported_dll, imported_ordinal);
    return nullptr;
}
}

void* patch_iat(HMODULE module, const char* imported_dll, const char* imported_name, void* replacement) {
    return patch_iat_impl(module, imported_dll, imported_name, 0, replacement);
}

void* patch_iat_ordinal(HMODULE module, const char* imported_dll, WORD imported_ordinal, void* replacement) {
    return patch_iat_impl(module, imported_dll, nullptr, imported_ordinal, replacement);
}
