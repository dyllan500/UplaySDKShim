#include "core/logging.h"

#include <cstdarg>
#include <cstdio>
#include <cstring>

namespace { FILE* g_log = nullptr; char g_prefix[64] = "UPLAYSDKSHIM"; }

void initialize_logging(HINSTANCE self, const char* game_id) {
    strncpy_s(g_prefix, game_id, _TRUNCATE);
    char path[MAX_PATH] = {};
    GetModuleFileNameA(self, path, MAX_PATH);
    if (char* slash = strrchr(path, '\\')) *slash = 0;
    char log_path[MAX_PATH] = {};
    snprintf(log_path, sizeof(log_path), "%s\\hook.log", path);
    fopen_s(&g_log, log_path, "a");
    shim_log("========== %s new process ==========", game_id);
}

void shutdown_logging() { if (g_log) { fclose(g_log); g_log = nullptr; } }

void shim_log(const char* format, ...) {
    char message[2048] = {};
    va_list args; va_start(args, format); vsnprintf(message, sizeof(message), format, args); va_end(args);
    char line[2200] = {};
    SYSTEMTIME now{}; GetLocalTime(&now);
    snprintf(line, sizeof(line), "%02u:%02u:%02u.%03u | %s\n", now.wHour, now.wMinute, now.wSecond, now.wMilliseconds, message);
    char debug[2300] = {}; snprintf(debug, sizeof(debug), "%s: %s", g_prefix, line);
    OutputDebugStringA(debug);
    if (g_log) { fputs(line, g_log); fflush(g_log); }
}

void shim_log_bytes(const char* prefix, const void* data, int len) {
    if (!data || len <= 0) return;
    const auto* bytes = static_cast<const unsigned char*>(data);
    constexpr int kMax = 2048;
    char text[kMax * 2 + 1] = {};
    const int count = len < kMax ? len : kMax;
    for (int i = 0; i < count; ++i) snprintf(text + i * 2, 3, "%02x", bytes[i]);
    shim_log("%s len=%d %s%s", prefix, len, text, len > count ? "...(truncated)" : "");
}
