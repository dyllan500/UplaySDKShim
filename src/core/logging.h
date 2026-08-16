#pragma once

#include <windows.h>

void initialize_logging(HINSTANCE self, const char* game_id);
void shutdown_logging();
void shim_log(const char* format, ...);
void shim_log_bytes(const char* prefix, const void* data, int len);
