#pragma once

#include "core/game_adapter.h"
#include "games/common/fc_m64_debug.h"

namespace newdawn::current {
inline constexpr const char* kVersion = "fcnd-fc_m64-67ef9b27";
inline constexpr const char* kModules[] = {"FC_m64.dll", nullptr};
inline constexpr const char* kHosts[] = {
    "*storm.ubi.com", "*mpe-traversal", "*mpe-detect",
    "public-ubiservices.ubi.com", "uat-public-ubiservices.ubi.com",
    "prod-public-ubiservices.ubi.com", "ubiservices.ubi.com",
    "public-ws-ubiservices.ubi.com", "msr-public-ubiservices.ubi.com", nullptr
};
inline constexpr NetworkBindingDefinition kNetwork[] = {
    {NetworkApi::Connect, nullptr, 4},
    {NetworkApi::Recv, nullptr, 16},
    {NetworkApi::RecvFrom, nullptr, 17},
    {NetworkApi::Send, nullptr, 19},
    {NetworkApi::SendTo, nullptr, 20},
    {NetworkApi::WSARecvFrom, nullptr, 112},
    {NetworkApi::WSASendTo, nullptr, 116},
    {NetworkApi::AddrInfoLookup, "getaddrinfo", 0},
    {NetworkApi::GetHostByName, nullptr, 52},
};
inline constexpr TlsHookDefinition kTls{
    0x03e07d00, TlsHookMethod::Int3ReturnTrueAndClearError, 0, 0x17c
};
inline constexpr FcM64DebugDefinition kDebug{
    0x03dd6430, 0x03dd6880, 0x00264d10, 0x075a3040, 0x00241520
};
}
