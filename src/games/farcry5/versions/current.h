#pragma once

#include "core/game_adapter.h"
#include "games/common/fc_m64_debug.h"

namespace farcry5::current {
inline constexpr const char* kVersion = "fc5-fc_m64-rva-03e01eb0";
inline constexpr const char* kModules[] = {"FC_m64.dll", nullptr};
inline constexpr const char* kHosts[] = {
    "*storm.ubi.com", "*mpe-traversal", "*mpe-detect",
    "public-ubiservices.ubi.com", "uat-public-ubiservices.ubi.com",
    "prod-public-ubiservices.ubi.com", "ubiservices.ubi.com",
    "public-ws-ubiservices.ubi.com", "msr-public-ubiservices.ubi.com", nullptr
};

inline constexpr NetworkBindingDefinition kNetwork[] = {
    {NetworkApi::Socket, "socket", 0, ResolverIat | ResolverGetProc},
    {NetworkApi::WSASocketW, "WSASocketW", 0, ResolverIat | ResolverGetProc},
    {NetworkApi::Connect, nullptr, 4, ResolverIat | ResolverGetProc},
    {NetworkApi::Recv, nullptr, 16, ResolverIat | ResolverGetProc},
    {NetworkApi::RecvFrom, nullptr, 17, ResolverIat | ResolverGetProc},
    {NetworkApi::Send, nullptr, 19, ResolverIat | ResolverGetProc},
    {NetworkApi::SendTo, nullptr, 20, ResolverIat | ResolverGetProc},
    {NetworkApi::AddrInfoLookup, "getaddrinfo", 0, ResolverIat | ResolverGetProc},
    {NetworkApi::GetHostByName, nullptr, 52, ResolverIat | ResolverGetProc},
    {NetworkApi::WSARecvFrom, "WSARecvFrom", 0, ResolverIat | ResolverGetProc},
    {NetworkApi::WSAGetOverlappedResult, "WSAGetOverlappedResult", 0, ResolverIat | ResolverGetProc},
    {NetworkApi::WSASendTo, "WSASendTo", 0, ResolverIat | ResolverGetProc},
    {NetworkApi::WSASend, "WSASend", 0, ResolverIat | ResolverGetProc},
    {NetworkApi::WSARecv, "WSARecv", 0, ResolverIat | ResolverGetProc},
    {NetworkApi::WSAIoctl, "WSAIoctl", 0, ResolverIat | ResolverGetProc},
};
inline constexpr TlsHookDefinition kTls{
    0x03e01eb0, TlsHookMethod::Int3ReturnTrueAndClearError, 0, 0x17c
};
inline constexpr FcM64DebugDefinition kDebug{0, 0, 0x00264d10, 0x075a3040, 0x00241520};
}
