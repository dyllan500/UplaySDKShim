#pragma once

#include "core/game_adapter.h"

namespace farcry3::current {
inline constexpr const char* kVersion = "fc3-pc-2018";
inline constexpr const char* kModules[] = {"FC3_d3d11.dll", "FC3.dll", nullptr};
inline constexpr const char* kHosts[] = {
    "cert-onlineconfigservice.ubi.com", "onlineconfigservice.ubi.com",
    "uat-onlineconfigservice.ubi.com", "fc3-bloomberg-server.ubisoft.org", nullptr
};
inline constexpr NetworkBindingDefinition kNetwork[] = {
    {NetworkApi::AddrInfoLookup, "getaddrinfo", 0, ResolverIat | ResolverGetProc},
    {NetworkApi::GetHostByName, "gethostbyname", 0, ResolverIat | ResolverGetProc},
    {NetworkApi::Connect, "connect", 4, ResolverIat | ResolverGetProc},
    {NetworkApi::Send, "send", 19, ResolverIat | ResolverGetProc},
    {NetworkApi::Recv, "recv", 16, ResolverIat | ResolverGetProc},
    {NetworkApi::CloseSocket, "closesocket", 3, ResolverIat | ResolverGetProc},
    {NetworkApi::SendTo, "sendto", 20, ResolverIat | ResolverGetProc},
    {NetworkApi::RecvFrom, "recvfrom", 17, ResolverIat | ResolverGetProc},
};
inline constexpr TlsHookDefinition kTls{0, TlsHookMethod::Int3ReturnTrue, 0, 0};
}
