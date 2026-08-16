#pragma once

#include "core/game_adapter.h"

namespace farcry4::current {
inline constexpr const char* kVersion = "fc4-fc64-rva-024134f0";
inline constexpr const char* kModules[] = {"FC64.dll", nullptr};
inline constexpr const char* kHosts[] = {
    "api-ubiservices.ubi.com", "prod-api-ubiservices.ubi.com", "uat-api-ubiservices.ubi.com",
    "ubiservices.ubi.com", "uplay-ext.ubi.com", "bloomberg-fcpc-server.ubisoft.org", "shop.ubi.com", nullptr
};
inline constexpr NetworkBindingDefinition kNetwork[] = {
    {NetworkApi::AddrInfoLookup, "getaddrinfo", 0, ResolverIat | ResolverGetProc | ResolverExportDetour},
    {NetworkApi::GetHostByName, "gethostbyname", 0, ResolverIat | ResolverGetProc | ResolverExportDetour},
};
inline constexpr TlsHookDefinition kTls{
    0x024134f0, TlsHookMethod::HardwareBreakpointReturnTrue, 0, 0
};
}
