# Ubisoft LAN setup

This guide covers the consolidated shim for Ubisoft Games. The server and Uplay emulator are separate projects. This repository provides the per-game Bink proxy that redirects Ubisoft services and bypasses the certificate verifier.

## Network layout

Run one shared server stack on the LAN host. Point every game client—including the client running on the server machine—at that machine's LAN address, such as `192.168.1.50`. Do not use `127.0.0.1`, because the other clients must reach the same Storm broker.

| Port | Protocol | Purpose |
| --- | --- | --- |
| 443 | TCP/TLS | UbiServices REST and WebSocket |
| 11000, 11001 | UDP | Storm detect |
| 11005 | UDP | Storm traversal |
| 12000 | UDP | Storm relay |
| 47100 | UDP | Uplay emulator/CoopNet LAN discovery |
| 9000 | UDP | Direct game data path used by the existing setup |

Allow the applicable ports through the host firewall. The ServerEmus configuration used by the original setup was:

```json
{
  "Servers": [
    { "Name": "UbiServices",    "Port": 443,   "UseUDP": false, "UseCerts": true  },
    { "Name": "StormDetect01",  "Port": 11000, "UseUDP": true,  "UseCerts": false },
    { "Name": "StormDetect02",  "Port": 11001, "UseUDP": true,  "UseCerts": false },
    { "Name": "StormTraversal", "Port": 11005, "UseUDP": true,  "UseCerts": false },
    { "Name": "StormRelay",     "Port": 12000, "UseUDP": true,  "UseCerts": false }
  ],
  "CertDetails": [
    { "Name": "UbisoftCert", "Password": "", "IsMainCert": true }
  ]
}
```

Place `UbisoftCert.crt` and `UbisoftCert.key` in the server's `Cert` directory. A self-signed certificate is expected, but a client accepts it only when the correct game profile has a verified TLS bypass and `bypass_tls_verify=1`.

## Install

For each game, rename its original Bink library once, then copy the matching artifact and `hook.config` beside the game executable:

| Game | Shim artifact | Preserve original as |
| --- | --- | --- |
| Far Cry 3 | `build/x86/farcry3_shim/binkw32.dll` | `binkw32_real.dll` |
| Far Cry 4 | `build/x64/farcry4_shim/bink2w64.dll` | `bink2w64_real.dll` |
| Far Cry 5 | `build/x64/farcry5_shim/bink2w64.dll` | `bink2w64_real.dll` |
| Far Cry New Dawn | `build/x64/farcrynewdawn_shim/bink2w64.dll` | `bink2w64_real.dll` |

The three x64 files have the same filename but are not interchangeable. Their export tables and game adapters differ.

## Game profiles and TLS RVAs

These values are relative to the listed module.

| Game/profile | Main module | Resolver strategy | TLS verifier RVA and behavior |
| --- | --- | --- | --- |
| Far Cry 3 (`fc3-pc-2018`) | `FC3_d3d11.dll` or `FC3.dll` | Static IAT plus dynamic `GetProcAddress`; classic Winsock names and ordinals | No safe default. A verified override also needs the x86 `__stdcall` argument-byte count. |
| Far Cry 4 (`fc4-fc64-rva-024134f0`) | `FC64.dll` | Direct `ws2_32` export detours because the packed module's import table is unusable | `0x024134f0`, `X509_verify_cert`; forced success with per-thread hardware breakpoints. |
| Far Cry 5 (`fc5-fc_m64-rva-03e01eb0`) | `FC_m64.dll` | Early `GetProcAddress` interception; `getaddrinfo` by name and `gethostbyname` by ordinal 52 | `0x03e01eb0`; forced success and clears the verifier error field at object offset `0x17c`. |
| Far Cry New Dawn (`fcnd-fc_m64-67ef9b27`) | `FC_m64.dll` | Static Winsock IAT, including `gethostbyname` ordinal 52 | `0x03e07d00`; forced success and clears the verifier error field at object offset `0x17c`. |

Do not copy an RVA from one game or executable update to another. The shim logs the module PE timestamp and image size so a failing report can identify the actual build. For an updated supported build, add a new definition below the game's `versions/` directory rather than replacing an unrelated profile.

## Client `hook.config`

The minimum configuration for FC4, FC5, and New Dawn is:

```ini
redirect_ip=192.168.1.50
bypass_tls_verify=1
```

Far Cry 3 has no default verifier address. Keep bypass disabled unless both values have been verified against that exact DLL:

```ini
redirect_ip=192.168.1.50
bypass_tls_verify=1
rva_tls_verify=0x01234567
tls_verify_stack_bytes=8
```

Common options:

| Key | Meaning |
| --- | --- |
| `redirect_ip` | IPv4 address returned for the game profile's Ubisoft service hosts. |
| `redirect_all_dns` | Redirect every IPv4 DNS result. Use only while discovering a missing hostname. |
| `bypass_tls_verify` | Enable the profile's verified certificate-verifier hook. |
| `rva_tls_verify` | Override the profile RVA for a separately verified build. |
| `tls_verify_stack_bytes` | FC3/x86 stack cleanup required when skipping a `__stdcall` verifier. |
| `capture_tcp` | Capture traffic associated with the redirected address. |
| `log_rdv_full` | Full UDP/Storm packet logging. |
| `log_tcp_full` | Full TCP logging. |
| `trace_getprocaddr` | Log dynamic API resolution. |
| `capture_uplay`, `trace_uplay` | Structured or broad Uplay SDK call diagnostics on FC5/New Dawn. |
| `trace_cng`, `trace_cng_payload` | FC5 BCrypt diagnostics. |
| `capture_ssl` | Decrypted SSL read/write capture where the game profile has verified RVAs (New Dawn currently). |
| `trace_game_log` | Enable the verified FC_m64 native game-log callback. |
| `dump_module` | Press F10 to dump the live game module beside the shim. |
| `trace_points` | FC3-only comma-separated `module:rva:label` INT3 trace points. |

## Uplay emulator

Install the matching Uplay emulator loader beside each game. Every machine must have a distinct `AccountId` and clients sharing an ID discard one another's LAN announcements. Set `Coop.IsHost` to `true` on the hosting client and `false` on the peer when the emulator supports those settings.

## Launch and verify

1. Start the REST and Storm server stack.
2. Launch both clients and inspect `hook.log` beside each shim.
3. Confirm a DNS redirect line appears for the server hostname.
4. Confirm the resolver strategy matches the table above.
5. Exercise an HTTPS request. `verifier bypass active` is logged on the first verifier call, not merely when the trap is armed.
6. Create the co-op session on the host and watch the emulator/Storm logs for both distinct accounts.

