# OPNsense API user

Create a dedicated local user, for example `icinga-api`, and generate an API key
under **System > Access > Users**.

Do not grant WebGUI login or shell access unless required for a separate
purpose. Grant read privileges only for the checks that will be used. Confirm
the effective privileges on the user page; OPNsense shows the API endpoints
associated with each privilege.

API authentication uses HTTP Basic Authentication:

- username: API key
- password: API secret

The secret is stored as a protected Director Data Field and is not stored in a
plugin-side credential file.

## Endpoint matrix

| Check | Privilege on OPNsense 26.7 | Primary endpoint |
| --- | --- | --- |
| CPU | `Lobby: Dashboard` | `GET /api/diagnostics/cpu_usage/stream` |
| Memory | `Lobby: Dashboard` | `GET /api/diagnostics/system/system_resources`, `GET /api/diagnostics/system/system_swap` |
| Disk | `Lobby: Dashboard` | `GET /api/diagnostics/system/system_disk` |
| Services | `Status: Services` | `GET /api/core/service/search` |
| Updates | `System: Firmware` | `POST /api/core/firmware/check`, `GET /api/core/firmware/status` |
| Certificates | `System: Certificate Manager` | `GET /api/trust/cert/search`, `GET /api/trust/cert/get/<uuid>` |
| Interfaces | `Status: Interfaces` | `GET /api/interfaces/overview/export` |
| WireGuard | `VPN: WireGuard: Status` | `GET /api/wireguard/service/status`, `GET /api/wireguard/service/show` |
| Firewall | `Lobby: Dashboard` | `GET /api/diagnostics/firewall/pf_states` |

For OPNsense 24.7 and 25.x, the plugin retains the older camelCase diagnostic
endpoints as fallbacks. On OPNsense 26.7 the privilege-separated snake_case
endpoints are tried first so a monitoring user does not require `All pages`.
