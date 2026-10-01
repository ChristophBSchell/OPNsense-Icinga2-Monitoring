# check_opnsense

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Current version: **0.1**

Icinga/Nagios monitoring plugin for OPNsense 24.7 through 26.x using the
official OPNsense API.

## Checks

| Mode | Description |
| --- | --- |
| `cpu` | CPU utilisation |
| `memory` | RAM and swap utilisation |
| `disk` | System filesystem utilisation |
| `services` | State of selected services |
| `updates` | Available firmware, package and security updates |
| `certificates` | Expiry of certificates stored in OPNsense or the WebGUI TLS certificate |
| `interfaces` | Link state, errors, drops and traffic counters |
| `wireguard` | WireGuard service and instances; peer state is informational |
| `firewall` | PF status, state-table utilisation and packet drops |

The plugin uses only Python's standard library and emits Nagios performance
data where meaningful.

## Installation

```bash
install -m 0755 check_opnsense.py /usr/lib/nagios/plugins/check_opnsense.py
```

Test the API connection:

```bash
/usr/lib/nagios/plugins/check_opnsense.py \
  --host firewall.example.net \
  --api-key 'API_KEY' \
  --api-secret 'API_SECRET' \
  --mode cpu
```

For an internal CA, either install the CA on the Icinga host and specify
`--ca-file`, or use `--insecure`. Disabling certificate verification is not
recommended for production.

## Director import

1. Upload `director/check_opnsense-basket.json` under
   **Icinga Director > Configuration Baskets**.
2. Open the uploaded basket snapshot and click **Restore**. Uploading alone
   does not create the objects.
3. Verify that the restore preview lists one Command, ten Service Templates and
   the OPNsense Data Fields, then confirm the restore.
4. Deploy the Director configuration.
5. Import or apply `director/services.conf.example` as described in that file.
6. Assign the Service Set `OPNsense Monitoring` to the OPNsense host or host
   template.
7. Set `OPNsense API Host`, API key and API secret on the host or inherited
   host template.

The basket creates:

- Data Field category `OPNsense`
- all API and threshold Data Fields
- CheckCommand `check_opnsense`
- Master service template `OPNsense Service Master`
- nine derived service templates, one for every check mode
- Service Set `OPNsense Monitoring` containing all nine checks

Template inheritance:

```text
OPNsense Service Master
├── OPNsense CPU Template
├── OPNsense Memory Template
├── OPNsense Disk Template
├── OPNsense Services Template
├── OPNsense Updates Template
├── OPNsense Certificates Template
├── OPNsense Interfaces Template
├── OPNsense WireGuard Template
└── OPNsense Firewall Template
```

Each service in the Service Set imports its matching derived template. The
check mode is stored in that template rather than directly on the service.

Assign the Service Set `OPNsense Monitoring` to an OPNsense host or host
template. Individual services can then be adjusted or disabled in Director as
needed.

The API secret is a protected Director field and is passed directly to the
process. It is not read from a file.

`OPNsense API Host` defines the DNS name or IP address used by `--host`.
It is independent from Icinga's built-in `$address$` host property.

## Required OPNsense API permissions

Create a dedicated, non-interactive OPNsense user and API key. Grant only the
privileges required by the checks in use. Depending on the installed OPNsense
release, the privilege names can vary slightly. The relevant read endpoints
are:

- `/api/diagnostics/cpu_usage/*`
- `/api/diagnostics/system/*`
- `/api/diagnostics/interface/*`
- `/api/core/service/search`
- `/api/core/firmware/*`
- `/api/trust/cert/*`
- `/api/wireguard/service/*`
- `/api/diagnostics/firewall/*`

The `updates` check invokes OPNsense's read-only firmware check operation. No
upgrade or package installation is performed.

## Multi-value fields

The following options may be repeated and are represented as Director arrays:

- `--service`
- `--interface`
- `--wireguard-instance`
- `--wireguard-peer`
- `--certificate`
- `--filesystem`

An empty array means "check all objects returned by the API".

## Examples

```bash
# Memory
check_opnsense.py -H fw.example.net -k KEY -s SECRET -m memory -w 80 -c 90

# Several services
check_opnsense.py -H fw.example.net -k KEY -s SECRET -m services \
  --service unbound --service wireguard

# WAN and LAN
check_opnsense.py -H fw.example.net -k KEY -s SECRET -m interfaces \
  --interface wan --interface lan --warning-errors 1 --critical-errors 10

# WireGuard peers; stale after 10 minutes, critical after 30
check_opnsense.py -H fw.example.net -k KEY -s SECRET -m wireguard \
  --wireguard-peer branch-a --wireguard-peer branch-b \
  --warning-age 600 --critical-age 1800

# Stored certificates
check_opnsense.py -H fw.example.net -k KEY -s SECRET -m certificates \
  --certificate webgui --warning-days 30 --critical-days 14

# WebGUI certificate only
check_opnsense.py -H fw.example.net -k KEY -s SECRET -m certificates \
  --tls-certificate-only --warning-days 30 --critical-days 14
```

## Exit codes

- `0`: OK
- `1`: WARNING
- `2`: CRITICAL
- `3`: UNKNOWN

## Compatibility notes

OPNsense responses have changed in detail between releases. The check accepts
the known response layouts used from 24.7 onward and uses compatible endpoint
fallbacks. The Trust API is preferred for stored certificates. The WebGUI TLS
certificate can always be checked independently with
`--tls-certificate-only`.

## Development

Run the tests with:

```bash
python3 -m unittest discover -s tests -v
```

Rebuild the Director basket after changing its source definition:

```bash
python3 tools/build_director_basket.py
```

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) and
[SECURITY.md](SECURITY.md).
