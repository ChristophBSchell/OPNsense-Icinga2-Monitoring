#!/usr/bin/env python3
"""Icinga/Nagios monitoring plugin for OPNsense 24.7 through 26.x."""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import json
import math
import re
import socket
import ssl
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Iterable

__version__ = "0.1"

OK, WARNING, CRITICAL, UNKNOWN = 0, 1, 2, 3
STATE_NAMES = {OK: "OK", WARNING: "WARNING", CRITICAL: "CRITICAL", UNKNOWN: "UNKNOWN"}


class CheckError(Exception):
    pass


class ApiError(CheckError):
    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


@dataclass
class Result:
    state: int
    summary: str
    details: list[str]
    perfdata: list[str]


def value_at(data: Any, *keys: str, default: Any = None) -> Any:
    if not isinstance(data, dict):
        return default
    lowered = {str(k).lower(): v for k, v in data.items()}
    for key in keys:
        if key in data:
            return data[key]
        if key.lower() in lowered:
            return lowered[key.lower()]
    return default


def to_float(value: Any, default: float = 0.0) -> float:
    if isinstance(value, bool):
        return float(value)
    if isinstance(value, (int, float)):
        return float(value)
    if value is None:
        return default
    match = re.search(r"-?\d+(?:[.,]\d+)?", str(value))
    return float(match.group(0).replace(",", ".")) if match else default


def to_int(value: Any, default: int = 0) -> int:
    return int(to_float(value, float(default)))


def is_true(value: Any) -> bool:
    return value is True or str(value).strip().lower() in {
        "1", "true", "yes", "on", "up", "running", "active", "enabled", "ok"
    }


def parse_size(value: Any) -> int:
    if isinstance(value, (int, float)):
        return int(value)
    text = str(value or "").strip()
    match = re.search(r"([\d.,]+)\s*([kmgtpe]?)(?:i?b)?", text, re.I)
    if not match:
        return 0
    number = float(match.group(1).replace(",", "."))
    power = {"": 0, "k": 1, "m": 2, "g": 3, "t": 4, "p": 5, "e": 6}[match.group(2).lower()]
    return int(number * (1024**power))


def percent(used: float, total: float) -> float:
    return used / total * 100.0 if total > 0 else 0.0


def threshold_state(value: float, warning: float, critical: float) -> int:
    if value >= critical:
        return CRITICAL
    if value >= warning:
        return WARNING
    return OK


def lower_threshold_state(value: float, warning: float, critical: float) -> int:
    if value <= critical:
        return CRITICAL
    if value <= warning:
        return WARNING
    return OK


def worst(states: Iterable[int]) -> int:
    ranking = {OK: 0, WARNING: 1, UNKNOWN: 2, CRITICAL: 3}
    values = list(states)
    return max(values, key=lambda state: ranking[state]) if values else OK


def perf_label(text: str) -> str:
    return "'" + str(text).replace("'", "_").replace(" ", "_") + "'"


def human_duration(seconds: float) -> str:
    seconds = max(0, int(seconds))
    days, seconds = divmod(seconds, 86400)
    hours, seconds = divmod(seconds, 3600)
    minutes, seconds = divmod(seconds, 60)
    if days:
        return f"{days}d {hours}h"
    if hours:
        return f"{hours}h {minutes}m"
    if minutes:
        return f"{minutes}m {seconds}s"
    return f"{seconds}s"


def rows(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [row for row in payload if isinstance(row, dict)]
    if not isinstance(payload, dict):
        return []
    for key in ("rows", "items", "data", "certificates", "services", "result"):
        candidate = value_at(payload, key)
        if isinstance(candidate, list):
            return [row for row in candidate if isinstance(row, dict)]
    return []


def find_numbers(data: Any, names: set[str]) -> list[float]:
    found: list[float] = []
    if isinstance(data, dict):
        for key, value in data.items():
            normalized = re.sub(r"[^a-z]", "", str(key).lower())
            if normalized in names and not isinstance(value, (dict, list)):
                found.append(to_float(value))
            found.extend(find_numbers(value, names))
    elif isinstance(data, list):
        for value in data:
            found.extend(find_numbers(value, names))
    return found


def parse_datetime(value: Any) -> dt.datetime | None:
    if value in (None, "", 0, "0", "-"):
        return None
    if isinstance(value, (int, float)) or str(value).isdigit():
        timestamp = float(value)
        if timestamp > 1e12:
            timestamp /= 1000
        try:
            return dt.datetime.fromtimestamp(timestamp, dt.timezone.utc)
        except (ValueError, OSError):
            return None
    text = str(value).strip().replace("Z", "+00:00")
    for parser in (
        lambda: dt.datetime.fromisoformat(text),
        lambda: dt.datetime.strptime(text, "%b %d %H:%M:%S %Y %Z"),
        lambda: dt.datetime.strptime(text, "%Y-%m-%d %H:%M:%S"),
    ):
        try:
            parsed = parser()
            return parsed.replace(tzinfo=parsed.tzinfo or dt.timezone.utc)
        except ValueError:
            pass
    return None


class OPNsenseAPI:
    def __init__(self, args: argparse.Namespace):
        self.base = f"https://{args.host}:{args.port}/api"
        auth = base64.b64encode(f"{args.api_key}:{args.api_secret}".encode()).decode()
        self.headers = {"Authorization": f"Basic {auth}", "Accept": "application/json"}
        self.timeout = args.timeout
        if args.insecure:
            self.context = ssl._create_unverified_context()
        else:
            self.context = ssl.create_default_context(cafile=args.ca_file)

    def request(self, endpoint: str, method: str = "GET", body: dict | None = None) -> Any:
        url = self.base + "/" + endpoint.lstrip("/")
        data = None
        headers = dict(self.headers)
        if method == "POST":
            data = json.dumps(body or {}).encode()
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=self.timeout, context=self.context) as response:
                raw = response.read()
        except urllib.error.HTTPError as exc:
            detail = exc.read(400).decode(errors="replace").strip()
            raise ApiError(f"HTTP {exc.code} for {endpoint}: {detail or exc.reason}", exc.code) from exc
        except urllib.error.URLError as exc:
            raise ApiError(f"cannot reach {self.base}: {exc.reason}") from exc
        except (TimeoutError, socket.timeout) as exc:
            raise ApiError(f"timeout after {self.timeout}s for {endpoint}") from exc
        try:
            return json.loads(raw.decode()) if raw else {}
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ApiError(f"invalid JSON from {endpoint}") from exc

    def stream_sample(self, endpoint: str) -> Any:
        """Read one JSON event from an OPNsense server-sent event stream."""
        url = self.base + "/" + endpoint.lstrip("/")
        request = urllib.request.Request(
            url, headers=dict(self.headers), method="GET"
        )
        try:
            with urllib.request.urlopen(
                request, timeout=self.timeout, context=self.context
            ) as response:
                for _ in range(100):
                    raw = response.readline(65536)
                    if not raw:
                        break
                    line = raw.decode(errors="replace").strip()
                    if not line or line.startswith(":"):
                        continue
                    if line.lower().startswith("data:"):
                        line = line[5:].strip()
                    try:
                        return json.loads(line)
                    except json.JSONDecodeError:
                        continue
        except urllib.error.HTTPError as exc:
            detail = exc.read(400).decode(errors="replace").strip()
            raise ApiError(
                f"HTTP {exc.code} for {endpoint}: {detail or exc.reason}",
                exc.code,
            ) from exc
        except urllib.error.URLError as exc:
            raise ApiError(f"cannot reach {self.base}: {exc.reason}") from exc
        except (TimeoutError, socket.timeout) as exc:
            raise ApiError(
                f"timeout after {self.timeout}s for {endpoint}"
            ) from exc
        raise ApiError(f"no JSON event returned by {endpoint}")

    def first(self, candidates: list[tuple[str, str, dict | None]]) -> Any:
        errors = []
        for endpoint, method, body in candidates:
            try:
                return self.request(endpoint, method, body)
            except ApiError as exc:
                errors.append(str(exc))
                if exc.status not in (404, 405) and "invalid JSON" not in str(exc):
                    raise
        raise ApiError("; ".join(errors))


def extract_usage(payload: Any, used_names: set[str], total_names: set[str]) -> tuple[float, float, float]:
    percentages = find_numbers(payload, {"usage", "usagepercent", "usedpercent", "percent", "percentage"})
    used = find_numbers(payload, used_names)
    total = find_numbers(payload, total_names)
    if percentages:
        return percentages[0], used[0] if used else 0, total[0] if total else 0
    if used and total:
        return percent(used[0], total[0]), used[0], total[0]
    return 0, 0, 0


def check_cpu(api: OPNsenseAPI, args: argparse.Namespace) -> Result:
    payload = api.stream_sample("diagnostics/cpu_usage/stream")
    # The CPU stream returned by current OPNsense releases contains the
    # percentages for user/nice/system/interrupt/idle and a `total` field.
    # `total` is always 100 and is not the utilisation value.
    values = find_numbers(
        payload,
        {"usage", "usagepercent", "percent", "percentage", "cpuusage"},
    )
    if values:
        usage = values[0]
    else:
        idle_values = find_numbers(payload, {"idle", "cpuidle", "idlepercent"})
        if idle_values:
            usage = 100.0 - idle_values[0]
        else:
            component_values = find_numbers(
                payload,
                {
                    "user", "nice", "system", "sys", "interrupt", "intr",
                    "irq", "softirq", "steal",
                },
            )
            if not component_values:
                raise CheckError("CPU usage not found in API response")
            usage = sum(component_values)
    if not 0 <= usage <= 100:
        raise CheckError(
            f"Invalid CPU usage {usage:g} returned by OPNsense API"
        )
    state = threshold_state(usage, args.warning, args.critical)
    return Result(state, f"CPU usage {usage:.1f}%", [], [
        f"'cpu'= {usage:.1f}%;{args.warning};{args.critical};0;100".replace("= ", "=")
    ])


def check_memory(api: OPNsenseAPI, args: argparse.Namespace) -> Result:
    memory = api.first([
        ("diagnostics/system/system_resources", "GET", None),
        ("diagnostics/system/systemResources", "GET", None),
        ("diagnostics/system/memory", "GET", None),
        ("diagnostics/interface/getMemoryStatistics", "GET", None),
        ("diagnostics/interface/get_memory_statistics", "GET", None),
    ])
    usage, used, total = extract_usage(
        memory,
        {"used", "memoryused", "active", "usedbytes"},
        {"total", "memorytotal", "realmemory", "totalbytes"},
    )
    if not usage and total:
        free = find_numbers(memory, {"free", "available", "memoryfree"})
        if free:
            used = total - free[0]
            usage = percent(used, total)
    swap_usage = 0.0
    try:
        swap = api.first([
            ("diagnostics/system/system_swap", "GET", None),
            ("diagnostics/system/systemSwap", "GET", None),
        ])
        swap_usage, _, _ = extract_usage(
            swap, {"used", "swapused"}, {"total", "swaptotal"}
        )
    except ApiError as exc:
        if exc.status not in (403, 404):
            raise
    state = worst([
        threshold_state(usage, args.warning, args.critical),
        threshold_state(swap_usage, args.warning, args.critical),
    ])
    detail = f"RAM {usage:.1f}%"
    if total:
        detail += f" ({used / 1024**2:.0f}/{total / 1024**2:.0f} MiB)"
    detail += f", swap {swap_usage:.1f}%"
    return Result(state, detail, [], [
        f"'memory'={usage:.1f}%;{args.warning};{args.critical};0;100",
        f"'swap'={swap_usage:.1f}%;{args.warning};{args.critical};0;100",
    ])


def disk_rows(payload: Any) -> list[dict[str, Any]]:
    candidates = rows(payload)
    if candidates:
        return candidates
    if isinstance(payload, dict):
        for value in payload.values():
            if isinstance(value, list) and value and isinstance(value[0], dict):
                return value
    return []


def check_disk(api: OPNsenseAPI, args: argparse.Namespace) -> Result:
    payload = api.first([
        ("diagnostics/system/system_disk", "GET", None),
        ("diagnostics/system/systemDisk", "GET", None),
    ])
    selected = set(args.filesystem)
    results, details, perf = [], [], []
    for item in disk_rows(payload):
        mount = str(value_at(item, "mountpoint", "mounted", "filesystem", "name", default="?"))
        if selected and mount not in selected:
            continue
        total = parse_size(value_at(item, "size", "total", "blocks"))
        used = parse_size(value_at(item, "used", "usedBytes", "used_bytes"))
        usage = to_float(value_at(item, "capacity", "usage", "used_pct", "usedPercent"))
        if "%" not in str(value_at(item, "capacity", default="")) and 0 < usage <= 1:
            usage *= 100
        if not usage and total:
            usage = percent(used, total)
        state = threshold_state(usage, args.warning, args.critical)
        results.append(state)
        details.append(f"{mount} {usage:.1f}%")
        perf.append(f"{perf_label('disk_' + mount)}={usage:.1f}%;{args.warning};{args.critical};0;100")
    missing = sorted(selected - {detail.split(" ", 1)[0] for detail in details})
    if missing:
        return Result(CRITICAL, f"filesystems not found: {', '.join(missing)}", details, perf)
    if not results:
        raise CheckError("no filesystem data returned")
    return Result(worst(results), f"{len(results)} filesystem(s): {', '.join(details)}", [], perf)


def service_rows(payload: Any) -> list[dict[str, Any]]:
    return rows(payload)


def check_services(api: OPNsenseAPI, args: argparse.Namespace) -> Result:
    payload = api.first([
        ("core/service/search", "GET", None),
        ("core/service/search", "POST", {"current": 1, "rowCount": -1, "searchPhrase": ""}),
    ])
    items = service_rows(payload)
    selected = set(args.service)
    seen, failed, stopped = set(), [], []
    for item in items:
        name = str(value_at(item, "name", "id", default=""))
        description = str(value_at(item, "description", default=name))
        if selected and name not in selected and description not in selected:
            continue
        seen.add(name)
        running = is_true(value_at(item, "running", "status", "active"))
        enabled_value = value_at(item, "enabled", default=True)
        enabled = is_true(enabled_value) if enabled_value is not True else True
        if enabled and not running:
            failed.append(name)
        elif not running:
            stopped.append(name)
    missing = sorted(selected - seen)
    if missing or failed:
        parts = []
        if failed:
            parts.append("not running: " + ", ".join(failed))
        if missing:
            parts.append("not found: " + ", ".join(missing))
        return Result(CRITICAL, "; ".join(parts), [], [f"'services_failed'={len(failed)+len(missing)};;;0;"])
    checked = len(seen) if selected else len(items)
    return Result(OK, f"{checked} service(s) running" + (f", {len(stopped)} inactive" if stopped else ""), [], [
        "'services_failed'=0;;;0;"
    ])


def update_count(payload: Any) -> tuple[int, int, list[str]]:
    packages: list[str] = []
    security = 0
    for item in rows(payload):
        name = str(value_at(item, "name", "package", default="unknown"))
        status = str(value_at(item, "status", "action", default="")).lower()
        current = value_at(item, "current_version", "installed", "current")
        remote = value_at(item, "new_version", "available", "remote")
        if status in {"upgrade", "update", "new", "reinstall"} or (remote and remote != current):
            packages.append(name)
            if is_true(value_at(item, "security", "vulnerable", default=False)):
                security += 1
    count_fields = find_numbers(payload, {"updates", "updatecount", "updatetotal", "upgradecount"})
    count = max(len(packages), int(max(count_fields, default=0)))
    return count, security, packages


def check_updates(api: OPNsenseAPI, args: argparse.Namespace) -> Result:
    payload = api.first([
        ("core/firmware/check", "POST", {}),
        ("core/firmware/status", "POST", {}),
        ("core/firmware/info", "GET", None),
    ])
    count, security, packages = update_count(payload)
    state = threshold_state(count, args.warning_updates, args.critical_updates)
    if security and args.security_critical:
        state = CRITICAL
    summary = f"{count} update(s) available"
    if security:
        summary += f", {security} security-related"
    details = ["Packages: " + ", ".join(packages[:50])] if packages else []
    return Result(state, summary, details, [
        f"'updates'={count};{args.warning_updates};{args.critical_updates};0;",
        f"'security_updates'={security};;;0;",
    ])


def certificate_expiry(item: dict[str, Any]) -> dt.datetime | None:
    for key in ("valid_to", "validTo", "not_after", "notAfter", "expires", "expiry", "validity"):
        value = value_at(item, key)
        parsed = parse_datetime(value)
        if parsed:
            return parsed
    return None


def tls_certificate(host: str, port: int, timeout: int, ca_file: str | None, insecure: bool) -> dict[str, Any]:
    context = ssl._create_unverified_context() if insecure else ssl.create_default_context(cafile=ca_file)
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
    except (OSError, ssl.SSLError) as exc:
        raise CheckError(f"TLS certificate query failed: {exc}") from exc
    subject = dict(part[0] for part in cert.get("subject", []))
    return {"name": subject.get("commonName", host), "not_after": cert.get("notAfter")}


def check_certificates(api: OPNsenseAPI, args: argparse.Namespace) -> Result:
    items: list[dict[str, Any]] = []
    if not args.tls_certificate_only:
        try:
            payload = api.first([
                ("trust/cert/search", "GET", None),
                ("trust/cert/search", "POST", {"current": 1, "rowCount": -1, "searchPhrase": ""}),
            ])
            items = rows(payload)
        except ApiError as exc:
            if exc.status not in (403, 404):
                raise
    if args.tls_certificate_only or not items:
        items.append(tls_certificate(args.host, args.port, args.timeout, args.ca_file, args.insecure))
    selected = set(args.certificate)
    now = dt.datetime.now(dt.timezone.utc)
    states, details, perf, seen = [], [], [], set()
    for item in items:
        name = str(value_at(item, "name", "descr", "description", "common_name", "cn", default="certificate"))
        uuid = str(value_at(item, "uuid", "refid", default=""))
        if selected and name not in selected and uuid not in selected:
            continue
        seen.update({name, uuid})
        expires = certificate_expiry(item)
        if not expires and uuid and not args.tls_certificate_only:
            try:
                detail = api.request(f"trust/cert/get/{uuid}")
                nested = value_at(detail, "cert", "certificate", default=detail)
                if isinstance(nested, dict):
                    expires = certificate_expiry(nested)
            except ApiError:
                pass
        if not expires:
            states.append(UNKNOWN)
            details.append(f"{name}: expiry unknown")
            continue
        days = math.floor((expires - now).total_seconds() / 86400)
        state = lower_threshold_state(days, args.warning_days, args.critical_days)
        states.append(state)
        details.append(f"{name}: {days}d")
        perf.append(f"{perf_label('cert_' + name)}={days}d;{args.warning_days};{args.critical_days};0;")
    missing = sorted(selected - seen)
    if missing:
        states.append(CRITICAL)
        details.append("not found: " + ", ".join(missing))
    if not states:
        raise CheckError("no matching certificates returned")
    return Result(worst(states), f"{len(states)} certificate(s): {', '.join(details)}", [], perf)


def interface_rows(payload: Any) -> list[dict[str, Any]]:
    direct = rows(payload)
    if direct:
        return direct
    result = []
    if isinstance(payload, dict):
        source = value_at(payload, "interfaces", default=payload)
        if isinstance(source, dict):
            for logical, item in source.items():
                if isinstance(item, dict):
                    row = dict(item)
                    row.setdefault("logical_name", logical)
                    result.append(row)
    return result


def interface_name(item: dict[str, Any]) -> tuple[str, str]:
    logical = str(value_at(item, "logical_name", "identifier", "descr", "description", default=""))
    device = str(value_at(item, "name", "device", "if", "interface", default=logical))
    return logical or device, device or logical


def check_interfaces(api: OPNsenseAPI, args: argparse.Namespace) -> Result:
    payload = api.first([
        ("interfaces/overview/export", "GET", None),
        ("diagnostics/interface/get_interface_statistics", "GET", None),
        ("diagnostics/interface/getInterfaceStatistics", "GET", None),
        ("diagnostics/interface/getInterfaceConfig", "GET", None),
    ])
    selected, seen = set(args.interface), set()
    states, details, perf = [], [], []
    for item in interface_rows(payload):
        logical, device = interface_name(item)
        if selected and logical not in selected and device not in selected:
            continue
        seen.update({logical, device})
        status = str(value_at(item, "status", "link_state", "linkstate", "up", default="up")).lower()
        # Explicitly map known down states; missing status is treated as up for old counter-only responses.
        down = status in {"down", "0", "false", "inactive", "no carrier", "unknown"}
        errors = sum(to_int(value_at(item, key)) for key in ("inerrs", "outerrs", "errors", "ierrors", "oerrors"))
        drops = sum(to_int(value_at(item, key)) for key in ("indrops", "outdrops", "drops", "iqdrops", "oqdrops"))
        state = CRITICAL if down else threshold_state(errors + drops, args.warning_errors, args.critical_errors)
        states.append(state)
        details.append(f"{logical}({device}) {'DOWN' if down else 'up'}, errors={errors}, drops={drops}")
        rx = to_int(value_at(item, "inbytes", "bytes_in", "ibytes", "rx_bytes"))
        tx = to_int(value_at(item, "outbytes", "bytes_out", "obytes", "tx_bytes"))
        perf.extend([
            f"{perf_label(logical + '_rx')}={rx}B;;;0;",
            f"{perf_label(logical + '_tx')}={tx}B;;;0;",
            f"{perf_label(logical + '_errors')}={errors};{args.warning_errors};{args.critical_errors};0;",
            f"{perf_label(logical + '_drops')}={drops};{args.warning_errors};{args.critical_errors};0;",
        ])
    missing = sorted(selected - seen)
    if missing:
        states.append(CRITICAL)
        details.append("not found: " + ", ".join(missing))
    if not states:
        raise CheckError("no matching interfaces returned")
    return Result(worst(states), "; ".join(details), [], perf)


def wireguard_peers(payload: Any) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    interfaces, peers = [], []
    source = value_at(payload, "rows", "data", "interfaces", default=payload)
    if isinstance(source, dict):
        for name, value in source.items():
            if not isinstance(value, dict):
                continue
            interface = dict(value)
            interface.setdefault("name", name)
            interfaces.append(interface)
            nested = value_at(value, "peers", default=[])
            if isinstance(nested, dict):
                nested = [dict(peer, name=peer_name) for peer_name, peer in nested.items() if isinstance(peer, dict)]
            if isinstance(nested, list):
                for peer in nested:
                    if isinstance(peer, dict):
                        copy = dict(peer)
                        copy.setdefault("interface", name)
                        peers.append(copy)
    elif isinstance(source, list):
        for item in source:
            if isinstance(item, dict):
                if value_at(item, "public-key", "public_key", "peer"):
                    peers.append(item)
                else:
                    interfaces.append(item)
    return interfaces, peers


def handshake_age(item: dict[str, Any]) -> float | None:
    value = value_at(
        item, "latest-handshake", "latest_handshake", "last_handshake",
        "handshake", "lastHandshake", "last_handshake_time"
    )
    parsed = parse_datetime(value)
    if parsed:
        return (dt.datetime.now(dt.timezone.utc) - parsed).total_seconds()
    numeric = to_float(value, -1)
    if numeric > 0:
        return numeric
    return None


def check_wireguard(api: OPNsenseAPI, args: argparse.Namespace) -> Result:
    service = api.first([
        ("wireguard/service/status", "GET", None),
        ("wireguard/service/show", "GET", None),
    ])
    status = value_at(service, "status", "running", "result", default=True)
    if isinstance(status, dict):
        status = value_at(status, "running", "status", default=True)
    show = api.first([
        ("wireguard/service/show", "GET", None),
        ("wireguard/service/status", "GET", None),
    ])
    interfaces, peers = wireguard_peers(show)
    # On current OPNsense releases WireGuard is implemented by kernel
    # interfaces. The generic service status can report it as stopped even
    # though configured interfaces are present and operational.
    if not is_true(status) and not interfaces and not peers:
        return Result(CRITICAL, "WireGuard service is not running", [], [])
    selected_instances, selected_peers = set(args.wireguard_instance), set(args.wireguard_peer)
    states, details, perf, seen_instances, seen_peers = [], [], [], set(), set()
    for interface in interfaces:
        name = str(value_at(interface, "name", "interface", "instance", default="unknown"))
        if selected_instances and name not in selected_instances:
            continue
        seen_instances.add(name)
        states.append(OK)
    for peer in peers:
        name = str(value_at(peer, "name", "peer", "description", "public-key", "public_key", default="unknown"))
        interface = str(value_at(peer, "interface", default=""))
        if selected_instances and interface not in selected_instances:
            continue
        if selected_peers and name not in selected_peers:
            continue
        seen_peers.add(name)
        age = handshake_age(peer)
        if age is None:
            details.append(f"{name}: no handshake")
            perf.append(
                f"{perf_label('wg_' + name + '_handshake_age')}=0s;;;0;"
            )
        else:
            details.append(f"{name}: {human_duration(age)}")
            perf.append(
                f"{perf_label('wg_' + name + '_handshake_age')}={int(age)}s;;;0;"
            )
    missing_instances = sorted(selected_instances - seen_instances)
    missing_peers = sorted(selected_peers - seen_peers)
    if missing_instances:
        states.append(CRITICAL)
        details.append("instances not found: " + ", ".join(missing_instances))
    if missing_peers:
        details.append("peers not found: " + ", ".join(missing_peers))
    if not states:
        states.append(OK)
    return Result(worst(states), f"WireGuard running; {len(seen_instances) or len(interfaces)} instance(s), "
                  f"{len(seen_peers) or len(peers)} peer(s)" + (f"; {', '.join(details)}" if details else ""), [], perf)


def check_firewall(api: OPNsenseAPI, args: argparse.Namespace) -> Result:
    stats = api.first([
        ("diagnostics/firewall/pf_states", "GET", None),
        ("diagnostics/firewall/pf_statistics", "GET", None),
        ("diagnostics/firewall/pfStatistics", "GET", None),
        ("diagnostics/firewall/stats", "GET", None),
    ])
    running_values = []
    if isinstance(stats, dict):
        for key in ("running", "enabled", "status"):
            value = value_at(stats, key)
            if value is not None:
                running_values.append(value)
    if running_values and not any(is_true(value) for value in running_values):
        return Result(CRITICAL, "PF firewall is not running", [], [])
    states = max(
        find_numbers(
            stats,
            {"states", "current", "currentstates", "stateentries", "entries"},
        ),
        default=0,
    )
    state_limit = max(
        find_numbers(
            stats,
            {"limit", "statelimit", "maxstates", "stateslimit", "limitstates"},
        ),
        default=0,
    )
    usage = percent(states, state_limit)
    drops = sum(find_numbers(stats, {
        "dropped", "drops", "baddrops", "memorydrops", "congestiondrops", "short"
    }))
    state = threshold_state(usage, args.warning, args.critical) if state_limit else OK
    if args.critical_drops >= 0 and drops >= args.critical_drops:
        state = CRITICAL
    elif args.warning_drops >= 0 and drops >= args.warning_drops:
        state = worst([state, WARNING])
    summary = f"PF running, states {int(states)}"
    if state_limit:
        summary += f"/{int(state_limit)} ({usage:.1f}%)"
    summary += f", drops {int(drops)}"
    return Result(state, summary, [], [
        f"'pf_states'={int(states)};;;0;{int(state_limit) if state_limit else ''}",
        f"'pf_state_usage'={usage:.1f}%;{args.warning};{args.critical};0;100",
        f"'pf_drops'={int(drops)};{args.warning_drops if args.warning_drops >= 0 else ''};"
        f"{args.critical_drops if args.critical_drops >= 0 else ''};0;",
    ])


CHECKS = {
    "cpu": check_cpu,
    "memory": check_memory,
    "disk": check_disk,
    "services": check_services,
    "updates": check_updates,
    "certificates": check_certificates,
    "interfaces": check_interfaces,
    "wireguard": check_wireguard,
    "firewall": check_firewall,
}


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    result.add_argument("-H", "--host", required=True)
    result.add_argument("-p", "--port", type=int, default=443)
    result.add_argument("-k", "--api-key", required=True)
    result.add_argument("-s", "--api-secret", required=True)
    result.add_argument("-m", "--mode", required=True, choices=sorted(CHECKS))
    result.add_argument("-w", "--warning", type=float, default=80)
    result.add_argument("-c", "--critical", type=float, default=90)
    result.add_argument("--timeout", type=int, default=15)
    result.add_argument("--insecure", action="store_true")
    result.add_argument("--ca-file")
    result.add_argument("--service", action="append", default=[])
    result.add_argument("--interface", action="append", default=[])
    result.add_argument("--filesystem", action="append", default=[])
    result.add_argument("--certificate", action="append", default=[])
    result.add_argument("--wireguard-instance", action="append", default=[])
    result.add_argument("--wireguard-peer", action="append", default=[])
    result.add_argument("--warning-age", type=int, default=600)
    result.add_argument("--critical-age", type=int, default=1800)
    result.add_argument("--warning-days", type=int, default=30)
    result.add_argument("--critical-days", type=int, default=14)
    result.add_argument("--warning-errors", type=int, default=1)
    result.add_argument("--critical-errors", type=int, default=10)
    result.add_argument("--warning-updates", type=int, default=1)
    result.add_argument("--critical-updates", type=int, default=20)
    result.add_argument("--security-critical", action="store_true")
    result.add_argument("--warning-drops", type=int, default=-1)
    result.add_argument("--critical-drops", type=int, default=-1)
    result.add_argument("--tls-certificate-only", action="store_true")
    return result


def validate(args: argparse.Namespace) -> None:
    pairs = [
        ("warning", args.warning, "critical", args.critical, False),
        ("warning-age", args.warning_age, "critical-age", args.critical_age, False),
        ("warning-errors", args.warning_errors, "critical-errors", args.critical_errors, False),
        ("warning-updates", args.warning_updates, "critical-updates", args.critical_updates, False),
        ("critical-days", args.critical_days, "warning-days", args.warning_days, False),
    ]
    for lower_name, lower, upper_name, upper, _ in pairs:
        if lower > upper:
            raise CheckError(f"--{lower_name} must not exceed --{upper_name}")
    if args.timeout <= 0:
        raise CheckError("--timeout must be greater than zero")


def emit(result: Result) -> int:
    first = f"{STATE_NAMES[result.state]} - {result.summary}"
    if result.perfdata:
        first += " | " + " ".join(result.perfdata)
    print(first)
    for detail in result.details:
        print(detail)
    return result.state


def main(argv: list[str] | None = None) -> int:
    try:
        args = parser().parse_args(argv)
        validate(args)
        api = OPNsenseAPI(args)
        return emit(CHECKS[args.mode](api, args))
    except CheckError as exc:
        print(f"UNKNOWN - {exc}")
        return UNKNOWN
    except KeyboardInterrupt:
        print("UNKNOWN - interrupted")
        return UNKNOWN


if __name__ == "__main__":
    sys.exit(main())
