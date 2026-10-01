import importlib.util
import pathlib
import sys
import unittest
from types import SimpleNamespace


MODULE_PATH = pathlib.Path(__file__).parents[1] / "check_opnsense.py"
SPEC = importlib.util.spec_from_file_location("check_opnsense", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class HelpersTest(unittest.TestCase):
    def test_parse_size(self):
        self.assertEqual(MODULE.parse_size("1G"), 1024**3)
        self.assertEqual(MODULE.parse_size("512 MiB"), 512 * 1024**2)

    def test_percent(self):
        self.assertAlmostEqual(MODULE.percent(25, 100), 25.0)
        self.assertEqual(MODULE.percent(1, 0), 0.0)

    def test_threshold_state(self):
        self.assertEqual(MODULE.threshold_state(91, 80, 90), MODULE.CRITICAL)
        self.assertEqual(MODULE.threshold_state(85, 80, 90), MODULE.WARNING)
        self.assertEqual(MODULE.threshold_state(10, 80, 90), MODULE.OK)

    def test_flat_rows(self):
        payload = {"total": 1, "rows": [{"name": "unbound", "running": 1}]}
        self.assertEqual(MODULE.rows(payload)[0]["name"], "unbound")

    def test_interface_normalization(self):
        payload = {
            "interfaces": {
                "wan": {"name": "igc0", "status": "up", "inbytes": 10},
                "lan": {"name": "igc1", "status": "down", "inbytes": 20},
            }
        }
        result = MODULE.interface_rows(payload)
        self.assertEqual(result[0]["logical_name"], "wan")
        self.assertEqual(result[1]["logical_name"], "lan")

    def test_duration(self):
        self.assertEqual(MODULE.human_duration(65), "1m 5s")
        self.assertEqual(MODULE.human_duration(3661), "1h 1m")


class FakeAPI:
    def __init__(self, payload):
        self.payload = payload

    def first(self, _candidates):
        return self.payload

    def stream_sample(self, _endpoint):
        return self.payload


class SequenceAPI:
    def __init__(self, *payloads):
        self.payloads = iter(payloads)

    def first(self, _candidates):
        return next(self.payloads)


class RecordingAPI(SequenceAPI):
    def __init__(self, *payloads):
        super().__init__(*payloads)
        self.calls = []

    def first(self, candidates):
        self.calls.append(candidates)
        return super().first(candidates)


class CheckTest(unittest.TestCase):
    def test_cpu_percentage(self):
        args = SimpleNamespace(warning=80, critical=90)
        payload = {"total": 100, "user": 30.0, "sys": 12.5, "idle": 57.5}
        result = MODULE.check_cpu(FakeAPI(payload), args)
        self.assertEqual(result.state, MODULE.OK)
        self.assertIn("42.5%", result.summary)

    def test_cpu_total_is_not_usage(self):
        args = SimpleNamespace(warning=80, critical=90)
        payload = {
            "user": 3.0,
            "nice": 0.0,
            "system": 2.0,
            "interrupt": 1.0,
            "idle": 94.0,
            "total": 100.0,
        }
        result = MODULE.check_cpu(FakeAPI(payload), args)
        self.assertEqual(result.state, MODULE.OK)
        self.assertIn("6.0%", result.summary)

    def test_cpu_can_sum_components_without_idle(self):
        args = SimpleNamespace(warning=80, critical=90)
        payload = {"user": 7.0, "nice": 1.0, "sys": 4.0, "intr": 0.5, "total": 100.0}
        result = MODULE.check_cpu(FakeAPI(payload), args)
        self.assertEqual(result.state, MODULE.OK)
        self.assertIn("12.5%", result.summary)

    def test_cpu_rejects_memory_total(self):
        args = SimpleNamespace(warning=80, critical=90)
        payload = {"total": 4254560256, "used": 1500000000}
        with self.assertRaises(MODULE.CheckError):
            MODULE.check_cpu(FakeAPI(payload), args)

    def test_services(self):
        args = SimpleNamespace(service=["unbound"])
        payload = {"rows": [{"name": "unbound", "running": 1}]}
        self.assertEqual(MODULE.check_services(FakeAPI(payload), args).state, MODULE.OK)

    def test_wireguard_interfaces_override_false_service_status(self):
        args = SimpleNamespace(
            wireguard_instance=[],
            wireguard_peer=[],
            warning_age=300,
            critical_age=900,
        )
        api = SequenceAPI(
            {"status": "stopped"},
            {"interfaces": {"wg0": {"name": "wg0", "peers": []}}},
        )
        result = MODULE.check_wireguard(api, args)
        self.assertEqual(result.state, MODULE.OK)
        self.assertIn("WireGuard running", result.summary)

    def test_wireguard_stopped_without_interfaces(self):
        args = SimpleNamespace(
            wireguard_instance=[],
            wireguard_peer=[],
            warning_age=300,
            critical_age=900,
        )
        api = SequenceAPI({"status": "stopped"}, {"interfaces": {}})
        result = MODULE.check_wireguard(api, args)
        self.assertEqual(result.state, MODULE.CRITICAL)

    def test_wireguard_offline_peers_are_informational(self):
        args = SimpleNamespace(
            wireguard_instance=[],
            wireguard_peer=[],
            warning_age=300,
            critical_age=900,
        )
        api = SequenceAPI(
            {"status": "running"},
            {
                "interfaces": {
                    "wg0": {
                        "name": "wg0",
                        "peers": {
                            "road-warrior": {
                                "latest_handshake": 0,
                            }
                        },
                    }
                }
            },
        )
        result = MODULE.check_wireguard(api, args)
        self.assertEqual(result.state, MODULE.OK)
        self.assertIn("road-warrior: no handshake", result.summary)

    def test_disk_critical(self):
        args = SimpleNamespace(filesystem=[], warning=80, critical=90)
        payload = {"rows": [{"mountpoint": "/", "size": "100G", "used": "95G"}]}
        api = RecordingAPI(payload)
        self.assertEqual(MODULE.check_disk(api, args).state, MODULE.CRITICAL)
        self.assertEqual(
            api.calls[0][0][0], "diagnostics/system/system_disk"
        )

    def test_memory_uses_system_resources(self):
        args = SimpleNamespace(warning=80, critical=90)
        api = RecordingAPI(
            {"total": 4 * 1024**3, "used": 2 * 1024**3},
            {"total": 1024**3, "used": 0},
        )
        result = MODULE.check_memory(api, args)
        self.assertEqual(result.state, MODULE.OK)
        self.assertEqual(
            api.calls[0][0][0], "diagnostics/system/system_resources"
        )

    def test_interfaces_down(self):
        args = SimpleNamespace(interface=["wan"], warning_errors=1, critical_errors=10)
        payload = {"interfaces": {"wan": {"name": "igc0", "status": "down"}}}
        api = RecordingAPI(payload)
        self.assertEqual(MODULE.check_interfaces(api, args).state, MODULE.CRITICAL)
        self.assertEqual(api.calls[0][0][0], "interfaces/overview/export")

    def test_firewall_state_usage(self):
        args = SimpleNamespace(
            warning=80, critical=90, warning_drops=-1, critical_drops=-1
        )
        payload = {"running": True, "current": 950, "limit": 1000}
        api = RecordingAPI(payload)
        self.assertEqual(MODULE.check_firewall(api, args).state, MODULE.CRITICAL)
        self.assertEqual(
            api.calls[0][0][0], "diagnostics/firewall/pf_states"
        )


if __name__ == "__main__":
    unittest.main()
