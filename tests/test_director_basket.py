import json
import pathlib
import unittest


ROOT = pathlib.Path(__file__).parents[1]
BASKET = ROOT / "director" / "check_opnsense-basket.json"


class DirectorBasketTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.basket = json.loads(BASKET.read_text(encoding="utf-8"))

    def test_master_and_derived_templates(self):
        templates = self.basket["ServiceTemplate"]
        self.assertEqual(len(templates), 10)
        self.assertIn("OPNsense Service Master", templates)
        self.assertEqual(templates["OPNsense Service Master"]["imports"], [])

        expected_modes = {
            "OPNsense CPU Template": "cpu",
            "OPNsense Memory Template": "memory",
            "OPNsense Disk Template": "disk",
            "OPNsense Services Template": "services",
            "OPNsense Updates Template": "updates",
            "OPNsense Certificates Template": "certificates",
            "OPNsense Interfaces Template": "interfaces",
            "OPNsense WireGuard Template": "wireguard",
            "OPNsense Firewall Template": "firewall",
        }
        for name, mode in expected_modes.items():
            self.assertEqual(templates[name]["imports"], ["OPNsense Service Master"])
            self.assertEqual(templates[name]["vars"]["opnsense_mode"], mode)

    def test_service_set_uses_derived_templates(self):
        service_set = self.basket["ServiceSet"]["OPNsense Monitoring"]
        services = service_set["services"]
        self.assertEqual(len(services), 9)
        for service in services:
            self.assertEqual(len(service["imports"]), 1)
            self.assertTrue(service["imports"][0].endswith(" Template"))
            self.assertEqual(service["vars"], {})


if __name__ == "__main__":
    unittest.main()
