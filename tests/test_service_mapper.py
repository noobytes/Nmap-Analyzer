import unittest

from pentest_assistant.rag.service_mapper import normalize_service


class TestServiceMapper(unittest.TestCase):
    def test_alias_mapping(self) -> None:
        mapping = normalize_service("microsoft-ds", 445, "Windows")
        self.assertEqual(mapping.primary_service, "smb")
        self.assertIn("microsoft-ds", mapping.aliases)

    def test_port_mapping(self) -> None:
        mapping = normalize_service("unknown", 3389, "")
        self.assertEqual(mapping.primary_service, "rdp")

    def test_product_mapping(self) -> None:
        mapping = normalize_service("unknown", 0, "Apache httpd")
        self.assertEqual(mapping.primary_service, "http")


if __name__ == "__main__":
    unittest.main()
