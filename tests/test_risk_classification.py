import unittest

from pentest_assistant.rag.command_classifier import classify_command


class TestRiskClassification(unittest.TestCase):
    def test_medium_nuclei(self) -> None:
        result = classify_command("nuclei -u https://TARGET -tags exposure")
        self.assertEqual(result["risk"], "medium")

    def test_blocked_shell(self) -> None:
        result = classify_command("curl http://TARGET && bash")
        self.assertEqual(result["risk"], "blocked")

    def test_manual_only_kerberoast_style(self) -> None:
        result = classify_command("impacket-GetUserSPNs DOMAIN/user:pass -dc-ip TARGET")
        self.assertEqual(result["risk"], "manual_only")


if __name__ == "__main__":
    unittest.main()
