import unittest

from pentest_assistant.rag.command_classifier import classify_command


class TestCommandClassifier(unittest.TestCase):
    def test_low_risk_banner_check(self) -> None:
        result = classify_command("curl -I http://TARGET")
        self.assertEqual(result["risk"], "low")
        self.assertTrue(result["safe_for_auto_execute"])

    def test_manual_only_bruteforce(self) -> None:
        result = classify_command("hydra -L users.txt -P rockyou.txt ssh://TARGET")
        self.assertEqual(result["risk"], "manual_only")
        self.assertFalse(result["safe_for_auto_execute"])

    def test_blocked_dos(self) -> None:
        result = classify_command("hping3 --flood TARGET")
        self.assertEqual(result["risk"], "blocked")


if __name__ == "__main__":
    unittest.main()
