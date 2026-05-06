import unittest
from unittest.mock import MagicMock

from pentest_assistant.ai import CommandSanityChecker
from pentest_assistant.models import Service
from pentest_assistant.pipeline import _extract_safe_commands_from_knowledge


class TestRagSafety(unittest.TestCase):
    def test_knowledge_commands_still_go_through_sanity_check(self) -> None:
        provider = MagicMock()
        provider.generate.return_value = '[{"approved": true, "risk": "low", "issues": [], "corrected_command": "", "safer_alternative": "", "manual_only": false, "reason": "", "confidence": 0.9}]'
        checker = CommandSanityChecker(provider)
        commands = [item["command"] for item in _extract_safe_commands_from_knowledge("```bash\nsmbclient -L //<target>/ -N\n```")]
        results = checker.check(
            commands,
            Service(port=445, protocol="tcp", name="microsoft-ds"),
            knowledge_context="knowledge_context:\nSMB notes",
        )
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0].approved)
        self.assertTrue(results[0].auto_execute)

    def test_high_risk_commands_are_not_auto_executed(self) -> None:
        provider = MagicMock()
        provider.generate.return_value = '[{"approved": false, "risk": "high", "issues": [{"type": "bruteforce", "message": "no brute force"}], "corrected_command": "", "safer_alternative": "", "manual_only": true, "reason": "manual only", "confidence": 0.9}]'
        checker = CommandSanityChecker(provider)
        results = checker.check(
            ["hydra -L users.txt -P rockyou.txt ssh://TARGET"],
            Service(port=22, protocol="tcp", name="ssh"),
            knowledge_context="knowledge_context:\nUnsafe example",
        )
        self.assertFalse(results[0].auto_execute)
        self.assertTrue(results[0].manual_only)


if __name__ == "__main__":
    unittest.main()
