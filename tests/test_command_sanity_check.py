"""Tests for fail-closed command_sanity_check behavior."""

import json
import unittest
from unittest.mock import MagicMock

from pentest_assistant.ai import CommandSanityChecker
from pentest_assistant.models import Service


def _service(name: str = "http", port: int = 80) -> Service:
    return Service(port=port, protocol="tcp", name=name, product="", version="")


def _provider(response: str) -> MagicMock:
    provider = MagicMock()
    provider.generate.return_value = response
    return provider


def _json_result(**kwargs) -> dict:
    payload = {
        "approved": True,
        "risk": "low",
        "issues": [],
        "corrected_command": "",
        "safer_alternative": "",
        "manual_only": False,
        "reason": "",
        "confidence": 0.9,
    }
    payload.update(kwargs)
    return payload


class TestCommandSanityCheckerFailClosed(unittest.TestCase):
    def test_empty_command_list_returns_empty(self) -> None:
        checker = CommandSanityChecker(_provider("[]"))
        self.assertEqual(checker.check([], _service()), [])

    def test_malformed_json_blocks_command(self) -> None:
        checker = CommandSanityChecker(_provider("not json"))
        results = checker.check(["nmap -sV TARGET"], _service())
        self.assertEqual(len(results), 1)
        self.assertFalse(results[0].approved)
        self.assertEqual(results[0].risk, "blocked")
        self.assertTrue(results[0].manual_only)
        self.assertFalse(results[0].auto_execute)
        self.assertIn("sanity_check_failed", [issue["message"] for issue in results[0].issues])

    def test_provider_failure_blocks_command(self) -> None:
        provider = MagicMock()
        provider.generate.side_effect = RuntimeError("Ollama unavailable")
        checker = CommandSanityChecker(provider)
        results = checker.check(["curl -I http://TARGET"], _service())
        self.assertEqual(results[0].risk, "blocked")
        self.assertFalse(results[0].approved)

    def test_timeout_blocks_command(self) -> None:
        provider = MagicMock()
        provider.generate.side_effect = TimeoutError("timed out")
        checker = CommandSanityChecker(provider)
        results = checker.check(["curl -I http://TARGET"], _service())
        self.assertEqual(results[0].risk, "blocked")
        self.assertFalse(results[0].auto_execute)

    def test_empty_response_blocks_command(self) -> None:
        checker = CommandSanityChecker(_provider(""))
        results = checker.check(["curl -I http://TARGET"], _service())
        self.assertEqual(results[0].risk, "blocked")
        self.assertTrue(results[0].manual_only)

    def test_short_response_pads_missing_entries_with_blocked(self) -> None:
        checker = CommandSanityChecker(_provider(json.dumps([_json_result()])))
        results = checker.check(
            ["curl -I http://TARGET", "nmap -sV TARGET"],
            _service(),
        )
        self.assertTrue(results[0].approved)
        self.assertEqual(results[1].risk, "blocked")


class TestCommandSanityCheckerPolicyEnforcement(unittest.TestCase):
    def test_high_risk_output_becomes_manual_only(self) -> None:
        checker = CommandSanityChecker(
            _provider(
                json.dumps(
                    [
                        _json_result(
                            approved=False,
                            risk="high",
                            manual_only=True,
                            issues=[{"type": "bruteforce", "message": "password spraying"}],
                            reason="manual only",
                        )
                    ]
                )
            )
        )
        results = checker.check(["hydra -L users.txt -P rockyou.txt ssh://TARGET"], _service("ssh", 22))
        self.assertEqual(results[0].risk, "manual_only")
        self.assertTrue(results[0].manual_only)
        self.assertFalse(results[0].auto_execute)

    def test_safe_command_can_remain_low_risk(self) -> None:
        checker = CommandSanityChecker(_provider(json.dumps([_json_result()])))
        results = checker.check(["curl -I http://TARGET"], _service())
        self.assertTrue(results[0].approved)
        self.assertEqual(results[0].risk, "low")
        self.assertTrue(results[0].auto_execute)


if __name__ == "__main__":
    unittest.main()
