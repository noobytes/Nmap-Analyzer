"""Tests for the command_sanity_check pipeline stage (CommandSanityChecker)."""
import json
import unittest
from unittest.mock import MagicMock

from pentest_assistant.ai import CommandSanityChecker
from pentest_assistant.models import SanityCheckResult, Service


def _make_service(name="http", port=80, protocol="tcp", product="", version="") -> Service:
    return Service(port=port, protocol=protocol, name=name, product=product, version=version)


def _make_provider(response: str):
    provider = MagicMock()
    provider.generate.return_value = response
    return provider


def _checker(response: str) -> CommandSanityChecker:
    return CommandSanityChecker(_make_provider(response))


def _json_result(**kwargs) -> dict:
    defaults = {
        "approved": True,
        "risk_level": "low",
        "issues": [],
        "corrected_command": "",
        "safer_alternative": "",
        "operator_warning": "",
        "confidence": 0.9,
    }
    defaults.update(kwargs)
    return defaults


class TestCommandSanityCheckerPassthrough(unittest.TestCase):
    """Checker must never break the pipeline on bad model output."""

    def test_empty_command_list_returns_empty(self):
        checker = _checker("[]")
        results = checker.check([], _make_service())
        self.assertEqual(results, [])

    def test_malformed_json_returns_passthrough(self):
        checker = _checker("not json at all")
        cmds = ["nmap -sV TARGET", "curl -I http://TARGET"]
        results = checker.check(cmds, _make_service())
        self.assertEqual(len(results), 2)
        for r in results:
            self.assertTrue(r.approved)
            self.assertEqual(r.risk_level, "low")
            self.assertEqual(r.issues, [])
            self.assertEqual(r.corrected_command, "")

    def test_provider_exception_returns_passthrough(self):
        provider = MagicMock()
        provider.generate.side_effect = RuntimeError("Ollama connection refused")
        checker = CommandSanityChecker(provider)
        cmds = ["nmap -sV TARGET"]
        results = checker.check(cmds, _make_service())
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0].approved)
        self.assertEqual(results[0].command, "nmap -sV TARGET")

    def test_short_response_pads_missing_entries(self):
        # Model returns only 1 result for 3 commands → remaining 2 get pass-through
        response = json.dumps([_json_result()])
        checker = _checker(response)
        cmds = ["nmap -sV TARGET", "curl TARGET", "ffuf -u http://TARGET/FUZZ -w list.txt"]
        results = checker.check(cmds, _make_service())
        self.assertEqual(len(results), 3)
        # First result uses model output
        self.assertTrue(results[0].approved)
        # Padded entries default to approved
        self.assertTrue(results[1].approved)
        self.assertTrue(results[2].approved)


class TestCommandSanityCheckerResultMapping(unittest.TestCase):
    """Results map back to the correct command in the same order."""

    def test_results_preserve_command_order(self):
        cmds = ["nmap -T5 -p- TARGET", "hydra -L users.txt -P rockyou.txt smb://TARGET"]
        response = json.dumps([
            _json_result(
                approved=False,
                risk_level="medium",
                issues=[{"type": "noise", "message": "-T5 is too aggressive"}],
                safer_alternative="nmap -T3 -Pn -sV --top-ports 1000 TARGET",
                operator_warning="Use -T3 instead",
            ),
            _json_result(
                approved=False,
                risk_level="high",
                issues=[{"type": "bruteforce", "message": "brute-force before enumeration"}],
                safer_alternative="netexec smb TARGET --shares",
                operator_warning="Enumerate shares first",
            ),
        ])
        checker = _checker(response)
        results = checker.check(cmds, _make_service(name="smb", port=445))

        self.assertEqual(len(results), 2)
        self.assertEqual(results[0].command, cmds[0])
        self.assertFalse(results[0].approved)
        self.assertEqual(results[0].risk_level, "medium")
        self.assertEqual(results[0].issues[0]["type"], "noise")
        self.assertEqual(results[0].safer_alternative, "nmap -T3 -Pn -sV --top-ports 1000 TARGET")

        self.assertEqual(results[1].command, cmds[1])
        self.assertFalse(results[1].approved)
        self.assertEqual(results[1].risk_level, "high")
        self.assertEqual(results[1].issues[0]["type"], "bruteforce")
        self.assertEqual(results[1].safer_alternative, "netexec smb TARGET --shares")

    def test_approved_clean_command(self):
        cmds = ["smbclient -L //TARGET -N"]
        response = json.dumps([_json_result(approved=True, risk_level="low", confidence=0.95)])
        checker = _checker(response)
        results = checker.check(cmds, _make_service(name="smb", port=445))
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0].approved)
        self.assertEqual(results[0].risk_level, "low")
        self.assertEqual(results[0].issues, [])
        self.assertEqual(results[0].operator_warning, "")


class TestCommandSanityCheckerIssueTypes(unittest.TestCase):
    """Unknown issue types are coerced to 'syntax'."""

    def test_unknown_issue_type_coerced_to_syntax(self):
        cmds = ["nmap TARGET"]
        response = json.dumps([
            _json_result(
                approved=False,
                issues=[{"type": "totally_unknown_type", "message": "something"}],
            )
        ])
        checker = _checker(response)
        results = checker.check(cmds, _make_service())
        self.assertEqual(results[0].issues[0]["type"], "syntax")

    def test_unknown_risk_level_coerced_to_low(self):
        cmds = ["nmap TARGET"]
        response = json.dumps([_json_result(risk_level="super_critical")])
        checker = _checker(response)
        results = checker.check(cmds, _make_service())
        self.assertEqual(results[0].risk_level, "low")


class TestCommandSanityCheckerToolExamples(unittest.TestCase):
    """Spec examples: nmap -T5 and hydra premature brute force."""

    def test_nmap_t5_flagged_as_noise(self):
        """nmap -T5 -p- should be rejected and a quieter alternative suggested."""
        cmds = ["nmap -T5 -p- 10.10.10.5"]
        response = json.dumps([
            _json_result(
                approved=False,
                risk_level="medium",
                issues=[{"type": "noise", "message": "-T5 is too aggressive for most engagements"}],
                safer_alternative="nmap -T3 -Pn -sV --top-ports 1000 10.10.10.5",
            )
        ])
        checker = _checker(response)
        results = checker.check(cmds, _make_service())
        self.assertFalse(results[0].approved)
        self.assertIn("noise", [i["type"] for i in results[0].issues])
        self.assertIn("nmap -T3", results[0].safer_alternative)

    def test_hydra_before_enum_flagged_as_bruteforce(self):
        """hydra with rockyou against SMB before enumeration should be rejected."""
        cmds = ["hydra -L users.txt -P rockyou.txt smb://10.10.10.8"]
        response = json.dumps([
            _json_result(
                approved=False,
                risk_level="high",
                issues=[{"type": "bruteforce", "message": "password spraying before share enumeration"}],
                safer_alternative="netexec smb 10.10.10.8 --shares",
                operator_warning="Enumerate shares and users before launching brute force",
            )
        ])
        checker = _checker(response)
        results = checker.check(cmds, _make_service(name="smb", port=445))
        self.assertFalse(results[0].approved)
        self.assertIn("bruteforce", [i["type"] for i in results[0].issues])
        self.assertIn("netexec", results[0].safer_alternative)

    def test_nmap_script_smb_enum_approved_on_smb_service(self):
        """nmap smb-enum scripts against SMB port should pass."""
        cmds = ["nmap --script smb-enum-shares,smb-enum-users -p 445 TARGET"]
        response = json.dumps([_json_result(approved=True, risk_level="low", confidence=0.95)])
        checker = _checker(response)
        results = checker.check(cmds, _make_service(name="smb", port=445))
        self.assertTrue(results[0].approved)

    def test_ldapsearch_on_ldap_service_approved(self):
        """ldapsearch against port 389 should pass cleanly."""
        cmds = ["ldapsearch -x -H ldap://TARGET -b '' -s base namingContexts"]
        response = json.dumps([_json_result(approved=True, risk_level="low")])
        checker = _checker(response)
        results = checker.check(cmds, _make_service(name="ldap", port=389))
        self.assertTrue(results[0].approved)

    def test_ffuf_against_web_service_approved(self):
        """ffuf content discovery against HTTP port should be approved."""
        cmds = ["ffuf -u http://TARGET/FUZZ -w /usr/share/wordlists/dirb/common.txt"]
        response = json.dumps([_json_result(approved=True, risk_level="low")])
        checker = _checker(response)
        results = checker.check(cmds, _make_service(name="http", port=80))
        self.assertTrue(results[0].approved)

    def test_syntax_correction_applied(self):
        """A command with broken syntax should have corrected_command set."""
        cmds = ["nmap --script smb-vuln TARGET -pTARGET"]   # malformed -p
        response = json.dumps([
            _json_result(
                approved=False,
                risk_level="low",
                issues=[{"type": "syntax", "message": "malformed -p argument"}],
                corrected_command="nmap --script smb-vuln -p 445 TARGET",
            )
        ])
        checker = _checker(response)
        results = checker.check(cmds, _make_service(name="smb", port=445))
        self.assertFalse(results[0].approved)
        self.assertEqual(results[0].corrected_command, "nmap --script smb-vuln -p 445 TARGET")


class TestSanityCheckResultDataclass(unittest.TestCase):
    """SanityCheckResult dataclass is importable and behaves as expected."""

    def test_instantiation(self):
        result = SanityCheckResult(
            command="nmap -sV TARGET",
            approved=True,
            risk_level="low",
            issues=[],
            corrected_command="",
            safer_alternative="",
            operator_warning="",
            confidence=0.95,
        )
        self.assertTrue(result.approved)
        self.assertEqual(result.risk_level, "low")
        self.assertEqual(result.confidence, 0.95)


if __name__ == "__main__":
    unittest.main()
