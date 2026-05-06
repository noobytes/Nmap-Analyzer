import unittest

from pentest_assistant.core.command_policy import classify_command
from pentest_assistant.core.scope_guard import evaluate_scope
from pentest_assistant.core.web_discovery_policy import (
    build_safe_ffuf_command,
    select_web_fuzzer,
    should_skip_web_fuzzing,
    record_web_fuzzing,
)
from pentest_assistant.state import ServiceState


class TestWebDiscoveryPolicy(unittest.TestCase):
    def test_ffuf_is_preferred_if_available(self) -> None:
        self.assertEqual(select_web_fuzzer({"ffuf", "feroxbuster"}), "ffuf")

    def test_feroxbuster_is_fallback_when_ffuf_unavailable(self) -> None:
        self.assertEqual(select_web_fuzzer({"feroxbuster"}), "feroxbuster")

    def test_gobuster_and_dirsearch_are_not_auto_selected(self) -> None:
        self.assertEqual(select_web_fuzzer({"gobuster", "dirsearch"}), "no_available_tool")

    def test_ffuf_simple_command_is_not_blocked(self) -> None:
        decision = classify_command("ffuf -u http://TARGET/FUZZ -w list.txt")
        self.assertEqual(decision["risk"], "medium")
        self.assertNotEqual(decision["risk"], "blocked")

    def test_ffuf_without_limits_is_rewritten(self) -> None:
        decision = classify_command("ffuf -u http://TARGET/FUZZ -w list.txt")
        self.assertEqual(decision["risk"], "medium")
        self.assertFalse(decision["safe_for_auto_execute"])
        self.assertIn("-t 10", decision["corrected_command"])
        self.assertIn("-rate 50", decision["corrected_command"])
        self.assertIn("-timeout 10", decision["corrected_command"])

    def test_ffuf_with_safe_limits_is_allowed_as_medium(self) -> None:
        decision = classify_command("ffuf -u http://TARGET/FUZZ -w list.txt -t 10 -rate 50 -timeout 10")
        self.assertEqual(decision["risk"], "medium")
        self.assertTrue(decision["safe_for_auto_execute"])
        self.assertFalse(decision["manual_only"])

    def test_ffuf_with_recursion_is_manual_only(self) -> None:
        decision = classify_command("ffuf -u http://TARGET/FUZZ -w list.txt -recursion -t 10 -rate 50 -timeout 10")
        self.assertEqual(decision["risk"], "manual_only")
        self.assertTrue(decision["manual_only"])

    def test_ffuf_with_huge_wordlist_is_manual_only(self) -> None:
        decision = classify_command(
            "ffuf -u http://TARGET/FUZZ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 10 -rate 50 -timeout 10"
        )
        self.assertEqual(decision["risk"], "manual_only")

    def test_ffuf_with_andand_is_blocked(self) -> None:
        decision = classify_command("ffuf -u http://TARGET/FUZZ -w list.txt && whoami")
        self.assertEqual(decision["risk"], "blocked")

    def test_ffuf_against_out_of_scope_host_is_blocked_by_scope_guard(self) -> None:
        allowed = evaluate_scope(
            "ffuf -u http://10.0.0.99/FUZZ -w list.txt -t 10 -rate 50 -timeout 10",
            scope_hosts=["10.0.0.10"],
            expected_target="10.0.0.10",
        )
        self.assertFalse(allowed["allowed"])

    def test_feroxbuster_safe_command_is_allowed_as_fallback_medium(self) -> None:
        decision = classify_command(
            "feroxbuster -u http://TARGET -w list.txt -t 10 -r --depth 1 --rate-limit 50",
            context={"available_tools": {"feroxbuster"}},
        )
        self.assertEqual(decision["risk"], "medium")
        self.assertTrue(decision["safe_for_auto_execute"])

    def test_feroxbuster_not_used_when_ffuf_available(self) -> None:
        decision = classify_command(
            "feroxbuster -u http://TARGET -w list.txt -t 10 -r --depth 1 --rate-limit 50",
            context={"available_tools": {"ffuf", "feroxbuster"}},
        )
        self.assertEqual(decision["risk"], "manual_only")

    def test_gobuster_and_dirsearch_are_manual_only_and_normalized(self) -> None:
        gobuster = classify_command("gobuster dir -u http://TARGET -w list.txt")
        dirsearch = classify_command("dirsearch -u http://TARGET -w list.txt")
        self.assertEqual(gobuster["risk"], "manual_only")
        self.assertEqual(dirsearch["risk"], "manual_only")
        self.assertTrue(gobuster["corrected_command"].startswith("ffuf -u http://TARGET/FUZZ"))
        self.assertTrue(dirsearch["corrected_command"].startswith("ffuf -u http://TARGET/FUZZ"))

    def test_duplicate_web_fuzzing_is_prevented(self) -> None:
        service_state = ServiceState(service_id="svc", service_label="80/tcp http")
        command = build_safe_ffuf_command("http://10.0.0.10")
        self.assertFalse(should_skip_web_fuzzing(service_state, command, "10.0.0.10"))
        record_web_fuzzing(service_state, command, "10.0.0.10", "found /admin")
        self.assertTrue(should_skip_web_fuzzing(service_state, command, "10.0.0.10"))


if __name__ == "__main__":
    unittest.main()
