import tempfile
import unittest
from pathlib import Path

from pentest_assistant.analysis_loop import build_initial_case_state, generate_candidate_actions
from pentest_assistant.executor import EXECUTE_TOOLS
from pentest_assistant.models import AnalysisResult, CommandSuggestion, Host, SanityCheckResult, Service, ServiceFinding


class TestIterativeWorkflowDryRun(unittest.TestCase):
    def test_dry_run_prepares_safe_and_manual_buckets_without_execution(self) -> None:
        service = Service(port=80, protocol="tcp", name="http", product="Apache", version="2.4.58")
        finding = ServiceFinding(
            service=service,
            ips=["10.0.0.10"],
            cves=[],
            playbook_commands=["curl -I http://TARGET"],
            ai_commands=["hydra -L users.txt -P rockyou.txt http://TARGET"],
            playbook_confidence=0.8,
            ai_confidence=0.4,
            command_suggestions=[
                CommandSuggestion(command="curl -I http://TARGET", source="playbook", confidence=0.8, auto_execute=True, risk="low"),
                CommandSuggestion(command="hydra -L users.txt -P rockyou.txt http://TARGET", source="ai", confidence=0.4, manual_only=True, risk="blocked"),
            ],
            risk_score=5.0,
            sanity_check_results=[
                SanityCheckResult(
                    command="curl -I http://TARGET",
                    approved=True,
                    risk="low",
                    issues=[],
                    corrected_command="",
                    safer_alternative="",
                    manual_only=False,
                    reason="safe",
                    auto_execute=True,
                    confidence=0.9,
                ),
                SanityCheckResult(
                    command="hydra -L users.txt -P rockyou.txt http://TARGET",
                    approved=False,
                    risk="blocked",
                    issues=[{"type": "policy", "message": "blocked"}],
                    corrected_command="",
                    safer_alternative="",
                    manual_only=True,
                    reason="blocked",
                    auto_execute=False,
                    confidence=0.9,
                ),
            ],
        )
        result = AnalysisResult(
            hosts=[Host(ip="10.0.0.10", services=[service], role="Web Server")],
            role_groups={"Web Server": ["10.0.0.10"]},
            findings=[finding],
            workflow="iterative",
        )
        state = build_initial_case_state(result, "external", sorted(EXECUTE_TOOLS))

        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "case_state.json"
            actions = generate_candidate_actions(result, state)
            path.write_text("{}", encoding="utf-8")

        self.assertEqual(len(state.approved_commands), 1)
        self.assertEqual(len(state.manual_only_commands), 1)
        self.assertEqual(actions[0].action_type, "safe_enumeration")


if __name__ == "__main__":
    unittest.main()
