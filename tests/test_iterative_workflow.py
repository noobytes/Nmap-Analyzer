import tempfile
import unittest
from pathlib import Path

from pentest_assistant.ai import parse_analysis_json
from pentest_assistant.analysis_loop import (
    apply_state_patch,
    build_initial_case_state,
    generate_candidate_actions,
    run_iterative_analysis_loop,
)
from pentest_assistant.executor import EXECUTE_TOOLS
from pentest_assistant.models import (
    AnalysisResult,
    CommandResult,
    CommandSuggestion,
    Host,
    Service,
    ServiceFinding,
)
from pentest_assistant.state import CaseState, ServiceState, StatePatch


class _FakeProvider:
    def generate(self, prompt: str, max_tokens: int = 400) -> str:
        if "Candidate approved validation actions" in prompt:
            return """
            {
              "network_summary": {
                "facts": ["HTTP service exposed on 10.0.0.10."],
                "hypotheses": ["A small fingerprinting step will reduce uncertainty."],
                "focus": "Prefer the smallest approved HTTP validation."
              },
              "service_assessments": [],
              "global_next_steps": [
                {
                  "service_id": "tcp|80|http|apache|2.4.58",
                  "host": "10.0.0.10",
                  "command_template": "whatweb http://TARGET",
                  "goal": "Fingerprint the web service.",
                  "why_now": "Smallest approved next step.",
                  "expected_signal": "Headers and framework clues.",
                  "confidence": 0.8
                }
              ],
              "state_update": {
                "add_confirmed": [],
                "add_likely": [],
                "add_ruled_out": [],
                "add_dead_ends": [],
                "notes_for_next_iteration": ["Keep the next step narrow."]
              }
            }
            """
        return """
        {
          "result_classification": "useful",
          "what_the_result_shows": {
            "facts": ["The server identifies as Apache/2.4.58."],
            "hypotheses": ["Version evidence still needs manual confirmation."],
            "summary": "Banner information was captured successfully."
          },
          "hypothesis_update": {
            "prior_hypothesis": "Validate the most informative read-only check for 80 tcp/http Apache 2.4.58.",
            "status": "strengthened",
            "reason": "The command returned a concrete banner."
          },
          "new_findings": ["Apache banner exposed."],
          "noise_or_false_positive_risk": "Low.",
          "recommended_next_step": {},
          "state_patch": {
            "add_likely": ["Apache banner exposed on 10.0.0.10."],
            "notes_for_next_iteration": ["Avoid repeating the same fingerprint command."]
          }
        }
        """


class IterativeWorkflowTests(unittest.TestCase):
    def _make_result(self) -> AnalysisResult:
        service = Service(port=80, protocol="tcp", name="http", product="Apache", version="2.4.58")
        finding = ServiceFinding(
            service=service,
            ips=["10.0.0.10"],
            cves=[],
            playbook_commands=["whatweb http://TARGET"],
            ai_commands=["curl -I http://TARGET"],
            playbook_confidence=0.8,
            ai_confidence=0.45,
            command_suggestions=[
                CommandSuggestion(command="whatweb http://TARGET", source="playbook", confidence=0.8),
                CommandSuggestion(command="whatweb http://TARGET", source="ai", confidence=0.45),
                CommandSuggestion(command="curl -I http://TARGET", source="ai", confidence=0.45),
            ],
            risk_score=7.5,
        )
        return AnalysisResult(
            hosts=[Host(ip="10.0.0.10", services=[service], role="Web Server")],
            role_groups={"Web Server": ["10.0.0.10"]},
            findings=[finding],
            ai_enabled=True,
            workflow="iterative",
        )

    def test_case_state_creation(self) -> None:
        result = self._make_result()
        state = build_initial_case_state(
            result,
            engagement_profile="internal",
            approved_tools=sorted(EXECUTE_TOOLS),
        )

        self.assertEqual(state.engagement_profile, "internal")
        self.assertEqual(state.scope_hosts, ["10.0.0.10"])
        self.assertIn("tcp|80|http|apache|2.4.58", state.service_states)
        self.assertIn("CVE matches are version-based leads", state.service_states["tcp|80|http|apache|2.4.58"].cve_interpretation[0])

    def test_candidate_action_generation_and_deduplication(self) -> None:
        result = self._make_result()
        state = build_initial_case_state(result, "internal", sorted(EXECUTE_TOOLS))
        actions = generate_candidate_actions(result, state)
        safe_actions = [action for action in actions if action.action_type == "safe_enumeration"]

        self.assertEqual(len(safe_actions), 2)
        commands = {action.command_template for action in safe_actions}
        self.assertEqual(commands, {"whatweb http://TARGET", "curl -I http://TARGET"})

    def test_parse_valid_analysis_json(self) -> None:
        payload = parse_analysis_json(
            """
            analysis
            ```json
            {
              "network_summary": {"facts": ["a"], "hypotheses": ["b"], "focus": "c"},
              "service_assessments": [],
              "global_next_steps": [],
              "state_update": {"add_confirmed": []}
            }
            ```
            """
        )

        self.assertEqual(payload["network_summary"]["focus"], "c")
        self.assertEqual(payload["network_summary"]["facts"], ["a"])

    def test_handling_malformed_model_json(self) -> None:
        with self.assertRaises(ValueError):
            parse_analysis_json("not-json-at-all")

    def test_state_patch_application(self) -> None:
        state = CaseState(
            engagement_profile="internal",
            service_states={
                "svc-1": ServiceState(service_id="svc-1", service_label="service"),
            },
        )
        patch = StatePatch(
            add_confirmed=["Confirmed banner"],
            notes_for_next_iteration=["Try a different safe check next."],
            service_observations={"svc-1": ["Observation 1"]},
        )

        apply_state_patch(state, patch)

        self.assertIn("Confirmed banner", state.confirmed)
        self.assertIn("Try a different safe check next.", state.notes_for_next_iteration)
        self.assertIn("Observation 1", state.service_states["svc-1"].observations)

    def test_iterative_loop_selects_only_one_approved_action_by_default(self) -> None:
        result = self._make_result()
        state = build_initial_case_state(result, "internal", sorted(EXECUTE_TOOLS))
        provider = _FakeProvider()
        executed_batches: list[int] = []

        def _runner(commands, output_dir: Path):
            executed_batches.append(len(commands))
            output_dir.mkdir(parents=True, exist_ok=True)
            return [
                CommandResult(
                    command=commands[0].command,
                    service_label=commands[0].service_label,
                    target_ip=commands[0].target_ip,
                    tool=commands[0].tool,
                    stdout="Apache/2.4.58",
                    stderr="",
                    return_code=0,
                    duration=0.2,
                )
            ]

        with tempfile.TemporaryDirectory() as td:
            updated = run_iterative_analysis_loop(
                result=result,
                case_state=state,
                analysis_provider=provider,
                review_provider=provider,
                second_opinion_provider=None,
                max_exec_commands=1,
                batch_size=1,
                output_dir=td,
                execution_runner=_runner,
                case_state_path=Path(td) / "case_state.json",
            )

        self.assertEqual(executed_batches, [1])
        self.assertEqual(len(updated.execution_results), 1)
        self.assertIsNotNone(updated.next_best_action)
        self.assertIn("Apache banner exposed on 10.0.0.10.", updated.case_state.likely)


if __name__ == "__main__":
    unittest.main()
