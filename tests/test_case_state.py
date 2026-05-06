import unittest

from pentest_assistant.state import CaseCommand, CaseState


class TestCaseState(unittest.TestCase):
    def test_command_buckets_round_trip(self) -> None:
        state = CaseState(
            engagement_profile="external",
            approved_commands=[
                CaseCommand(command="curl -I http://TARGET", risk="low", auto_execute=True, approved=True)
            ],
            blocked_commands=[
                CaseCommand(command="hydra -L users -P pass ssh://TARGET", risk="blocked", manual_only=True)
            ],
            manual_only_commands=[
                CaseCommand(command="nmap -T5 -p- TARGET", risk="medium", manual_only=True)
            ],
            agent_failures=[{"stage": "result_review", "reason": "bad json"}],
        )

        restored = CaseState.from_dict(state.to_dict())

        self.assertEqual(restored.approved_commands[0].command, "curl -I http://TARGET")
        self.assertEqual(restored.blocked_commands[0].risk, "blocked")
        self.assertTrue(restored.manual_only_commands[0].manual_only)
        self.assertEqual(restored.agent_failures[0]["stage"], "result_review")


if __name__ == "__main__":
    unittest.main()
