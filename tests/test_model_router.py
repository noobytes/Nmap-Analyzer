import unittest

from pentest_assistant.pipeline import AnalysisConfig
from pentest_assistant.providers import get_model_for_stage, resolve_models


class TestModelRouter(unittest.TestCase):
    def test_quick_preset_matches_requested_architecture(self) -> None:
        resolved = resolve_models(AnalysisConfig(ai_provider="ollama", preset="quick"))
        expected = {
            "network_overview": "gemma4:26b",
            "profile_analysis": "qwen3:30b",
            "command_generation": "qwen3:30b",
            "command_sanity_check": "qwen3:30b",
            "iterative_ranking": "qwen3:30b",
            "result_review": "gemma4:26b",
            "evidence_to_finding": "qwen3:30b",
            "report_writing": "gemma4:26b",
        }
        self.assertEqual({stage: get_model_for_stage(stage, resolved) for stage in expected}, expected)

    def test_deep_preset_matches_requested_architecture(self) -> None:
        resolved = resolve_models(AnalysisConfig(ai_provider="ollama", preset="deep"))
        expected = {
            "network_overview": "gemma4:26b",
            "profile_analysis": "qwen3:30b",
            "command_generation": "qwen3:30b",
            "command_sanity_check": "qwen3:30b",
            "iterative_ranking": "qwen3:30b",
            "result_review": "qwen3:30b",
            "evidence_to_finding": "qwen3:30b",
            "report_writing": "gemma4:26b",
        }
        self.assertEqual({stage: get_model_for_stage(stage, resolved) for stage in expected}, expected)


if __name__ == "__main__":
    unittest.main()
