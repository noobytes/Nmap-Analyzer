import unittest
from unittest.mock import patch

from nmap_analyzer import _preflight_ai
from pentest_assistant.pipeline import AnalysisConfig
from pentest_assistant.providers import DEFAULT_MODELS, get_model_for_stage, resolve_models


class ModelRoutingTests(unittest.TestCase):
    def test_default_mode_keeps_current_routing_unchanged(self) -> None:
        config = AnalysisConfig(ai_provider="ollama")

        resolved = resolve_models(config)

        self.assertIsNone(resolved["preset"])
        self.assertEqual(resolved["primary_model"], DEFAULT_MODELS["ollama"])
        self.assertIsNone(resolved["review_model"])
        self.assertEqual(get_model_for_stage("analysis", resolved), DEFAULT_MODELS["ollama"])
        self.assertEqual(get_model_for_stage("command_generation", resolved), DEFAULT_MODELS["ollama"])
        self.assertEqual(get_model_for_stage("result_review", resolved), DEFAULT_MODELS["ollama"])

    def test_qwen_coder_preset_stage_routing(self) -> None:
        config = AnalysisConfig(ai_provider="ollama", preset="qwen-coder")

        resolved = resolve_models(config)

        self.assertEqual(resolved["primary_model"], "qwen3-coder:30b")
        self.assertIsNone(resolved["review_model"])
        self.assertEqual(get_model_for_stage("analysis", resolved), "qwen3-coder:30b")
        self.assertEqual(get_model_for_stage("command_generation", resolved), "qwen3-coder:30b")
        self.assertEqual(get_model_for_stage("result_review", resolved), "qwen3-coder:30b")

    def test_qwen_coder_devstral_preset_stage_routing(self) -> None:
        config = AnalysisConfig(ai_provider="ollama", preset="qwen-coder-devstral")

        resolved = resolve_models(config)

        self.assertEqual(resolved["primary_model"], "qwen3-coder:30b")
        self.assertEqual(resolved["review_model"], "devstral-small-2:24b")
        self.assertEqual(get_model_for_stage("analysis", resolved), "qwen3-coder:30b")
        self.assertEqual(get_model_for_stage("command_generation", resolved), "qwen3-coder:30b")
        self.assertEqual(get_model_for_stage("result_review", resolved), "devstral-small-2:24b")

    def test_model_override_precedence(self) -> None:
        config = AnalysisConfig(
            ai_provider="ollama",
            preset="qwen-coder-devstral",
            ai_model="custom-primary:14b",
        )

        resolved = resolve_models(config)

        self.assertEqual(get_model_for_stage("analysis", resolved), "custom-primary:14b")
        self.assertEqual(get_model_for_stage("command_generation", resolved), "custom-primary:14b")
        self.assertEqual(get_model_for_stage("result_review", resolved), "devstral-small-2:24b")

    def test_review_model_override_precedence(self) -> None:
        config = AnalysisConfig(
            ai_provider="ollama",
            preset="qwen-coder-devstral",
            review_model="custom-review:8b",
        )

        resolved = resolve_models(config)

        self.assertEqual(get_model_for_stage("analysis", resolved), "qwen3-coder:30b")
        self.assertEqual(get_model_for_stage("result_review", resolved), "custom-review:8b")

    def test_result_review_falls_back_to_primary_when_review_model_absent(self) -> None:
        config = AnalysisConfig(
            ai_provider="ollama",
            ai_model="custom-primary:14b",
        )

        resolved = resolve_models(config)

        self.assertEqual(get_model_for_stage("analysis", resolved), "custom-primary:14b")
        self.assertEqual(get_model_for_stage("result_review", resolved), "custom-primary:14b")

    @patch("nmap_analyzer.get_missing_stage_models")
    def test_missing_model_error_handling_for_stage_based_routing(self, missing_models_mock) -> None:
        resolved = resolve_models(
            AnalysisConfig(ai_provider="ollama", preset="qwen-coder-devstral")
        )
        missing_models_mock.return_value = [("result_review", "devstral-small-2:24b")]

        ok, warnings, errors = _preflight_ai(
            "ollama",
            resolved,
            strict_routing=True,
            api_key=None,
        )

        self.assertFalse(ok)
        self.assertEqual(warnings, [])
        self.assertEqual(len(errors), 1)
        self.assertIn("stage 'result_review'", errors[0])
        self.assertIn("ollama pull devstral-small-2:24b", errors[0])


if __name__ == "__main__":
    unittest.main()
