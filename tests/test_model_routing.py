import unittest
from unittest.mock import patch

from nmap_analyzer import _preflight_ai
from pentest_assistant.pipeline import AnalysisConfig
from pentest_assistant.providers import DEFAULT_MODELS, get_model_for_stage, resolve_models


class ModelRoutingTests(unittest.TestCase):
    def test_default_mode_uses_qwen3_for_all_stages(self) -> None:
        config = AnalysisConfig(ai_provider="ollama")

        resolved = resolve_models(config)

        self.assertIsNone(resolved["preset"])
        self.assertEqual(resolved["primary_model"], DEFAULT_MODELS["ollama"])
        self.assertIsNone(resolved["review_model"])
        for stage in (
            "network_overview",
            "profile_analysis",
            "command_generation",
            "command_sanity_check",
            "iterative_ranking",
            "result_review",
            "report_writing",
        ):
            self.assertEqual(
                get_model_for_stage(stage, resolved),
                DEFAULT_MODELS["ollama"],
                msg=f"stage '{stage}' should use the default model",
            )

    def test_quick_preset_stage_routing(self) -> None:
        config = AnalysisConfig(ai_provider="ollama", preset="quick")

        resolved = resolve_models(config)

        self.assertEqual(resolved["primary_model"], "gemma4:26b")
        self.assertEqual(resolved["review_model"], "qwen3:30b")
        # gemma4:26b handles the bookend stages
        self.assertEqual(get_model_for_stage("network_overview", resolved), "gemma4:26b")
        self.assertEqual(get_model_for_stage("result_review", resolved), "gemma4:26b")
        # qwen3:30b handles everything in between
        self.assertEqual(get_model_for_stage("profile_analysis", resolved), "qwen3:30b")
        self.assertEqual(get_model_for_stage("command_generation", resolved), "qwen3:30b")
        self.assertEqual(get_model_for_stage("command_sanity_check", resolved), "qwen3:30b")
        self.assertEqual(get_model_for_stage("iterative_ranking", resolved), "qwen3:30b")
        self.assertEqual(get_model_for_stage("report_writing", resolved), "gemma4:26b")

    def test_deep_preset_stage_routing(self) -> None:
        config = AnalysisConfig(ai_provider="ollama", preset="deep")

        resolved = resolve_models(config)

        self.assertEqual(resolved["primary_model"], "gemma4:26b")
        self.assertEqual(resolved["review_model"], "qwen3:30b")
        # gemma4:26b handles only network_overview
        self.assertEqual(get_model_for_stage("network_overview", resolved), "gemma4:26b")
        # qwen3:30b handles all remaining stages
        self.assertEqual(get_model_for_stage("profile_analysis", resolved), "qwen3:30b")
        self.assertEqual(get_model_for_stage("command_generation", resolved), "qwen3:30b")
        self.assertEqual(get_model_for_stage("command_sanity_check", resolved), "qwen3:30b")
        self.assertEqual(get_model_for_stage("iterative_ranking", resolved), "qwen3:30b")
        self.assertEqual(get_model_for_stage("result_review", resolved), "qwen3:30b")
        self.assertEqual(get_model_for_stage("report_writing", resolved), "gemma4:26b")

    def test_command_sanity_check_stage_exists_and_is_routable(self) -> None:
        """command_sanity_check must be a recognised stage in all routing modes."""
        for preset in ("", "quick", "deep"):
            config = AnalysisConfig(ai_provider="ollama", preset=preset)
            resolved = resolve_models(config)
            model = get_model_for_stage("command_sanity_check", resolved)
            self.assertIsNotNone(model, msg=f"preset={preset!r}: command_sanity_check has no model")
            self.assertNotEqual(model, "", msg=f"preset={preset!r}: command_sanity_check model is empty")

    def test_model_override_precedence(self) -> None:
        # When ai_model is explicit AND a preset is active, the explicit primary
        # only replaces the preset's primary_model.  Review stages (profile_analysis,
        # command_generation, command_sanity_check, iterative_ranking) still use the
        # preset's review_model (qwen3:30b) because they appear in review_stages.
        config = AnalysisConfig(
            ai_provider="ollama",
            preset="quick",
            ai_model="custom-primary:14b",
        )

        resolved = resolve_models(config)

        # Non-review stages get the custom primary
        self.assertEqual(get_model_for_stage("network_overview", resolved), "custom-primary:14b")
        self.assertEqual(get_model_for_stage("result_review", resolved), "custom-primary:14b")
        # Review stages still use the preset's review_model
        self.assertEqual(get_model_for_stage("profile_analysis", resolved), "qwen3:30b")
        self.assertEqual(get_model_for_stage("command_generation", resolved), "qwen3:30b")
        self.assertEqual(get_model_for_stage("command_sanity_check", resolved), "qwen3:30b")
        self.assertEqual(get_model_for_stage("iterative_ranking", resolved), "qwen3:30b")

    def test_review_model_override_precedence(self) -> None:
        config = AnalysisConfig(
            ai_provider="ollama",
            preset="quick",
            review_model="custom-review:8b",
        )

        resolved = resolve_models(config)

        self.assertEqual(get_model_for_stage("network_overview", resolved), "gemma4:26b")
        self.assertEqual(get_model_for_stage("result_review", resolved), "gemma4:26b")
        self.assertEqual(get_model_for_stage("profile_analysis", resolved), "custom-review:8b")
        self.assertEqual(get_model_for_stage("command_sanity_check", resolved), "custom-review:8b")
        self.assertEqual(get_model_for_stage("iterative_ranking", resolved), "custom-review:8b")

    def test_result_review_falls_back_to_primary_when_review_model_absent(self) -> None:
        config = AnalysisConfig(
            ai_provider="ollama",
            ai_model="custom-primary:14b",
        )

        resolved = resolve_models(config)

        for stage in (
            "network_overview",
            "profile_analysis",
            "command_generation",
            "command_sanity_check",
            "iterative_ranking",
            "result_review",
            "report_writing",
        ):
            self.assertEqual(get_model_for_stage(stage, resolved), "custom-primary:14b")

    def test_review_override_without_preset_only_affects_result_review(self) -> None:
        config = AnalysisConfig(
            ai_provider="ollama",
            review_model="custom-review:8b",
        )

        resolved = resolve_models(config)

        self.assertEqual(get_model_for_stage("network_overview", resolved), DEFAULT_MODELS["ollama"])
        self.assertEqual(get_model_for_stage("profile_analysis", resolved), DEFAULT_MODELS["ollama"])
        self.assertEqual(get_model_for_stage("command_generation", resolved), DEFAULT_MODELS["ollama"])
        self.assertEqual(get_model_for_stage("command_sanity_check", resolved), DEFAULT_MODELS["ollama"])
        self.assertEqual(get_model_for_stage("iterative_ranking", resolved), DEFAULT_MODELS["ollama"])
        self.assertEqual(get_model_for_stage("result_review", resolved), "custom-review:8b")
        self.assertEqual(get_model_for_stage("report_writing", resolved), DEFAULT_MODELS["ollama"])

    @patch("nmap_analyzer.get_missing_stage_models")
    def test_missing_model_error_handling_for_stage_based_routing(self, missing_models_mock) -> None:
        resolved = resolve_models(
            AnalysisConfig(ai_provider="ollama", preset="quick")
        )
        missing_models_mock.return_value = [("command_sanity_check", "qwen3:30b")]

        ok, warnings, errors = _preflight_ai(
            "ollama",
            resolved,
            strict_routing=True,
            api_key=None,
        )

        self.assertFalse(ok)
        self.assertEqual(warnings, [])
        self.assertEqual(len(errors), 1)
        self.assertIn("stage 'command_sanity_check'", errors[0])
        self.assertIn("ollama pull qwen3:30b", errors[0])


if __name__ == "__main__":
    unittest.main()
