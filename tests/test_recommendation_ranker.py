import unittest

from pentest_assistant.rag.recommendation_ranker import rank_recommendations


class TestRecommendationRanker(unittest.TestCase):
    def test_low_risk_high_relevance_ranks_first(self) -> None:
        ranked = rank_recommendations(
            [
                {"command": "nuclei -u http://TARGET", "risk": "medium", "service": "http", "source_type": "json_playbook", "context": "both", "safe_for_auto_execute": False},
                {"command": "curl -I http://TARGET", "risk": "low", "service": "http", "source_type": "json_playbook", "context": "both", "safe_for_auto_execute": True},
            ],
            request_service="http",
            profile="external",
        )
        self.assertEqual(ranked[0]["command"], "curl -I http://TARGET")

    def test_previous_command_penalty(self) -> None:
        ranked = rank_recommendations(
            [
                {"command": "curl -I http://TARGET", "risk": "low", "service": "http", "source_type": "json_playbook", "context": "both", "safe_for_auto_execute": True},
                {"command": "whatweb http://TARGET", "risk": "low", "service": "http", "source_type": "json_playbook", "context": "both", "safe_for_auto_execute": True},
            ],
            request_service="http",
            profile="external",
            previous_commands={"curl -I http://TARGET"},
        )
        self.assertEqual(ranked[0]["command"], "whatweb http://TARGET")

    def test_ffuf_ranks_above_fallback_and_manual_web_fuzzers(self) -> None:
        ranked = rank_recommendations(
            [
                {"command": "gobuster dir -u http://TARGET -w list.txt", "risk": "manual_only", "service": "http", "source_type": "json_playbook", "context": "external", "safe_for_auto_execute": False, "manual_only": True, "category": "web_content_discovery"},
                {"command": "feroxbuster -u http://TARGET -w list.txt -t 10 -r --depth 1 --rate-limit 50", "risk": "medium", "service": "http", "source_type": "json_playbook", "context": "external", "safe_for_auto_execute": False, "manual_only": True, "category": "web_content_discovery"},
                {"command": "ffuf -u http://TARGET/FUZZ -w list.txt -t 10 -rate 50 -timeout 10", "risk": "medium", "service": "http", "source_type": "json_playbook", "context": "external", "safe_for_auto_execute": True, "manual_only": False, "category": "web_content_discovery"},
            ],
            request_service="http",
            profile="external",
            available_tools={"ffuf", "feroxbuster"},
        )
        self.assertEqual(ranked[0]["command"], "ffuf -u http://TARGET/FUZZ -w list.txt -t 10 -rate 50 -timeout 10")
        self.assertEqual(ranked[-1]["command"], "gobuster dir -u http://TARGET -w list.txt")


if __name__ == "__main__":
    unittest.main()
