import unittest
from unittest.mock import MagicMock

from pentest_assistant.ai import AICommandGenerator, CommandSanityChecker
from pentest_assistant.models import Service


class TestAgentKnowledgeContext(unittest.TestCase):
    def test_command_generation_prompt_includes_knowledge_context(self) -> None:
        generator = AICommandGenerator(provider=MagicMock(), max_commands=3)
        prompt = generator._build_prompt(
            Service(port=445, protocol="tcp", name="microsoft-ds", product="Windows", version=""),
            "File Server",
            knowledge_context="knowledge_context:\nSMB safe validation only",
        )
        self.assertIn("<untrusted_knowledge_context>", prompt)
        self.assertIn("SMB safe validation only", prompt)

    def test_agents_still_work_when_no_chunks_returned(self) -> None:
        provider = MagicMock()
        provider.generate.return_value = '[{"approved": true, "risk": "low", "issues": [], "corrected_command": "", "safer_alternative": "", "manual_only": false, "reason": "", "confidence": 0.9}]'
        checker = CommandSanityChecker(provider)
        results = checker.check(
            ["nmap -sV TARGET"],
            Service(port=22, protocol="tcp", name="ssh"),
            knowledge_context="",
        )
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0].approved)


if __name__ == "__main__":
    unittest.main()
