import unittest

from pentest_assistant.rag.retriever import KnowledgeRetriever
from pentest_assistant.rag.schemas import RetrievalRequest, RetrievalResult


class _ContextStore:
    def search(self, query: str, top_k: int = 5, filters=None):
        service = (filters or {}).get("service", "")
        profile = (filters or {}).get("profile", "")
        if service == "smb":
            return [RetrievalResult(id="smb1", text="SMB internal chunk", score=0.1, metadata={"service": "smb", "profile": "internal", "title": "SMB", "heading": "Structured"}, commands=[{"command": "nmap --script smb2-security-mode -p445 TARGET", "risk": "low", "safe_for_auto_execute": True}])]
        if profile == "internal":
            return [RetrievalResult(id="meth1", text="Internal methodology", score=0.2, metadata={"service": "", "profile": "internal", "title": "Internal", "heading": "Methodology"})]
        return []


class TestContextualRetrieval(unittest.TestCase):
    def test_internal_profile_prefers_internal_context(self) -> None:
        retriever = KnowledgeRetriever(_ContextStore(), top_k=5)
        context = retriever.retrieve(RetrievalRequest(service="microsoft-ds", port=445, profile="internal"))
        self.assertTrue(context.results)
        self.assertEqual(context.results[0].metadata["service"], "smb")
        self.assertTrue(context.recommended_commands)


if __name__ == "__main__":
    unittest.main()
