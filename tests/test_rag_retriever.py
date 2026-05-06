import unittest

from pentest_assistant.rag.retriever import KnowledgeRetriever, normalize_service_name
from pentest_assistant.rag.schemas import RetrievalRequest, RetrievalResult


class _FakeStore:
    def search(self, query: str, top_k: int = 5, filters=None):
        service = (filters or {}).get("service", "")
        if service == "smb":
            return [RetrievalResult(id="1", text="SMB chunk", score=0.1, metadata={"service": "smb", "title": "SMB", "heading": "Safe Validation"})]
        return []


class TestRagRetriever(unittest.TestCase):
    def test_service_query_generation(self) -> None:
        retriever = KnowledgeRetriever(_FakeStore(), top_k=5)
        queries = retriever.build_queries(
            RetrievalRequest(service="smb", port=445, product="Windows", profile="internal", detected_role="File Server")
        )
        self.assertIn("SMB port 445 Windows", queries[0])

    def test_smb_retrieval_returns_smb_chunks(self) -> None:
        retriever = KnowledgeRetriever(_FakeStore(), top_k=5)
        context = retriever.retrieve(RetrievalRequest(service="microsoft-ds", port=445, profile="internal"))
        self.assertTrue(context.results)
        self.assertEqual(context.results[0].metadata["service"], "smb")
        self.assertEqual(normalize_service_name("microsoft-ds", 445), "smb")


if __name__ == "__main__":
    unittest.main()
