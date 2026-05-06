import importlib.util
import tempfile
import unittest

from pentest_assistant.rag.schemas import KnowledgeChunk

CHROMA_AVAILABLE = importlib.util.find_spec("chromadb") is not None

if CHROMA_AVAILABLE:
    from pentest_assistant.rag.vector_store import ChromaVectorStore


@unittest.skipUnless(CHROMA_AVAILABLE, "chromadb not installed")
class TestRagVectorStore(unittest.TestCase):
    def test_add_and_search(self) -> None:
        def fake_embed(text: str) -> list[float]:
            text = text.lower()
            return [1.0 if "smb" in text else 0.0, 1.0 if "http" in text else 0.0]

        with tempfile.TemporaryDirectory() as td:
            store = ChromaVectorStore(db_path=td, embedding_fn=fake_embed)
            store.reset()
            store.add_chunks(
                [
                    KnowledgeChunk(id="a", text="SMB playbook guidance", metadata={"service": "smb", "source_type": "playbooks"}),
                    KnowledgeChunk(id="b", text="HTTP playbook guidance", metadata={"service": "http", "source_type": "playbooks"}),
                ]
            )
            results = store.search("SMB safe enumeration", top_k=1, filters={"service": "smb"})
            count = store.count()

        self.assertEqual(count, 2)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].metadata["service"], "smb")


if __name__ == "__main__":
    unittest.main()
