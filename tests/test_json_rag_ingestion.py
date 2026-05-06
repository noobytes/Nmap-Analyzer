import importlib.util
import tempfile
import unittest
from pathlib import Path

from pentest_assistant.rag.chunker import chunk_markdown_text
from pentest_assistant.rag.json_playbook_loader import load_json_playbook_chunks

CHROMA_AVAILABLE = importlib.util.find_spec("chromadb") is not None

if CHROMA_AVAILABLE:
    from pentest_assistant.rag.vector_store import ChromaVectorStore


@unittest.skipUnless(CHROMA_AVAILABLE, "chromadb not installed")
class TestJsonRagIngestion(unittest.TestCase):
    def test_markdown_and_json_chunks_ingest_together(self) -> None:
        def fake_embed(text: str) -> list[float]:
            lowered = text.lower()
            return [1.0 if "smb" in lowered else 0.0, 1.0 if "http" in lowered else 0.0]

        markdown = "---\nsource_type: playbooks\nservice: http\n---\n# HTTP\ncurl -I http://TARGET"
        with tempfile.TemporaryDirectory() as td:
            md_chunks = chunk_markdown_text(markdown, Path(td) / "http.md")
            json_path = Path(td) / "playbooks.json"
            json_path.write_text(
                '{"smb":{"ports":[445],"protocol":"tcp","description":"SMB","context":"internal","category":"windows","tools":["nmap"],"commands":["nmap --script smb2-security-mode -p445 TARGET"],"notes":"note"}}',
                encoding="utf-8",
            )
            json_chunks = load_json_playbook_chunks(json_path)
            store = ChromaVectorStore(db_path=td, embedding_fn=fake_embed)
            store.reset()
            store.add_chunks(md_chunks + json_chunks)
            count = store.count()

        self.assertEqual(count, 2)


if __name__ == "__main__":
    unittest.main()
