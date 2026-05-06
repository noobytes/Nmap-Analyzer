import tempfile
import unittest
from pathlib import Path

from pentest_assistant.rag.chunker import chunk_markdown_file, chunk_markdown_text


class TestRagChunker(unittest.TestCase):
    def test_heading_chunking(self) -> None:
        markdown = """---
title: SMB Notes
source_type: playbooks
service: smb
ports: 445,139
---
# Intro
Line one.

## Commands
```bash
nmap --script smb2-security-mode -p445 TARGET
```
"""
        chunks = chunk_markdown_text(markdown, "smb.md", max_chunk_size=500)
        self.assertGreaterEqual(len(chunks), 2)
        self.assertEqual(chunks[0].metadata["service"], "smb")
        self.assertIn("Intro", chunks[0].metadata["heading"])

    def test_metadata_preservation(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "http.md"
            path.write_text(
                "---\nsource_type: playbooks\nservice: http\nprofile: external\ntitle: HTTP Notes\n---\n# Section\nText",
                encoding="utf-8",
            )
            chunks = chunk_markdown_file(path)
        self.assertEqual(chunks[0].metadata["source_type"], "playbooks")
        self.assertEqual(chunks[0].metadata["profile"], "external")
        self.assertEqual(chunks[0].metadata["title"], "HTTP Notes")


if __name__ == "__main__":
    unittest.main()
