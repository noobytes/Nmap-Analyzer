import unittest

from nmap_analyzer import _build_parser


class TestRagCliFlags(unittest.TestCase):
    def test_rag_flags_parse(self) -> None:
        args = _build_parser().parse_args(
            [
                "scan.xml",
                "--ai",
                "--rag",
                "--rag-rebuild",
                "--rag-top-k",
                "7",
                "--knowledge-dir",
                "pentest_assistant/knowledge",
                "--rag-db-path",
                ".nmap_analyzer/chroma",
                "--embedding-model",
                "nomic-embed-text",
            ]
        )
        self.assertTrue(args.rag)
        self.assertTrue(args.rag_rebuild)
        self.assertEqual(args.rag_top_k, 7)
        self.assertEqual(args.knowledge_dir, "pentest_assistant/knowledge")
        self.assertEqual(args.embedding_model, "nomic-embed-text")


if __name__ == "__main__":
    unittest.main()
