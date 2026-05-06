import tempfile
import unittest
from pathlib import Path

from pentest_assistant.rag.json_playbook_loader import load_json_playbook_chunks


class TestJsonPlaybookLoader(unittest.TestCase):
    def test_loader_creates_chunks_and_classifies_commands(self) -> None:
        payload = """
        {
          "smb": {
            "ports": [445, 139],
            "protocol": "tcp",
            "description": "Server Message Block",
            "context": "internal",
            "category": "windows",
            "tools": ["nmap", "smbclient", "hydra"],
            "commands": ["nmap --script smb2-security-mode -p445 TARGET", "hydra -L users.txt -P rockyou.txt smb://TARGET"],
            "notes": "Check signing",
            "services": ["microsoft-ds"]
          }
        }
        """
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "playbooks.json"
            path.write_text(payload, encoding="utf-8")
            chunks = load_json_playbook_chunks(path)

        self.assertEqual(len(chunks), 1)
        self.assertEqual(chunks[0].metadata["service"], "smb")
        self.assertIn("SMB Enumeration Playbook", chunks[0].text)
        self.assertEqual(chunks[0].commands[0]["risk"], "low")
        self.assertEqual(chunks[0].commands[1]["risk"], "manual_only")


if __name__ == "__main__":
    unittest.main()
