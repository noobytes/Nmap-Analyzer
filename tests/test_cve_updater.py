import unittest

from update_cve_db import _extract_row


def _sample_vulnerability() -> dict:
    return {
        "cve": {
            "id": "CVE-2099-0001",
            "descriptions": [
                {"lang": "en", "value": "Example remote code execution flaw"},
            ],
            "metrics": {
                "cvssMetricV31": [
                    {
                        "cvssData": {
                            "baseScore": 9.8,
                            "baseSeverity": "CRITICAL",
                        }
                    }
                ]
            },
            "configurations": [
                {
                    "nodes": [
                        {
                            "cpeMatch": [
                                {
                                    "vulnerable": True,
                                    "criteria": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
                                }
                            ]
                        }
                    ]
                }
            ],
        }
    }


class CVEUpdaterTests(unittest.TestCase):
    def test_extract_row_maps_expected_fields(self) -> None:
        vuln = _sample_vulnerability()
        row = _extract_row(vuln, set())
        self.assertIsNotNone(row)
        assert row is not None
        self.assertEqual(row[0], "CVE-2099-0001")
        self.assertEqual(row[1], "apache:http_server")
        self.assertEqual(row[2], "2.4.49")
        self.assertEqual(row[3], "CRITICAL")
        self.assertEqual(row[4], 9.8)
        self.assertIn("remote code execution", row[5])

    def test_extract_row_returns_none_for_missing_cve_id(self) -> None:
        vuln = {"cve": {"descriptions": [], "metrics": {}}}
        row = _extract_row(vuln, set())
        self.assertIsNone(row)

    def test_extract_row_marks_kev_by_id(self) -> None:
        vuln = _sample_vulnerability()
        row = _extract_row(vuln, {"CVE-2099-0001"})
        self.assertIsNotNone(row)
        assert row is not None
        # is_kev is index 7 — should be 1 when cve_id is in kev_ids
        self.assertEqual(row[7], 1)

    def test_extract_row_not_kev_when_absent(self) -> None:
        vuln = _sample_vulnerability()
        row = _extract_row(vuln, set())
        self.assertIsNotNone(row)
        assert row is not None
        self.assertEqual(row[7], 0)


if __name__ == "__main__":
    unittest.main()
