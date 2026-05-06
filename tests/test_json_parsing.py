import json
import unittest

from pentest_assistant.core.json_utils import extract_json_array, extract_json_object, parse_agent_json


class _FakeProvider:
    def __init__(self, responses):
        self.responses = list(responses)

    def generate(self, prompt: str, max_tokens: int = 4000, think: bool | None = None) -> str:
        return self.responses.pop(0)


class TestJsonParsing(unittest.TestCase):
    def test_extract_json_object_from_wrapped_text(self) -> None:
        raw = "analysis\n```json\n{\"ok\": true, \"value\": 1}\n```"
        self.assertEqual(json.loads(extract_json_object(raw))["value"], 1)

    def test_extract_json_array_from_wrapped_text(self) -> None:
        raw = "```json\n[{\"ok\": true}]\n```"
        self.assertTrue(json.loads(extract_json_array(raw))[0]["ok"])

    def test_parse_agent_json_retries_once(self) -> None:
        provider = _FakeProvider(["not json", "{\"ok\": true}"])
        payload, failure = parse_agent_json(
            provider,
            "prompt",
            "test-stage",
            lambda raw: json.loads(extract_json_object(raw)),
        )
        self.assertIsNone(failure)
        self.assertEqual(payload["ok"], True)

    def test_parse_agent_json_returns_failure_without_crashing(self) -> None:
        provider = _FakeProvider(["bad", "still bad"])
        payload, failure = parse_agent_json(
            provider,
            "prompt",
            "test-stage",
            lambda raw: json.loads(extract_json_object(raw)),
        )
        self.assertIsNone(payload)
        self.assertEqual(failure.stage, "test-stage")


if __name__ == "__main__":
    unittest.main()
