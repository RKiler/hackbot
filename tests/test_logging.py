from io import StringIO
import json
import unittest

from hackbot.logging import REDACTED, create_logger


class LoggingTests(unittest.TestCase):
    def _log(
        self, message: str, *, context: object = None, env: dict[str, str] | None = None
    ) -> dict:
        stream = StringIO()
        logger = create_logger(stream=stream, environ={} if env is None else env)
        logger.info(message, extra={"context": context})
        return json.loads(stream.getvalue())

    def test_json_structure(self) -> None:
        record = self._log("started", context={"item_id": 12})
        self.assertEqual(record["level"], "INFO")
        self.assertEqual(record["logger"], "hackbot")
        self.assertEqual(record["context"], {"item_id": 12})
        self.assertIn("timestamp", record)

    def test_nested_secret_fields(self) -> None:
        context = {
            "password": "pword123",
            "headers": {
                "Authorization": "Basic abc123",
                "Cookie": "sid=abc",
                "X-Api-Key": "key123",
            },
            "nested": [{"session_token": "sess123", "client_secret": "secret123"}],
            "safe": "visible",
        }
        record = self._log("test", context=context)
        serialized = json.dumps(record)
        for secret in ("pword123", "abc123", "key123", "sess123", "secret123"):
            self.assertNotIn(secret, serialized)
        self.assertEqual(record["context"]["password"], REDACTED)
        self.assertEqual(record["context"]["safe"], "visible")

    def test_free_text_authorization_cookie_bearer_and_assignments(self) -> None:
        raw = (
            'Authorization: Bearer auth123\nCookie: sid=cookie123\n'
            'password=pass123 api_key=key123 session_token=sess123 '
            '"client_secret":"secret123" Bearer loose123'
        )
        output = json.dumps(self._log(raw))
        for secret in (
            "auth123", "cookie123", "pass123", "key123", "sess123", "secret123", "loose123"
        ):
            self.assertNotIn(secret, output)

    def test_environment_secret_values_and_explicit_values(self) -> None:
        stream = StringIO()
        logger = create_logger(
            stream=stream,
            environ={"AWS_SECRET_ACCESS_KEY": "envsecret123", "PUBLIC_ID": "visible-id"},
            additional_secret_values=("explicitsecret123",),
        )
        logger.info("envsecret123 explicitsecret123 visible-id")
        output = stream.getvalue()
        self.assertNotIn("envsecret123", output)
        self.assertNotIn("explicitsecret123", output)
        self.assertIn("visible-id", output)

    def test_common_short_credential_names_are_redacted(self) -> None:
        stream = StringIO()
        logger = create_logger(
            stream=stream,
            environ={"DB_PASS": "dbpass123", "GITHUB_PAT": "githubpat123"},
        )
        logger.info(
            "dbpass123 githubpat123 key=plainkey123",
            extra={"context": {"pass": "fieldpass123", "api_key": "fieldkey123"}},
        )
        output = stream.getvalue()
        for secret in ("dbpass123", "githubpat123", "plainkey123", "fieldpass123", "fieldkey123"):
            self.assertNotIn(secret, output)
        self.assertEqual(json.loads(output)["context"]["pass"], REDACTED)

    def test_inline_authorization_with_basic_scheme(self) -> None:
        output = json.dumps(self._log("Authorization=Basic basicsecret123; status=denied"))
        self.assertNotIn("basicsecret123", output)
        self.assertIn("status=denied", output)

    def test_quoted_bearer_token(self) -> None:
        output = json.dumps(self._log('Bearer "quotedsecret123"'))
        self.assertNotIn("quotedsecret123", output)

    def test_exception_message_is_not_emitted(self) -> None:
        stream = StringIO()
        logger = create_logger(stream=stream, environ={})
        try:
            raise RuntimeError("unstructured-secret-not-in-registry")
        except RuntimeError:
            logger.exception("failed")
        record = json.loads(stream.getvalue())
        self.assertEqual(record["exception_type"], "RuntimeError")
        self.assertNotIn("unstructured-secret-not-in-registry", stream.getvalue())
