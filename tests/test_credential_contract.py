"""Sync/async credential audience options preserve raw text and error retry metadata."""
import json
import unittest
from unittest.mock import patch

import httpx
from didis.client import AsyncDidisClient, DidisClient, DidisError

RAW = '{"issuer":"bad","issuer":"good"}'


def transport_handler(request: httpx.Request) -> httpx.Response:
    assert request.url.path == "/v1/credentials/verify"
    body = json.loads(request.content)
    assert body["credential"] == RAW
    if body.get("expectedAudience") == "recipient":
        return httpx.Response(429, json={"title": "Limited", "detail": "Retry later"}, headers={"retry-after": "5"})
    assert "expectedAudience" not in body
    return httpx.Response(200, json={"status": "MALFORMED", "valid": False})


class SyncContract(unittest.TestCase):
    def test_additive_audience_raw_text_and_retry_hint(self) -> None:
        underlying = httpx.Client(base_url="https://example.com", transport=httpx.MockTransport(transport_handler))
        with patch("didis.client.httpx.Client", return_value=underlying):
            client = DidisClient("https://example.com")
        try:
            self.assertEqual(client.verify_credential(RAW)["status"], "MALFORMED")
            with self.assertRaises(DidisError) as caught:
                client.verify_credential(RAW, expected_audience="recipient")
            self.assertEqual(caught.exception.status, 429)
            self.assertEqual(caught.exception.problem["retryAfter"], "5")
        finally:
            client.close()


class AsyncContract(unittest.IsolatedAsyncioTestCase):
    async def test_additive_audience_raw_text_and_retry_hint(self) -> None:
        underlying = httpx.AsyncClient(base_url="https://example.com", transport=httpx.MockTransport(transport_handler))
        with patch("didis.client.httpx.AsyncClient", return_value=underlying):
            client = AsyncDidisClient("https://example.com")
        try:
            self.assertEqual((await client.verify_credential(RAW))["status"], "MALFORMED")
            with self.assertRaises(DidisError) as caught:
                await client.verify_credential(RAW, expected_audience="recipient")
            self.assertEqual(caught.exception.status, 429)
            self.assertEqual(caught.exception.problem["retryAfter"], "5")
        finally:
            await client.close()


if __name__ == "__main__":
    unittest.main()
