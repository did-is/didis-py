import asyncio
import unittest
from unittest.mock import patch

import httpx

from didis.client import AsyncDidisClient, DidisClient, DidisError, retry_after_seconds

LIMITED = (429, {"title": "Rate limited", "detail": "wait", "code": "RATE_LIMITED"})


def scripted(answers, retry_after="0"):
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        status, body = answers.pop(0) if answers else (200, {"status": "ok"})
        headers = {"retry-after": retry_after} if status in (429, 503) else {}
        return httpx.Response(status, json=body, headers=headers)

    return calls, handler


class RetryTest(unittest.TestCase):
    def client(self, handler, **kw):
        real = httpx.Client
        with patch("didis.client.httpx.Client", lambda **k: real(transport=httpx.MockTransport(handler), **k)):
            return DidisClient(**kw)

    def test_waits_out_429_then_succeeds(self) -> None:
        calls, h = scripted([LIMITED])
        self.assertEqual(self.client(h).health(), {"status": "ok"})
        self.assertEqual(len(calls), 2)

    def test_bounded_and_surfaces_last_problem(self) -> None:
        calls, h = scripted([LIMITED] * 5)
        with self.assertRaises(DidisError) as caught:
            self.client(h).health()
        self.assertEqual(caught.exception.status, 429)
        self.assertEqual(caught.exception.problem["retryAfter"], "0")
        self.assertEqual(len(calls), 3)

    def test_disabled_long_wait_and_other_errors_do_not_retry(self) -> None:
        calls, h = scripted([LIMITED])
        with self.assertRaises(DidisError):
            self.client(h, retry=False).health()
        self.assertEqual(len(calls), 1)
        calls, h = scripted([LIMITED], retry_after="30")
        with self.assertRaises(DidisError):
            self.client(h).health()
        self.assertEqual(len(calls), 1)
        calls, h = scripted([(400, {"title": "Bad"})])
        with self.assertRaises(DidisError):
            self.client(h).health()
        self.assertEqual(len(calls), 1)

    def test_async_retries(self) -> None:
        calls, h = scripted([(503, {"title": "Busy"})])
        real = httpx.AsyncClient

        async def run():
            with patch("didis.client.httpx.AsyncClient", lambda **k: real(transport=httpx.MockTransport(h), **k)):
                c = AsyncDidisClient()
            return await c.health()

        self.assertEqual(asyncio.run(run()), {"status": "ok"})
        self.assertEqual(len(calls), 2)

    def test_retry_after_parsing(self) -> None:
        self.assertEqual(retry_after_seconds("3"), 3.0)
        self.assertEqual(retry_after_seconds("Thu, 01 Jan 1970 00:00:10 GMT", now=4.0), 6.0)
        self.assertIsNone(retry_after_seconds("soon"))
        self.assertIsNone(retry_after_seconds(None))


if __name__ == "__main__":
    unittest.main()
