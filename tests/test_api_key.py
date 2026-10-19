import asyncio
import json
import unittest
from unittest.mock import patch

import httpx

from didis.client import AsyncDidisClient, DidisClient


def recorder(status_first=None):
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if status_first and len(calls) == 1:
            return httpx.Response(status_first, json={"title": "busy"}, headers={"retry-after": "0"})
        return httpx.Response(200, json={})

    return calls, handler


def sync_client(handler, **kw):
    real = httpx.Client
    with patch("didis.client.httpx.Client", lambda **k: real(transport=httpx.MockTransport(handler), **k)):
        return DidisClient(base_url="http://x", **kw)


class ApiKeyTest(unittest.TestCase):
    def test_paid_routes_with_fresh_idempotency_keys(self) -> None:
        calls, handler = recorder()
        c = sync_client(handler, api_key="didis_test")
        c.inspect_mcp("https://mcp.example.com/mcp")
        c.inspect_a2a("https://agent.example.com")
        c.authorize(["r1"], "payments:transfer")
        c.verify_delegation(["r1"], trusted_roots=["did:web:a"])
        c.usage()
        self.assertEqual([f"{r.method} {r.url.path}" for r in calls], [
            "POST /v1/customer/mcp/inspect",
            "POST /v1/customer/a2a/inspect",
            "POST /v1/customer/agents/authorize",
            "POST /v1/customer/agents/verify-delegation",
            "GET /v1/customer/usage",
        ])
        self.assertEqual(json.loads(calls[2].content), {"chain": ["r1"], "tool": "payments:transfer"})
        self.assertEqual(json.loads(calls[3].content), {"chain": ["r1"], "trustedRoots": ["did:web:a"]})
        for r in calls:
            self.assertEqual(r.headers["authorization"], "Bearer didis_test")
        keys = [r.headers["idempotency-key"] for r in calls[:4]]
        self.assertEqual(len(set(keys)), 4)
        self.assertNotIn("idempotency-key", calls[4].headers)

    def test_retry_reuses_idempotency_key(self) -> None:
        calls, handler = recorder(status_first=503)
        sync_client(handler, api_key="k").inspect_mcp("https://m.example/mcp")
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0].headers["idempotency-key"], calls[1].headers["idempotency-key"])

    def test_without_key_and_register_stay_public(self) -> None:
        calls, handler = recorder()
        sync_client(handler).inspect_mcp("https://m.example/mcp")
        sync_client(handler, api_key="k").verify_delegation(["r1"], register=True)
        self.assertEqual(calls[0].url.path, "/v1/mcp/inspect")
        self.assertEqual(calls[1].url.path, "/v1/agents/verify-delegation")
        for r in calls:
            self.assertNotIn("authorization", r.headers)
        with self.assertRaises(ValueError):
            sync_client(handler).usage()

    def test_async_paid_route(self) -> None:
        calls, handler = recorder()
        real = httpx.AsyncClient

        async def run() -> None:
            with patch("didis.client.httpx.AsyncClient", lambda **k: real(transport=httpx.MockTransport(handler), **k)):
                c = AsyncDidisClient(base_url="http://x", api_key="k")
            await c.authorize(["r1"], "t")
            await c.close()

        asyncio.run(run())
        self.assertEqual(calls[0].url.path, "/v1/customer/agents/authorize")
        self.assertEqual(calls[0].headers["authorization"], "Bearer k")
        self.assertIn("idempotency-key", calls[0].headers)


if __name__ == "__main__":
    unittest.main()
