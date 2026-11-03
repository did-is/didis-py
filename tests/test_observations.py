"""Precise public observation selectors do not change legacy hash parameters."""
import unittest
from unittest.mock import patch
import httpx
from didis.client import AsyncDidisClient, DidisClient


def handler(request):
    assert request.url.params["fromObservation"] == "obs:11"
    assert request.url.params["toObservation"] == "obs:12"
    assert "from" not in request.url.params
    return httpx.Response(200, json={"domainBindingChanged": True})


class SyncObservation(unittest.TestCase):
    def test_exact_rows(self):
        underlying = httpx.Client(base_url="https://example.com", transport=httpx.MockTransport(handler))
        with patch("didis.client.httpx.Client", return_value=underlying):
            client = DidisClient("https://example.com")
        try:
            self.assertTrue(client.diff_observations("did:key:test", "obs:11", "obs:12")["domainBindingChanged"])
        finally:
            client.close()


class AsyncObservation(unittest.IsolatedAsyncioTestCase):
    async def test_exact_rows(self):
        underlying = httpx.AsyncClient(base_url="https://example.com", transport=httpx.MockTransport(handler))
        with patch("didis.client.httpx.AsyncClient", return_value=underlying):
            client = AsyncDidisClient("https://example.com")
        try:
            self.assertTrue((await client.diff_observations("did:key:test", "obs:11", "obs:12"))["domainBindingChanged"])
        finally:
            await client.close()
