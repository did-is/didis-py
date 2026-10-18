import tomllib
import unittest
from pathlib import Path
from unittest.mock import patch

import httpx

import didis
from didis.client import AsyncDidisClient, DidisClient


class UserAgentTest(unittest.TestCase):
    def test_version_matches_pyproject(self) -> None:
        meta = tomllib.loads((Path(__file__).parents[1] / "pyproject.toml").read_text())
        self.assertEqual(didis.__version__, meta["project"]["version"])

    def test_sync_and_async_send_sdk_user_agent(self) -> None:
        seen = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(request.headers["user-agent"])
            return httpx.Response(200, json={"status": "ok"})

        real = httpx.Client
        with patch("didis.client.httpx.Client", lambda **kw: real(transport=httpx.MockTransport(handler), **kw)):
            DidisClient().health()
        self.assertTrue(seen[0].startswith(f"didis-py/{didis.__version__} "))
        self.assertIsNotNone(AsyncDidisClient()._client.headers["user-agent"])
        self.assertTrue(AsyncDidisClient()._client.headers["user-agent"].startswith("didis-py/"))


if __name__ == "__main__":
    unittest.main()
