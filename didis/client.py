"""DID.is client SDK for Python (sync and async, httpx).

Identifiers are percent-encoded exactly once; the resolver decodes them exactly once.
Errors raise ``DidisError`` carrying the RFC 9457 problem object returned by the API.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from typing import Any, AsyncIterator, Dict, Iterator, List, Optional, Tuple, cast
from urllib.parse import quote

import httpx

from .types import (
    A2aInspection,
    AuthorizationResponse,
    DelegationVerification,
    DereferencingResult,
    EnrichedResolution,
    FastVerifyDidResult,
    FastVerifyJwsResult,
    GraphResponse,
    HealthStatus,
    HistoryResponse,
    McpInspection,
    Policy,
    PolicyResponse,
    ResolutionResult,
    SemanticDiff,
    ToolAuthorization,
    CredentialVerification,
)

DEFAULT_BASE_URL = "https://did.is/api"
"""Public DID.is API. Pass your own ``base_url`` when self-hosting."""

JSON = Dict[str, Any]


def _enc(value: str) -> str:
    return quote(value.strip(), safe="")


class DidisError(Exception):
    """Raised for non-2xx responses; ``problem`` is the RFC 9457 body."""

    def __init__(self, status: int, problem: JSON):
        self.status = status
        self.problem = problem
        super().__init__(f"{problem.get('title', 'HTTP ' + str(status))}: {problem.get('detail', '')}")


def _raise_for_problem(resp: httpx.Response) -> JSON:
    if resp.is_success:
        return resp.json() if resp.content else {}
    try:
        body = resp.json()
    except ValueError:
        body = {"title": f"HTTP {resp.status_code}", "detail": resp.text}
    problem = body if isinstance(body, dict) else {"detail": str(body)}
    retry_after = resp.headers.get("retry-after")
    if retry_after is not None:
        problem["retryAfter"] = retry_after
    raise DidisError(resp.status_code, problem)


class _SseParser:
    """Incremental text/event-stream parser yielding (event, json-or-text) per dispatched event."""

    def __init__(self) -> None:
        self.event = "message"
        self.data: List[str] = []

    def feed(self, line: str) -> Optional[Tuple[str, Any]]:
        if line == "":
            out: Optional[Tuple[str, Any]] = None
            if self.data:
                raw = "\n".join(self.data)
                try:
                    out = (self.event, json.loads(raw))
                except ValueError:
                    out = (self.event, raw)
            self.event, self.data = "message", []
            return out
        if line.startswith("event:"):
            self.event = line[6:].strip()
        elif line.startswith("data:"):
            value = line[5:]
            self.data.append(value[1:] if value.startswith(" ") else value)
        return None


def verify_webhook_signature(secret: str, timestamp: str, body: bytes, signature_header: str, tolerance_seconds: int = 300) -> bool:
    """Verifies ``X-Didis-Signature-256 = sha256=HMAC(secret, timestamp + "." + body)``."""
    try:
        ts = int(timestamp)
    except ValueError:
        return False
    if abs(time.time() - ts) > tolerance_seconds:
        return False
    mac = hmac.new(secret.encode(), timestamp.encode() + b"." + body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(f"sha256={mac}", signature_header)


def verify_customer_monitor_signature(secret: str, body: bytes, signature: str, *, tenant_id: str, project_id: str, event_id: str, max_age_seconds: int = 30 * 86400) -> bool:
    """Verify the durable CUSTOMER event format; receivers MUST durably deduplicate event IDs.

    This creation timestamp is immutable on retry, unlike the existing admin format.
    A valid signature does not establish DID authority or a paid entitlement.
    """
    import re
    match = re.fullmatch(r"t=(0|[1-9][0-9]{0,15}),v1=([0-9a-f]{64})", signature)
    if not match or not secret or len(body) > 300 * 1024 or type(max_age_seconds) is not int or not 1 <= max_age_seconds <= 30 * 86400:
        return False
    timestamp = int(match[1])
    now = time.time()
    if timestamp > 2**53 - 1 or timestamp > now + 60 or now - timestamp >= max_age_seconds:
        return False
    mac = hmac.new(secret.encode(), match[1].encode() + b"." + body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(mac, match[2]):
        return False
    try:
        event = json.loads(body)
        return (isinstance(event, dict) and event.get("specVersion") == "didis.customer-monitor.v1"
                and type(event.get("createdAt")) is int and event["createdAt"] == timestamp
                and re.fullmatch(r"cevent_[0-9a-f]{64}", event_id) is not None and event.get("id") == event_id
                and re.fullmatch(r"tenant_[0-9a-f]{64}", tenant_id) is not None and event.get("tenantId") == tenant_id
                and re.fullmatch(r"project_[0-9a-f]{64}", project_id) is not None and event.get("projectId") == project_id)
    except (ValueError, UnicodeError):
        return False


class DidisClient:
    """Synchronous client."""

    def __init__(self, base_url: str = DEFAULT_BASE_URL, admin_token: Optional[str] = None, timeout: float = 30.0):
        self.base_url = base_url.rstrip("/")
        self._admin_token = admin_token
        self._client = httpx.Client(base_url=self.base_url, timeout=timeout, headers={"accept": "application/json"})

    def _admin(self) -> Dict[str, str]:
        if not self._admin_token:
            raise ValueError("admin_token is required for monitoring routes")
        return {"authorization": f"Bearer {self._admin_token}"}

    def health(self) -> HealthStatus:
        return cast(HealthStatus, _raise_for_problem(self._client.get("/health")))

    def resolve(self, did: str, no_cache: bool = False) -> EnrichedResolution:
        params = {"noCache": "true"} if no_cache else None
        return cast(EnrichedResolution, _raise_for_problem(self._client.get(f"/v1/resolve/{_enc(did)}", params=params)))

    def resolve_w3c(self, did: str) -> ResolutionResult:
        return cast(ResolutionResult, _raise_for_problem(self._client.get(f"/1.0/identifiers/{_enc(did)}", headers={"accept": "application/did-resolution"})))

    def dereference(self, did_url: str) -> DereferencingResult:
        return cast(DereferencingResult, _raise_for_problem(self._client.get(f"/v1/dereference/{_enc(did_url)}")))

    def stream(self, did: str, no_cache: bool = True) -> Iterator[Tuple[str, Any]]:
        params = {"noCache": "true"} if no_cache else None
        with self._client.stream("GET", f"/v1/stream/{_enc(did)}", params=params, headers={"accept": "text/event-stream"}) as resp:
            if not resp.is_success:
                resp.read()
                _raise_for_problem(resp)
            parser = _SseParser()
            for line in resp.iter_lines():
                item = parser.feed(line)
                if item is not None:
                    yield item
                    if item[0] == "done":
                        return

    def history(self, did: str) -> HistoryResponse:
        return cast(HistoryResponse, _raise_for_problem(self._client.get(f"/v1/history/{_enc(did)}")))

    def diff(self, did: str, from_hash: Optional[str] = None, to_hash: Optional[str] = None) -> SemanticDiff:
        params = {"from": from_hash, "to": to_hash} if from_hash and to_hash else None
        return cast(SemanticDiff, _raise_for_problem(self._client.get(f"/v1/diff/{_enc(did)}", params=params)))

    def graph(self, did: str) -> GraphResponse:
        return cast(GraphResponse, _raise_for_problem(self._client.get(f"/v1/graph/{_enc(did)}")))

    def verify_credential(self, credential: Any, *, expected_audience: Optional[str] = None) -> CredentialVerification:
        """Check JWT audience only when a recipient is supplied; raw JSON strings preserve member identity."""
        body: JSON = {"credential": credential}
        if expected_audience is not None:
            body["expectedAudience"] = expected_audience
        return cast(CredentialVerification, _raise_for_problem(self._client.post("/v1/credentials/verify", json=body)))

    def evaluate_policy(self, did: str, policy: Policy, credential: Any = None) -> PolicyResponse:
        body: JSON = {"did": did, "policy": dict(policy)}
        if credential is not None:
            body["credential"] = credential
        return cast(PolicyResponse, _raise_for_problem(self._client.post("/v1/policies/evaluate", json=body)))

    def inspect_mcp(self, endpoint: str) -> McpInspection:
        return cast(McpInspection, _raise_for_problem(self._client.get("/v1/mcp/inspect", params={"endpoint": endpoint})))

    def inspect_a2a(self, url: str) -> A2aInspection:
        return cast(A2aInspection, _raise_for_problem(self._client.get("/v1/a2a/inspect", params={"url": url})))

    def verify_delegation(self, chain: List[str], trusted_roots: Optional[List[str]] = None, register: bool = False) -> DelegationVerification:
        return cast(DelegationVerification, _raise_for_problem(self._client.post("/v1/agents/verify-delegation", json={"chain": chain, "trustedRoots": trusted_roots, "register": register})))

    def authorize(self, chain: List[str], tool: str, trusted_roots: Optional[List[str]] = None) -> AuthorizationResponse:
        return cast(AuthorizationResponse, _raise_for_problem(self._client.post("/v1/agents/authorize", json={"chain": chain, "tool": tool, "trustedRoots": trusted_roots})))

    def verify_tool(self, agent: str, tool: str, root: Optional[str] = None) -> ToolAuthorization:
        params = {"agent": agent, "tool": tool, **({"root": root} if root else {})}
        return cast(ToolAuthorization, _raise_for_problem(self._client.get("/v1/agents/verify-tool", params=params)))

    def fast_verify_did(self, did: str) -> FastVerifyDidResult:
        return cast(FastVerifyDidResult, _raise_for_problem(self._client.get(f"/v1/fast-verify/did/{_enc(did)}")))

    def fast_verify_jws(self, jws: str, relationship: Optional[str] = None) -> FastVerifyJwsResult:
        return cast(FastVerifyJwsResult, _raise_for_problem(self._client.post("/v1/fast-verify/jws", json={"jws": jws, "relationship": relationship})))

    # Monitoring (admin token required)
    def watch(self, did: str, webhook_url: str, interval_seconds: Optional[int] = None) -> JSON:
        return _raise_for_problem(self._client.post("/v1/monitoring/watches", json={"did": did, "webhookUrl": webhook_url, "intervalSeconds": interval_seconds}, headers=self._admin()))

    def watches(self) -> JSON:
        return _raise_for_problem(self._client.get("/v1/monitoring/watches", headers=self._admin()))

    def unwatch(self, watch_id: str) -> None:
        _raise_for_problem(self._client.delete(f"/v1/monitoring/watches/{_enc(watch_id)}", headers=self._admin()))

    def events(self, watch_id: Optional[str] = None) -> JSON:
        params = {"watchId": watch_id} if watch_id else None
        return _raise_for_problem(self._client.get("/v1/monitoring/events", params=params, headers=self._admin()))

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "DidisClient":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


class AsyncDidisClient:
    """Asynchronous client (same surface as ``DidisClient``)."""

    def __init__(self, base_url: str = DEFAULT_BASE_URL, admin_token: Optional[str] = None, timeout: float = 30.0):
        self.base_url = base_url.rstrip("/")
        self._admin_token = admin_token
        self._client = httpx.AsyncClient(base_url=self.base_url, timeout=timeout, headers={"accept": "application/json"})

    def _admin(self) -> Dict[str, str]:
        if not self._admin_token:
            raise ValueError("admin_token is required for monitoring routes")
        return {"authorization": f"Bearer {self._admin_token}"}

    async def health(self) -> HealthStatus:
        return cast(HealthStatus, _raise_for_problem(await self._client.get("/health")))

    async def resolve(self, did: str, no_cache: bool = False) -> EnrichedResolution:
        params = {"noCache": "true"} if no_cache else None
        return cast(EnrichedResolution, _raise_for_problem(await self._client.get(f"/v1/resolve/{_enc(did)}", params=params)))

    async def resolve_w3c(self, did: str) -> ResolutionResult:
        return cast(ResolutionResult, _raise_for_problem(await self._client.get(f"/1.0/identifiers/{_enc(did)}", headers={"accept": "application/did-resolution"})))

    async def dereference(self, did_url: str) -> DereferencingResult:
        return cast(DereferencingResult, _raise_for_problem(await self._client.get(f"/v1/dereference/{_enc(did_url)}")))

    async def stream(self, did: str, no_cache: bool = True) -> AsyncIterator[Tuple[str, Any]]:
        params = {"noCache": "true"} if no_cache else None
        async with self._client.stream("GET", f"/v1/stream/{_enc(did)}", params=params, headers={"accept": "text/event-stream"}) as resp:
            if not resp.is_success:
                await resp.aread()
                _raise_for_problem(resp)
            parser = _SseParser()
            async for line in resp.aiter_lines():
                item = parser.feed(line)
                if item is not None:
                    yield item
                    if item[0] == "done":
                        return

    async def history(self, did: str) -> HistoryResponse:
        return cast(HistoryResponse, _raise_for_problem(await self._client.get(f"/v1/history/{_enc(did)}")))

    async def diff(self, did: str, from_hash: Optional[str] = None, to_hash: Optional[str] = None) -> SemanticDiff:
        params = {"from": from_hash, "to": to_hash} if from_hash and to_hash else None
        return cast(SemanticDiff, _raise_for_problem(await self._client.get(f"/v1/diff/{_enc(did)}", params=params)))

    async def graph(self, did: str) -> GraphResponse:
        return cast(GraphResponse, _raise_for_problem(await self._client.get(f"/v1/graph/{_enc(did)}")))

    async def verify_credential(self, credential: Any, *, expected_audience: Optional[str] = None) -> CredentialVerification:
        """Check JWT audience only when a recipient is supplied; raw JSON strings preserve member identity."""
        body: JSON = {"credential": credential}
        if expected_audience is not None:
            body["expectedAudience"] = expected_audience
        return cast(CredentialVerification, _raise_for_problem(await self._client.post("/v1/credentials/verify", json=body)))

    async def evaluate_policy(self, did: str, policy: Policy, credential: Any = None) -> PolicyResponse:
        body: JSON = {"did": did, "policy": dict(policy)}
        if credential is not None:
            body["credential"] = credential
        return cast(PolicyResponse, _raise_for_problem(await self._client.post("/v1/policies/evaluate", json=body)))

    async def inspect_mcp(self, endpoint: str) -> McpInspection:
        return cast(McpInspection, _raise_for_problem(await self._client.get("/v1/mcp/inspect", params={"endpoint": endpoint})))

    async def inspect_a2a(self, url: str) -> A2aInspection:
        return cast(A2aInspection, _raise_for_problem(await self._client.get("/v1/a2a/inspect", params={"url": url})))

    async def verify_delegation(self, chain: List[str], trusted_roots: Optional[List[str]] = None, register: bool = False) -> DelegationVerification:
        return cast(DelegationVerification, _raise_for_problem(await self._client.post("/v1/agents/verify-delegation", json={"chain": chain, "trustedRoots": trusted_roots, "register": register})))

    async def authorize(self, chain: List[str], tool: str, trusted_roots: Optional[List[str]] = None) -> AuthorizationResponse:
        return cast(AuthorizationResponse, _raise_for_problem(await self._client.post("/v1/agents/authorize", json={"chain": chain, "tool": tool, "trustedRoots": trusted_roots})))

    async def verify_tool(self, agent: str, tool: str, root: Optional[str] = None) -> ToolAuthorization:
        params = {"agent": agent, "tool": tool, **({"root": root} if root else {})}
        return cast(ToolAuthorization, _raise_for_problem(await self._client.get("/v1/agents/verify-tool", params=params)))

    async def fast_verify_did(self, did: str) -> FastVerifyDidResult:
        return cast(FastVerifyDidResult, _raise_for_problem(await self._client.get(f"/v1/fast-verify/did/{_enc(did)}")))

    async def fast_verify_jws(self, jws: str, relationship: Optional[str] = None) -> FastVerifyJwsResult:
        return cast(FastVerifyJwsResult, _raise_for_problem(await self._client.post("/v1/fast-verify/jws", json={"jws": jws, "relationship": relationship})))

    async def close(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> "AsyncDidisClient":
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()
