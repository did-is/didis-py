# didis-py

Official Python SDK for the [DID.is](https://did.is) public API: DID resolution with evidence, W3C DID Resolution, verifiable credentials, explicit policies, and MCP/A2A agent trust. Sync and async clients on `httpx`; Python 3.11+. Responses are plain `dict`s typed with `TypedDict` (`didis.types`), so editors and mypy know their shape.

The distribution is `didis-py`; the import name is `didis`.

## Install

```bash
pip install didis-py
```

## Usage

```python
from didis import DidisClient, AsyncDidisClient, DidisError

# Defaults to the public API at https://did.is/api; pass base_url when self-hosting.
with DidisClient() as didis:
    r = didis.resolve("did:web:identity.foundation")
    print(r["verdict"]["headline"])
    for d in r["dimensions"]:
        print(d["label"], d["state"])

    # DID Resolution v1 (W3C CR Draft HTTPS binding, unmodified)
    w3c = didis.resolve_w3c("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")

    # Live resolution stream (server-sent events)
    for event, data in didis.stream("did:web:identity.foundation"):
        if event == "stage":
            print(data["label"], data["status"])

    # Credentials: VC DM 2.0 / 1.1, Data Integrity (eddsa-jcs-2022, ecdsa-jcs-2019), VC-JOSE/VC-JWT
    credential = {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiableCredential"],
        "issuer": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
        "validFrom": "2026-01-01T00:00:00Z",
        "credentialSubject": {"id": "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLdmQR63zLFKfvUwi3"},
    }
    vc = didis.verify_credential(credential)
    print(vc["status"], vc["headline"])

    # Policies are explicit rules, never scores
    out = didis.evaluate_policy(
        "did:web:example.com",
        {"rules": {"allowedMethods": ["web", "webvh"], "domainBinding": "required"}},
    )
    print(out["evaluation"]["status"])

    # Agents
    mcp = didis.inspect_mcp("https://mcp.example.com/mcp")
    print(mcp["status"], mcp["inventoryHash"], len(mcp["tools"]))
    chain: list[str] = []  # delegation receipt JWS strings, root first
    decision = didis.authorize(chain, "payments.refund", trusted_roots=["did:web:example.com"])
    print(decision["authorization"]["decision"])

    try:
        didis.resolve("did:web:does-not-exist.invalid")
    except DidisError as e:
        print(e.status, e.problem.get("code"), e.problem.get("detail"))


async def main() -> None:
    async with AsyncDidisClient() as didis:
        diff = await didis.diff("did:web:example.com")
        print(diff)
```

Identifiers are percent-encoded exactly once (`quote(did, safe="")`). Non-2xx responses raise `DidisError` with the RFC 9457 problem body.

## Guard agent tools

A guarded tool function runs only when (1) the tool definition the agent received still matches the one you approved and (2) DID.is says the agent's registered delegation grants the tool. Every failure raises `DidisGuardError` and the function does not run (fail-closed).

```python
import os
from didis import DidisClient, DidisGuard, pin_tool_definitions

didis = DidisClient()
# Once, after reviewing the server's tools/list: store these pins in your config.
pins = pin_tool_definitions(reviewed_tools)

guard = DidisGuard(
    didis,
    agent=os.environ["AGENT_DID"],  # from configuration, never from model output
    root=os.environ["ROOT_DID"],    # require this delegation root
    pins=pins,
    require_pins=True,
)

@guard.tool("github:create_issue", definition=lambda: current_tools["github:create_issue"])
def create_issue(title: str, body: str) -> dict:
    return github.create_issue(title, body)
```

- The definition check is local (RFC 8785 JCS + SHA-256, the same `definitionSha256` DID.is reports) and makes no network call.
- The delegation check calls `verify_tool`. An ALLOW is reused for 30 s by default (`allow_cache_seconds`), never past the delegation expiry; DENY and errors are never cached.
- Error codes: `TOOL_DRIFT`, `TOOL_DEFINITION_MISSING`, `TOOL_NOT_AUTHORIZED`, `GUARD_UNAVAILABLE`, `GUARD_MISCONFIGURED`.
- One tool only: `@didis_guard(client, agent, "github:create_issue", root, pin=..., definition=...)`. With `AsyncDidisClient` use `AsyncDidisGuard` (or `didis_guard`, which picks it automatically) on `async def` functions.
- `attest_mcp_pins(client, endpoint, pins)` asks DID.is to inspect a public MCP server and compares its hashes with your pins. Run it at startup or deploy time, not per call: it is an outbound, rate-limited request, and servers that need login or run on a private network cannot be inspected.

## Webhooks

Console project monitor events use `verify_customer_monitor_signature`:

```python
from didis import verify_customer_monitor_signature

ok = verify_customer_monitor_signature(
    secret,
    raw_body,
    request.headers["X-DIDIS-Signature"],
    tenant_id=tenant_id,
    project_id=project_id,
    event_id=request.headers["X-DIDIS-Event-ID"],
)
```

For self-hosted admin daemon monitoring deliveries, use `verify_webhook_signature`:

```python
from didis import verify_webhook_signature

ok = verify_webhook_signature(
    secret,
    request.headers["x-didis-timestamp"],
    raw_body,
    request.headers["x-didis-signature-256"],
)
```

Public API reference: <https://did.is/developers>. Monitoring routes need `admin_token=` and are only available on self-hosted deployments; they are not exposed by the public API.

## License

MIT
