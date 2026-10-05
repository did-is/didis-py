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

## Webhooks

Monitoring routes need `admin_token=` and belong on servers only. Verify deliveries with:

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
