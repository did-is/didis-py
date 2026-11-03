# Changelog

All notable changes to `didis-py` (import name `didis`) are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and release numbering follows the project’s pre-1.0 policy. A third-component increment can contain breaking changes; read **Changed** and migration notes before upgrading. 0.2.6 is not a backward-compatible patch.

## [Unreleased]

## [0.2.6] - 2026-11-03

### Fixed

- `DidisGuard` / `AsyncDidisGuard` / `didis_guard`: reject an ALLOW whose parseable `expires` is at or before execution time with the existing `TOOL_NOT_AUTHORIZED` code, including first use and disabled caching. Re-read pinned definitions after authorization and recheck each call's immutable deadline after async work and immediately before handler invocation; concurrent refreshes cannot extend another call's approval. Cached ALLOW is still bounded by both configured TTL and delegation expiry; failed/DENY/expired refreshes never fall back to stale approval (`GUARD_UNAVAILABLE` for transport/unexpected-answer errors). Missing/unparseable expiry remains optional and keeps the existing TTL-only behavior. Pin providers may now run twice per check. This is a pre-execution boundary, not per-stream reauthorization, resource binding, replay prevention, or an atomic remote side-effect guarantee.

### Changed

- **Breaking in 0.2.6:** execution guards require a nonempty, trimmed application-owned trusted root DID. Missing/null/empty/whitespace roots raise `GUARD_MISCONFIGURED` at construction, before network or handler work. Migrate every guard and one-line wrapper by passing the root from trusted application configuration, not from a submitted chain, authorization response, or model output. Rootless advisory verification APIs remain available; signature-valid does not mean application-authorized. 0.2.5 accepts rootless guards; 0.2.6 rejects them. TypeScript requires `root` statically; Python retains its Optional annotation but enforces it at runtime.

- Correct delegation response fields to required nullable wire values; correct fast-verification explicit null fields. Include optional key material metadata and type graph fact pairs as JSON arrays. Wire-type corrections only; these corrections do not alter HTTP routing.

### Added

- Add optional tools-only inventory completeness/evidence (missing means unknown); scoped requested-pin attestation preserves partial-result pin checks and rejects duplicate ambiguity. Missing completeness remains unknown, not complete.

- sync/async `diff_observations()` selects exact public history observations, including domain-only changes with identical document hashes. Semantic diff adds optional `fromObservation`/`toObservation` references. Legacy hash selectors remain available but ambiguous hashes return `INVALID_REQUEST` instead of silently selecting a different state. No change to private usage/billing routes.

## [0.2.5] - 2026-10-19

### Added

- Optional project API key: `DidisClient(api_key=...)` / `AsyncDidisClient(api_key=...)`. With a key, MCP inspection, A2A inspection, tool-call authorization and delegation-chain checks use the paid `/v1/customer/*` routes and count against your team's monthly allowance instead of the anonymous per-IP limit. Results are identical to the public routes. Each call sends one fresh `Idempotency-Key`; automatic `429`/`503` retries reuse it, so a request is never billed twice. The key is never sent to public routes, and `register: true` delegation checks always use the public route. Without a key nothing changes.
- `usage()` returns this month's team allowance (`CustomerUsage`: used, reserved, limit and remaining per pool). Requires the API key.

## [0.2.4] - 2026-10-19

### Added

- Automatic wait-and-retry for `429` (request budget used up) and `503` (temporarily overloaded) responses that carry `Retry-After`, in `DidisClient` and `AsyncDidisClient`. By default the client retries up to 2 times and never waits longer than 10 seconds per attempt; a short random delay is added so clients refused together do not return together. Both statuses are refused before the request is processed, so retrying is safe for every call. Tune with `DidisClient(retry={"max_retries": 3, "max_wait": 5})` or turn off with `retry=False`. When retries run out, `DidisError` is raised as before, with `problem["retryAfter"]`.

## [0.2.3] - 2026-10-18

### Added

- Requests now carry `user-agent: didis-py/<version> python-httpx/<version>`. Only package names and versions are sent, so DID.is can count SDK use separately from other HTTP clients.

- Type `LinkedAccountEvidence` and `Evidence.linkedAccounts`: each `alsoKnownAs` value with whether that website links back to the DID (`CONFIRMED`, `NOT_CONFIRMED`, `FAILED`, `UNSUPPORTED`, `UNREACHABLE`, `NOT_CHECKABLE`). A confirmation proves the same party controls the website origin and the DID; it does not prove who that party is.

- Policy rule `linkedAccounts` in `PolicyRules`: 1–4 https origins (for example `["https://shop.example"]`) that must be listed in the DID's `alsoKnownAs` and confirm the DID back. Use it to require "this DID belongs to our official website" in one policy call.

## [0.2.2] - 2026-10-18

### Added

- `verify_credential(..., required_claims=[{"path": "/age_over_18", "equals": True}])`: check conditions without receiving claim values. The response key `requirements` reports `met` and a per-path result; conditions are evaluated only for a `VALID` credential. New types `ClaimRequirement`, `RequirementResult`, `RequirementsOutcome`.

## [0.2.1] - 2026-10-14

### Added

- Guard keyword argument `capability` (on `check`, `tool` and `@didis_guard`): the DID.is capability a tool needs when it differs from the tool name. MCP and OpenAI tool names cannot contain `:`, so use `guard.check("weather_forecast", definition, capability="weather:forecast")`. Pins stay keyed by the tool name; DID.is is asked about the capability; the ALLOW cache is keyed by capability. Without `capability`, behaviour is unchanged (the tool name is the capability).
- `on_decision` events and `DidisGuardError.detail` now include `capability`.
- Examples for the Python `mcp` SDK (`mcp_client.py`), LangChain (`langchain_tool.py`) and the OpenAI Agents SDK (`openai_agents_tool.py`).

### Changed

- A capability containing `*`, empty segments or whitespace is refused with `GUARD_MISCONFIGURED` before any network call. Wildcards belong in delegations, not in tool calls.

### Fixed

- `AsyncDidisGuard`: an exception raised while reading a definition callable now raises `TOOL_DEFINITION_MISSING` (the sync guard already did); before, the original exception escaped.

## [0.2.0] - 2026-10-13

### Added

- Fail-closed tool guard: `DidisGuard`, `AsyncDidisGuard`, the `@didis_guard` decorator and `DidisGuardError`. A guarded function runs only when the tool definition still matches its pin and DID.is `verify_tool` answers `ALLOW` for the configured agent (and root, if set). Drift, `DENY`, network errors, `429` and unexpected answers all raise, and the function does not run. See [Guard agent tools](https://docs.did.is/build/guard-tools/).
- Tool definition pinning: `canonical_json` (RFC 8785 JCS), `tool_definition_sha256`, `mcp_inventory_hash` and `pin_tool_definitions`. Hashes are identical to the `definitionSha256` and `inventoryHash` values DID.is reports.
- `attest_mcp_pins` and `attest_mcp_pins_async` compare a public MCP server, as observed by DID.is, with your pins.
- `verify_credential` keyword arguments `expected_nonce` and `trusted_issuer_certificates` (SD-JWT VC key binding and caller-chosen X.509 anchors), on both clients.
- `TypedDict`s `IssuerTrust` and `SdJwtEvidence`, and the optional `issuerTrust` and `sdJwt` keys on `CredentialVerification`.

## [0.1.0] - 2026-10-05

### Added

- First public release as `didis-py`. Python 3.11+, `httpx`, typed (`py.typed`).
- Sync `DidisClient` and async `AsyncDidisClient` for the DID.is public API (default base URL `https://did.is/api`): `health`, `resolve`, `resolve_w3c`, `dereference`, `stream` (server-sent events), `history`, `diff`, `graph`, `verify_credential`, `evaluate_policy`, `inspect_mcp`, `inspect_a2a`, `verify_delegation`, `authorize`, `verify_tool`, `fast_verify_did` and `fast_verify_jws`.
- Self-hosted monitoring methods that need an admin token: `watch`, `watches`, `unwatch` and `events`.
- `DidisError` carrying the RFC 9457 problem body and `retryAfter`.
- Response shapes as `TypedDict`s in `didis.types`.
- Webhook helpers `verify_webhook_signature` and `verify_customer_monitor_signature`.

[Unreleased]: https://github.com/did-is/didis-py/compare/v0.2.6...HEAD
[0.2.6]: https://github.com/did-is/didis-py/compare/v0.2.5...v0.2.6
[0.2.5]: https://github.com/did-is/didis-py/compare/v0.2.4...v0.2.5
[0.2.4]: https://github.com/did-is/didis-py/compare/v0.2.3...v0.2.4
[0.2.3]: https://github.com/did-is/didis-py/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/did-is/didis-py/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/did-is/didis-py/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/did-is/didis-py/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/did-is/didis-py/releases/tag/v0.1.0
