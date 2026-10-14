# Changelog

All notable changes to `didis-py` (import name `didis`) are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the package uses [Semantic Versioning](https://semver.org/). Before 1.0.0, a minor version (0.x.0) may add features; breaking changes are called out under **Changed** with a migration note.

## [Unreleased]

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

[Unreleased]: https://github.com/did-is/didis-py/compare/v0.2.1...HEAD
[0.2.1]: https://github.com/did-is/didis-py/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/did-is/didis-py/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/did-is/didis-py/releases/tag/v0.1.0
