"""Fail-closed pre-execution guard for agent tools.

Before a guarded tool function runs, the guard checks:

1. Definition pin (local, no network): the tool definition the agent actually received hashes to
   the SHA-256 you approved (the same RFC 8785 JCS hash DID.is reports as ``definitionSha256``).
2. Delegation (DID.is ``verify-tool``): the configured agent DID holds a registered, VALID
   delegation whose leaf capabilities grant the tool's capability. ALLOW is cached briefly;
   DENY and errors are never cached.

Tool name vs capability: MCP tool names may only use ``A-Z a-z 0-9 _ - .`` (SEP-986), while
DID.is capabilities are namespaced with ``:`` (e.g. ``weather:forecast``). Pass both when they
differ: ``guard.check("weather_forecast", definition, capability="weather:forecast")``. Pins are
keyed by the tool name (what ``tools/list`` returns); DID.is is asked about the capability.
When ``capability`` is omitted, the tool name is used as the capability.

Any failure raises :class:`DidisGuardError` and the function is not called.
:func:`attest_mcp_pins` is an optional startup check that asks DID.is to inspect a public MCP
server; never call it per tool call (outbound, rate-limited request).
"""

from __future__ import annotations

import functools
import hashlib
import inspect
import json
import math
import re
import threading
import time
from datetime import datetime
from typing import Any, Callable, Dict, List, Mapping, Optional, TypeVar, Union

from .client import AsyncDidisClient, DidisClient

F = TypeVar("F", bound=Callable[..., Any])

_DID = re.compile(r"^did:[a-z0-9]+:\S+$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
# An exact DID.is capability: ":"-separated non-empty segments, no whitespace, no "*".
_CAPABILITY = re.compile(r"^[^\s:*]+(?::[^\s:*]+)*\Z")

GUARD_ERROR_CODES = ("TOOL_DRIFT", "TOOL_DEFINITION_MISSING", "TOOL_NOT_AUTHORIZED", "GUARD_UNAVAILABLE", "GUARD_MISCONFIGURED")


class DidisGuardError(Exception):
    """Raised when a guarded tool call must not run. ``code`` is one of ``GUARD_ERROR_CODES``."""

    def __init__(self, code: str, tool: str, message: str, detail: Optional[Dict[str, Any]] = None):
        self.code = code
        self.tool = tool
        self.detail = detail or {}
        super().__init__(f"{code}: {message}")


# --- RFC 8785 (JCS) -------------------------------------------------------------------------

def _es_number(value: Union[int, float]) -> str:
    """ECMAScript Number::toString for a finite binary64 value (RFC 8785 §3.2.2.3)."""
    f = float(value)
    if not math.isfinite(f):
        raise ValueError("JCS: non-finite numbers are not JSON")
    if f == 0:
        return "0"
    sign = "-" if f < 0 else ""
    mantissa, _, exp = repr(abs(f)).partition("e")
    int_part, _, frac_part = mantissa.partition(".")
    digits = (int_part + frac_part).lstrip("0")
    point = len(int_part.lstrip("0")) if int_part.strip("0") else -(len(frac_part) - len(frac_part.lstrip("0")))
    point += int(exp) if exp else 0
    digits = digits.rstrip("0") or "0"
    k, n = len(digits), point
    if k <= n <= 21:
        out = digits + "0" * (n - k)
    elif 0 < n <= 21:
        out = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        out = "0." + "0" * (-n) + digits
    else:
        e = n - 1
        out = digits[0] + ("." + digits[1:] if k > 1 else "") + "e" + ("+" if e >= 0 else "-") + str(abs(e))
    return sign + out


def _es_string(s: str) -> str:
    try:
        s.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError("JCS: strings must be valid Unicode") from exc
    return json.dumps(s, ensure_ascii=False)


def canonical_json(value: Any) -> str:
    """RFC 8785 canonical JSON, matching the DID.is ``rfc8785-binary64-v1`` profile."""
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, (int, float)):
        return _es_number(value)
    if isinstance(value, str):
        return _es_string(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(canonical_json(v) for v in value) + "]"
    if isinstance(value, Mapping):
        for k in value:
            if not isinstance(k, str):
                raise TypeError("JCS: object keys must be strings")
        keys = sorted(value, key=lambda k: k.encode("utf-16-be"))
        return "{" + ",".join(f"{_es_string(k)}:{canonical_json(value[k])}" for k in keys) + "}"
    raise TypeError(f"JCS: unsupported value of type {type(value).__name__}")


def tool_definition_sha256(definition: Any) -> str:
    """SHA-256 of a tool definition exactly as an MCP server returned it in ``tools/list``."""
    return hashlib.sha256(canonical_json(definition).encode("utf-8")).hexdigest()


def mcp_inventory_hash(tools: List[Mapping[str, Any]]) -> str:
    """Inventory hash of a ``tools/list`` result, identical to DID.is ``inventoryHash``."""
    pairs: List[List[str]] = []
    for t in tools:
        name = t.get("name")
        pairs.append([name if isinstance(name, str) else "", tool_definition_sha256(t)])
    pairs.sort(key=lambda p: p[0].encode("utf-8"))
    return hashlib.sha256(canonical_json(pairs).encode("utf-8")).hexdigest()


def pin_tool_definitions(tools: List[Mapping[str, Any]]) -> Dict[str, str]:
    """Builds ``{tool_name: definitionSha256}`` pins from a ``tools/list`` result you reviewed."""
    pins: Dict[str, str] = {}
    for t in tools:
        name = t.get("name")
        if not isinstance(name, str) or not name:
            raise TypeError("every tool needs a string name")
        if name in pins:
            raise TypeError(f"duplicate tool name '{name}'")
        pins[name] = tool_definition_sha256(t)
    return pins


# --- guard ----------------------------------------------------------------------------------

Definition = Any  # a definition mapping, or a zero-argument callable returning one
DecisionHook = Callable[[Dict[str, Any]], None]


class _GuardCore:
    def __init__(self, agent: str, root: Optional[str], pins: Optional[Mapping[str, str]], require_pins: bool, allow_cache_seconds: float, on_decision: Optional[DecisionHook]):
        if not isinstance(agent, str) or not _DID.match(agent):
            raise DidisGuardError("GUARD_MISCONFIGURED", "", "agent must be a DID")
        if root is not None and (not isinstance(root, str) or not _DID.match(root)):
            raise DidisGuardError("GUARD_MISCONFIGURED", "", "root must be a DID")
        if not isinstance(allow_cache_seconds, (int, float)) or not math.isfinite(allow_cache_seconds) or allow_cache_seconds < 0:
            raise DidisGuardError("GUARD_MISCONFIGURED", "", "allow_cache_seconds must be >= 0")
        self.pins = dict(pins or {})
        for name, pin in self.pins.items():
            if not isinstance(pin, str) or not _HEX64.match(pin):
                raise DidisGuardError("GUARD_MISCONFIGURED", name, "pins must be lowercase hex SHA-256")
        self.agent, self.root, self.require_pins = agent, root, require_pins
        self.allow_cache_seconds = float(allow_cache_seconds)
        self.on_decision = on_decision
        self._allowed: Dict[str, float] = {}
        self._lock = threading.Lock()

    def _report(self, tool: str, capability: str, allowed: bool, reason: str, cached: bool, code: Optional[str] = None) -> None:
        if self.on_decision is None:
            return
        try:
            self.on_decision({"tool": tool, "capability": capability, "allowed": allowed, "code": code, "reason": reason, "cached": cached})
        except Exception:  # audit hooks must not change the decision
            pass

    def fail(self, code: str, tool: str, capability: str, reason: str, detail: Optional[Dict[str, Any]] = None) -> DidisGuardError:
        self._report(tool, capability, False, reason, False, code)
        return DidisGuardError(code, tool, reason, {**(detail or {}), "capability": capability})

    def resolve_names(self, tool: Any, capability: Any) -> str:
        """Validates the tool name and returns the capability to ask DID.is about."""
        if not isinstance(tool, str) or not tool.strip() or tool != tool.strip():
            raise self.fail("GUARD_MISCONFIGURED", str(tool), str(tool if capability is None else capability), "tool must be a non-empty, trimmed name")
        cap = tool if capability is None else capability
        if not isinstance(cap, str) or not _CAPABILITY.match(cap):
            raise self.fail("GUARD_MISCONFIGURED", tool, str(cap), "capability must be exact: ':'-separated non-empty segments, no spaces, no '*'")
        return cap

    def check_definition(self, tool: str, capability: str, definition: Definition) -> None:
        pin = self.pins.get(tool)
        if pin is None:
            if self.require_pins:
                raise self.fail("TOOL_DEFINITION_MISSING", tool, capability, f"no pinned definition for '{tool}'")
            return
        try:
            current = definition() if callable(definition) else definition
        except Exception:
            raise self.fail("TOOL_DEFINITION_MISSING", tool, capability, f"could not read the current definition of '{tool}'") from None
        if current is None:
            raise self.fail("TOOL_DEFINITION_MISSING", tool, capability, f"'{tool}' is pinned but no definition was supplied")
        try:
            actual = tool_definition_sha256(current)
        except (TypeError, ValueError):
            raise self.fail("TOOL_DRIFT", tool, capability, f"the definition of '{tool}' is not valid JSON") from None
        if not isinstance(current, Mapping) or current.get("name") != tool:
            raise self.fail("TOOL_DRIFT", tool, capability, f"definition name does not match '{tool}'", {"expected": pin, "actual": actual})
        if actual != pin:
            raise self.fail("TOOL_DRIFT", tool, capability, f"definition of '{tool}' changed since it was approved", {"expected": pin, "actual": actual})

    def cached(self, tool: str, capability: str) -> bool:
        with self._lock:
            until = self._allowed.get(capability)
            if until is not None and until > time.monotonic():
                hit = True
            else:
                self._allowed.pop(capability, None)
                hit = False
        if hit:
            self._report(tool, capability, True, "cached ALLOW", True)
        return hit

    def accept(self, tool: str, capability: str, auth: Any) -> None:
        exact = isinstance(auth, Mapping) and auth.get("decision") == "ALLOW" and auth.get("authorized") is True and auth.get("agent") == self.agent and auth.get("tool") == capability
        if not exact:
            if isinstance(auth, Mapping) and (auth.get("decision") == "DENY" or auth.get("authorized") is False):
                raise self.fail("TOOL_NOT_AUTHORIZED", tool, capability, str(auth.get("reason") or "delegation does not grant this capability"), {"matchedCapability": auth.get("matchedCapability")})
            raise self.fail("GUARD_UNAVAILABLE", tool, capability, "DID.is returned an unexpected authorization answer")
        if self.root is not None and auth.get("root") != self.root:
            raise self.fail("TOOL_NOT_AUTHORIZED", tool, capability, "delegation root does not match the configured root")
        if self.allow_cache_seconds > 0:
            ttl = self.allow_cache_seconds
            expires = auth.get("expires")
            if isinstance(expires, str):
                try:
                    ttl = min(ttl, datetime.fromisoformat(expires.replace("Z", "+00:00")).timestamp() - time.time())
                except ValueError:
                    pass
            if ttl > 0:
                with self._lock:
                    self._allowed[capability] = time.monotonic() + ttl
        self._report(tool, capability, True, str(auth.get("reason", "")), False)

    def unavailable(self, tool: str, capability: str, exc: Exception) -> DidisGuardError:
        status = getattr(exc, "status", None)
        return self.fail("GUARD_UNAVAILABLE", tool, capability, "DID.is verify-tool failed" + (f" (HTTP {status})" if status else ""), {"status": status})

    def clear_cache(self) -> None:
        with self._lock:
            self._allowed.clear()


class DidisGuard:
    """Guard backed by the synchronous :class:`DidisClient`.

    ``agent`` must come from your runtime configuration, never from model output.
    """

    def __init__(self, client: DidisClient, agent: str, root: Optional[str] = None, *, pins: Optional[Mapping[str, str]] = None, require_pins: bool = False, allow_cache_seconds: float = 30.0, on_decision: Optional[DecisionHook] = None):
        if not hasattr(client, "verify_tool"):
            raise DidisGuardError("GUARD_MISCONFIGURED", "", "a DidisClient is required")
        self._client = client
        self._core = _GuardCore(agent, root, pins, require_pins, allow_cache_seconds, on_decision)

    def check(self, tool: str, definition: Definition = None, *, capability: Optional[str] = None) -> None:
        """Raises :class:`DidisGuardError` unless the call may proceed.

        ``tool`` is the name the agent sees (MCP ``tools/list`` name, pin key). ``capability`` is
        the DID.is capability it needs (e.g. ``weather:forecast``); it defaults to ``tool``.
        """
        core = self._core
        cap = core.resolve_names(tool, capability)
        core.check_definition(tool, cap, definition)
        if core.cached(tool, cap):
            return
        try:
            auth = self._client.verify_tool(core.agent, cap, core.root)
        except Exception as exc:
            raise core.unavailable(tool, cap, exc) from None
        core.accept(tool, cap, auth)

    def tool(self, tool: str, definition: Definition = None, *, capability: Optional[str] = None) -> Callable[[F], F]:
        """Decorator: the function runs only after :meth:`check` passes (sync or async functions)."""

        def decorate(func: F) -> F:
            if inspect.iscoroutinefunction(func):
                @functools.wraps(func)
                async def run_async(*args: Any, **kwargs: Any) -> Any:
                    self.check(tool, definition, capability=capability)
                    return await func(*args, **kwargs)

                return run_async  # type: ignore[return-value]

            @functools.wraps(func)
            def run(*args: Any, **kwargs: Any) -> Any:
                self.check(tool, definition, capability=capability)
                return func(*args, **kwargs)

            return run  # type: ignore[return-value]

        return decorate

    def clear_cache(self) -> None:
        self._core.clear_cache()


class AsyncDidisGuard:
    """Guard backed by :class:`AsyncDidisClient`; decorates ``async def`` functions only."""

    def __init__(self, client: AsyncDidisClient, agent: str, root: Optional[str] = None, *, pins: Optional[Mapping[str, str]] = None, require_pins: bool = False, allow_cache_seconds: float = 30.0, on_decision: Optional[DecisionHook] = None):
        if not hasattr(client, "verify_tool"):
            raise DidisGuardError("GUARD_MISCONFIGURED", "", "an AsyncDidisClient is required")
        self._client = client
        self._core = _GuardCore(agent, root, pins, require_pins, allow_cache_seconds, on_decision)

    async def check(self, tool: str, definition: Definition = None, *, capability: Optional[str] = None) -> None:
        core = self._core
        cap = core.resolve_names(tool, capability)
        if callable(definition):
            try:
                got = definition()
                definition = (await got) if inspect.isawaitable(got) else got
            except Exception:
                raise core.fail("TOOL_DEFINITION_MISSING", tool, cap, f"could not read the current definition of '{tool}'") from None
        core.check_definition(tool, cap, definition)
        if core.cached(tool, cap):
            return
        try:
            auth = await self._client.verify_tool(core.agent, cap, core.root)
        except Exception as exc:
            raise core.unavailable(tool, cap, exc) from None
        core.accept(tool, cap, auth)

    def tool(self, tool: str, definition: Definition = None, *, capability: Optional[str] = None) -> Callable[[F], F]:
        def decorate(func: F) -> F:
            if not inspect.iscoroutinefunction(func):
                raise DidisGuardError("GUARD_MISCONFIGURED", tool, "AsyncDidisGuard decorates async functions; use DidisGuard for sync functions")

            @functools.wraps(func)
            async def run(*args: Any, **kwargs: Any) -> Any:
                await self.check(tool, definition, capability=capability)
                return await func(*args, **kwargs)

            return run  # type: ignore[return-value]

        return decorate

    def clear_cache(self) -> None:
        self._core.clear_cache()


def didis_guard(client: Union[DidisClient, AsyncDidisClient], agent: str, tool: str, root: Optional[str] = None, *, pin: Optional[str] = None, definition: Definition = None, capability: Optional[str] = None, **options: Any) -> Callable[[F], F]:
    """One-line decorator: ``@didis_guard(client, agent, "github_create_issue", root, capability="github:create_issue", pin=..., definition=...)``.

    For several tools, create one :class:`DidisGuard` and use ``guard.tool(...)`` so the ALLOW
    cache is shared.
    """
    pins = {tool: pin} if pin else None
    guard: Union[DidisGuard, AsyncDidisGuard]
    if isinstance(client, AsyncDidisClient):
        guard = AsyncDidisGuard(client, agent, root, pins=pins, **options)
    else:
        guard = DidisGuard(client, agent, root, pins=pins, **options)
    return guard.tool(tool, definition, capability=capability)


def attest_mcp_pins(client: DidisClient, endpoint: str, pins: Mapping[str, str]) -> Dict[str, Any]:
    """Optional startup check against DID.is ``inspect_mcp``; ``ok`` is False unless INSPECTED and all pins match."""
    return _attestation(client.inspect_mcp(endpoint), pins)


async def attest_mcp_pins_async(client: AsyncDidisClient, endpoint: str, pins: Mapping[str, str]) -> Dict[str, Any]:
    return _attestation(await client.inspect_mcp(endpoint), pins)


def _attestation(inspection: Mapping[str, Any], pins: Mapping[str, str]) -> Dict[str, Any]:
    seen = {t.get("name"): t.get("definitionSha256") for t in inspection.get("tools", [])}
    mismatched = [{"tool": name, "expected": exp, "observed": seen.get(name)} for name, exp in pins.items() if seen.get(name) != exp]
    return {
        "ok": inspection.get("status") == "INSPECTED" and not mismatched,
        "inventoryHash": inspection.get("inventoryHash"),
        "mismatched": mismatched,
        "unpinned": [n for n in seen if n not in pins],
        "status": inspection.get("status"),
    }


__all__ = [
    "AsyncDidisGuard",
    "DidisGuard",
    "DidisGuardError",
    "GUARD_ERROR_CODES",
    "attest_mcp_pins",
    "attest_mcp_pins_async",
    "canonical_json",
    "didis_guard",
    "mcp_inventory_hash",
    "pin_tool_definitions",
    "tool_definition_sha256",
]

