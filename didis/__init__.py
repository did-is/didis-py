"""DID.is Official Python SDK."""

from . import types
from .client import (
    DEFAULT_BASE_URL,
    AsyncDidisClient,
    DidisClient,
    DidisError,
    verify_customer_monitor_signature,
    verify_webhook_signature,
)
from .guard import (
    AsyncDidisGuard,
    DidisGuard,
    DidisGuardError,
    attest_mcp_pins,
    attest_mcp_pins_async,
    canonical_json,
    didis_guard,
    mcp_inventory_hash,
    pin_tool_definitions,
    tool_definition_sha256,
)

__all__ = [
    "DEFAULT_BASE_URL",
    "DidisClient",
    "AsyncDidisClient",
    "DidisError",
    "types",
    "verify_webhook_signature",
    "verify_customer_monitor_signature",
    "DidisGuard",
    "AsyncDidisGuard",
    "DidisGuardError",
    "didis_guard",
    "attest_mcp_pins",
    "attest_mcp_pins_async",
    "canonical_json",
    "tool_definition_sha256",
    "mcp_inventory_hash",
    "pin_tool_definitions",
]
__version__ = "0.2.1"
