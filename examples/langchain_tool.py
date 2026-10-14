"""Guard LangChain tools: the tool body runs only if DID.is says the agent was delegated the capability.

    python langchain_tool.py

No LLM or API key is needed: the example calls the tools the same way an agent loop would
(``tool.invoke`` with the model's arguments). Put ``tools`` into ``create_agent`` / ``bind_tools`` as usual.

LangChain tool names become function names for the model and cannot contain ":", so each tool
maps to a DID.is capability: weather_forecast -> weather:forecast.
"""

import os
from typing import Any, Callable

from langchain_core.tools import BaseTool, StructuredTool

from didis import DidisClient, DidisGuard, DidisGuardError
from _keys import new_principal, sign_receipt

# --- Setup, done once outside the agent -----------------------------------------------------------
didis = DidisClient(base_url=os.environ.get("DIDIS_BASE_URL", "https://did.is/api"))
root, agent = new_principal(), new_principal()
# The agent may use weather:* only. Demo keys; real deployments use their own key management.
didis.verify_delegation([sign_receipt(root, agent, ["weather:*"])], trusted_roots=[root.did], register=True)

guard = DidisGuard(
    didis,
    agent.did,  # from configuration, never from model output
    root.did,
    on_decision=lambda d: print(f"  audit: {'ALLOW' if d['allowed'] else 'BLOCK'} {d['tool']} ({d['capability']}) {d['code'] or ''}"),
)


def guarded_tool(fn: Callable[..., Any], *, name: str, capability: str) -> BaseTool:
    """A LangChain tool whose body runs only after the guard passes.

    When the guard blocks, the model gets a short refusal instead of a result, so it can tell the
    user rather than retry. Other errors are raised as usual.
    """

    def run(**kwargs: Any) -> Any:
        try:
            guard.check(name, capability=capability)
        except DidisGuardError as e:
            return f"Blocked by policy ({e.code}). Do not retry this tool."
        return fn(**kwargs)

    # The argument schema and description come from fn's signature and docstring, so the model sees
    # the real parameters.
    plain = StructuredTool.from_function(fn)
    return StructuredTool.from_function(func=run, name=name, description=plain.description, args_schema=plain.args_schema)


def forecast(city: str) -> str:
    """Forecast for a city."""
    return f"Sunny in {city}"


def refund(order: str) -> str:
    """Refund an order."""
    return f"Refunded {order}"


tools = [
    guarded_tool(forecast, name="weather_forecast", capability="weather:forecast"),
    guarded_tool(refund, name="payments_refund", capability="payments:refund"),
]

# --- What the agent loop does when the model picks a tool -----------------------------------------
if __name__ == "__main__":
    print(f"1. weather_forecast -> {tools[0].invoke({'city': 'Reykjavik'})}")
    print(f"2. payments_refund  -> {tools[1].invoke({'order': 'A-1001'})}")
    didis.close()
