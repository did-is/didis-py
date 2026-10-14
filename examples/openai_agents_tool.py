"""Guard OpenAI Agents SDK tools: the tool body runs only if DID.is says the agent was delegated the capability.

    python openai_agents_tool.py

No OpenAI API key is needed: the example invokes the tools the same way the Runner does
(``on_invoke_tool`` with the model's JSON arguments). Pass ``tools`` to ``Agent(tools=...)`` as usual.

OpenAI function names allow only letters, digits, "_" and "-", so each tool maps to a DID.is
capability: weather_forecast -> weather:forecast.
"""

import asyncio
import functools
import json
import os
from typing import Any, Awaitable, Callable

from agents import Agent, FunctionTool, function_tool
from agents.tool_context import ToolContext

from didis import AsyncDidisClient, AsyncDidisGuard, DidisGuardError
from _keys import new_principal, sign_receipt


def guarded(guard: AsyncDidisGuard, *, capability: str) -> Callable[[Callable[..., Awaitable[Any]]], Callable[..., Awaitable[Any]]]:
    """Decorator for an ``async def`` tool: the body runs only after the guard passes.

    The tool name is the function name (what the model sees). When the guard blocks, the model gets
    a short refusal instead of a result, so it can tell the user rather than retry.
    """

    def decorate(fn: Callable[..., Awaitable[Any]]) -> Callable[..., Awaitable[Any]]:
        @functools.wraps(fn)  # keeps the signature and docstring, so function_tool sees the real parameters
        async def run(*args: Any, **kwargs: Any) -> Any:
            try:
                await guard.check(fn.__name__, capability=capability)
            except DidisGuardError as e:
                return f"Blocked by policy ({e.code}). Do not retry this tool."
            return await fn(*args, **kwargs)

        return run

    return decorate


async def main() -> None:
    async with AsyncDidisClient(base_url=os.environ.get("DIDIS_BASE_URL", "https://did.is/api")) as didis:
        # --- Setup, done once outside the agent ---------------------------------------------------
        root, agent = new_principal(), new_principal()
        # The agent may use weather:* only. Demo keys; real deployments use their own key management.
        await didis.verify_delegation([sign_receipt(root, agent, ["weather:*"])], trusted_roots=[root.did], register=True)

        guard = AsyncDidisGuard(
            didis,
            agent.did,  # from configuration, never from model output
            root.did,
            on_decision=lambda d: print(f"  audit: {'ALLOW' if d['allowed'] else 'BLOCK'} {d['tool']} ({d['capability']}) {d['code'] or ''}"),
        )

        @function_tool
        @guarded(guard, capability="weather:forecast")
        async def weather_forecast(city: str) -> str:
            """Forecast for a city."""
            return f"Sunny in {city}"

        @function_tool
        @guarded(guard, capability="payments:refund")
        async def payments_refund(order: str) -> str:
            """Refund an order."""
            return f"Refunded {order}"

        tools = [weather_forecast, payments_refund]
        Agent(name="Assistant", instructions="Help with weather and orders.", tools=tools)

        # --- What the Runner does when the model picks a tool -------------------------------------
        async def invoke(t: FunctionTool, args: dict) -> Any:
            raw = json.dumps(args)
            ctx = ToolContext(context=None, tool_name=t.name, tool_call_id="call_demo", tool_arguments=raw)
            return await t.on_invoke_tool(ctx, raw)

        print(f"1. weather_forecast -> {await invoke(weather_forecast, {'city': 'Reykjavik'})}")
        print(f"2. payments_refund  -> {await invoke(payments_refund, {'order': 'A-1001'})}")


if __name__ == "__main__":
    asyncio.run(main())
