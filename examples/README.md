# didis-py examples

Each example runs in a minute against the public API at `https://did.is/api`. No account or API key is needed.

```bash
cd examples
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python delegation_chain.py          # register a delegation chain, then ask which tools an agent may call
python guard_tool.py                # guard tool functions: allowed, not delegated, and definition drift
python webhook_receiver.py --self-test  # verify signed monitoring webhooks (self-test, no network)
python mcp_client.py                # guard every MCP tool call (Python mcp SDK 2.x, in-process server)
python langchain_tool.py            # guard LangChain tools (no LLM or API key needed)
python openai_agents_tool.py        # guard OpenAI Agents SDK tools (no OpenAI key needed)
```

Python 3.11 or later (`mcp` 2.x needs 3.10+). `cryptography`, `mcp`, `langchain-core` and `openai-agents` are used only by the examples; the SDK itself depends only on `httpx`.
Set `DIDIS_BASE_URL` to use your own deployment.

| File | Shows |
| --- | --- |
| [`delegation_chain.py`](delegation_chain.py) | Build a root → team → agent chain, `verify_delegation(..., register=True)`, then `verify_tool`. Capabilities are namespace-scoped: `weather:*` grants `weather:forecast`, not `forecast` or `payments:refund`. |
| [`guard_tool.py`](guard_tool.py) | `pin_tool_definitions` + `DidisGuard`. The refund tool is blocked (`TOOL_NOT_AUTHORIZED`); the forecast tool is blocked after its description changes (`TOOL_DRIFT`). |
| [`mcp_client.py`](mcp_client.py) | One `call_tool` function for every MCP call: maps the MCP tool name to a capability (`weather_forecast` → `weather:forecast`), checks the definition the server serves *now* against the pin, then asks DID.is. Shows allowed, not delegated, and a server that changes a description. |
| [`langchain_tool.py`](langchain_tool.py) | `guarded_tool(...)` builds a LangChain `StructuredTool`. A blocked call returns a short refusal to the model instead of running. |
| [`openai_agents_tool.py`](openai_agents_tool.py) | A `@guarded(...)` decorator under `@function_tool` for the OpenAI Agents SDK. |
| [`webhook_receiver.py`](webhook_receiver.py) | `verify_customer_monitor_signature` on the raw body, duplicate handling, and `401` for forged or altered requests. |
| [`_keys.py`](_keys.py) | Demo-only throwaway `did:key` identities and signed delegation receipts. |

**Why a separate capability?** MCP and OpenAI tool names may only contain letters, digits, `_`, `-` and `.`, so they cannot be `weather:forecast`. DID.is capabilities use `:` namespaces so that `weather:*` can grant a whole group. Give the guard both: `guard.check("weather_forecast", definition, capability="weather:forecast")`. Pins use the tool name; DID.is is asked about the capability.

The demo keys exist only in memory. Registered demo chains expire after an hour.

Docs: [Guard agent tools](https://docs.did.is/build/guard-tools/) · [Agent trust APIs](https://docs.did.is/build/agents/) · [Webhook signatures](https://docs.did.is/build/webhooks/)
