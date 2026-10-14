"""Register a delegation chain (root -> team -> agent) and ask which tools the agent may call.

    python delegation_chain.py                 # uses https://did.is/api
    DIDIS_BASE_URL=... python delegation_chain.py
"""
import os

from didis import DEFAULT_BASE_URL, DidisClient

from _keys import new_principal, sign_receipt

with DidisClient(os.environ.get("DIDIS_BASE_URL", DEFAULT_BASE_URL)) as didis:
    # 1. Three throwaway identities. In production the root is your organisation's DID.
    root, team, agent = new_principal(), new_principal(), new_principal()

    # 2. root grants the team weather + refunds; the team passes only weather on to the agent.
    r1 = sign_receipt(root, team, ["weather:*", "payments:refund"])
    r2 = sign_receipt(team, agent, ["weather:*"], parent=r1)
    chain = [r1, r2]  # root first

    # 3. Verify and register once. Only a VALID chain is registered.
    v = didis.verify_delegation(chain, trusted_roots=[root.did], register=True)
    print(f"chain: {v['result']['status']} ({v['result']['headline']}), registered={v['registered']}")
    print("effective capabilities:", ", ".join(v["result"]["effectiveCapabilities"]))

    # 4. From now on, ask by agent DID only (standard rate-limit budget).
    for tool in ["weather:forecast", "weather:alerts:list", "payments:refund", "forecast"]:
        a = didis.verify_tool(agent.did, tool, root.did)
        print(f"{a['decision']:<5} {tool:<20} {a['reason']}")
