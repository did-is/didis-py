"""Demo-only helpers: throwaway did:key principals and signed delegation receipts.

Real deployments keep the root key offline and issue receipts from their own key management.
"""
from __future__ import annotations

import base64
import hashlib
import json
import time
import uuid
from dataclasses import dataclass
from typing import List, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _base58btc(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = _B58[r] + out
    return "1" * (len(data) - len(data.lstrip(b"\0"))) + out


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


@dataclass
class Principal:
    did: str
    kid: str
    key: Ed25519PrivateKey


def new_principal() -> Principal:
    """A new Ed25519 did:key (public key multicodec 0xed01)."""
    key = Ed25519PrivateKey.generate()
    raw = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ident = "z" + _base58btc(b"\xed\x01" + raw)
    return Principal(did=f"did:key:{ident}", kid=f"did:key:{ident}#{ident}", key=key)


def sign_receipt(frm: Principal, to: Principal, capabilities: List[str], *, parent: Optional[str] = None,
                 lifetime_seconds: int = 3600) -> str:
    """Delegation Receipt v1: ``frm`` grants ``capabilities`` to ``to``, optionally chained to ``parent``."""
    now = int(time.time())
    header = {"alg": "EdDSA", "typ": "didis-delegation+jwt", "kid": frm.kid}
    payload = {"iss": frm.did, "aud": to.did, "cap": capabilities, "nbf": now - 30, "exp": now + lifetime_seconds,
               "jti": f"urn:uuid:{uuid.uuid4()}"}
    if parent is not None:
        payload["prf"] = hashlib.sha256(parent.encode()).hexdigest()
    signing_input = f"{_b64url(json.dumps(header).encode())}.{_b64url(json.dumps(payload).encode())}"
    return f"{signing_input}.{_b64url(frm.key.sign(signing_input.encode()))}"
