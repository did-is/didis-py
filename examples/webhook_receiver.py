"""Receive DID.is monitoring webhooks and verify them before acting. Standard library + the SDK only.

    WEBHOOK_SECRET=... TENANT_ID=tenant_... PROJECT_ID=project_... python webhook_receiver.py
    python webhook_receiver.py --self-test   # signs a sample event locally and posts it to itself
"""
import hashlib
import hmac
import json
import os
import secrets
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

from didis import verify_customer_monitor_signature

SELF_TEST = "--self-test" in sys.argv
if SELF_TEST:
    CFG = {"secret": secrets.token_hex(32), "tenant_id": f"tenant_{secrets.token_hex(32)}",
           "project_id": f"project_{secrets.token_hex(32)}"}
else:
    CFG = {"secret": os.environ.get("WEBHOOK_SECRET", ""), "tenant_id": os.environ.get("TENANT_ID", ""),
           "project_id": os.environ.get("PROJECT_ID", "")}
    if not all(CFG.values()):
        sys.exit("Set WEBHOOK_SECRET, TENANT_ID and PROJECT_ID (shown in the DID.is console), or use --self-test.")

seen = set()  # use a database table with a unique key in production


class Handler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        if self.path != "/didis/webhook":
            self.send_response(404); self.end_headers(); return
        body = self.rfile.read(int(self.headers.get("content-length", 0)))  # the exact raw bytes
        ok = verify_customer_monitor_signature(
            CFG["secret"], body, self.headers.get("x-didis-signature", ""),
            tenant_id=CFG["tenant_id"], project_id=CFG["project_id"], event_id=self.headers.get("x-didis-event-id", ""),
        )
        if not ok:
            print("rejected: bad signature, too old, or not our project")
            self.send_response(401); self.end_headers(); return
        event = json.loads(body)
        if event["id"] in seen:
            print(f"duplicate {event['id'][:15]}… ignored")
        else:
            seen.add(event["id"])  # record first, then act
            print(f"accepted {event['type']} for watch {event['watchId']}")
        self.send_response(200); self.end_headers()

    def log_message(self, *args) -> None:  # keep the output readable
        pass


server = HTTPServer(("", int(os.environ.get("PORT", "8787"))), Handler)
print(f"listening on port {server.server_port}, POST /didis/webhook")
if not SELF_TEST:
    server.serve_forever()
else:
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f"http://localhost:{server.server_port}/didis/webhook"
    event = {"specVersion": "didis.customer-monitor.v1", "id": f"cevent_{secrets.token_hex(32)}",
             "tenantId": CFG["tenant_id"], "projectId": CFG["project_id"], "watchId": "watch_demo",
             "type": "document.changed", "createdAt": int(time.time()), "data": {}}
    body = json.dumps(event).encode()

    def sign(secret: str, payload: bytes = body) -> str:
        mac = hmac.new(secret.encode(), f"{event['createdAt']}.".encode() + payload, hashlib.sha256).hexdigest()
        return f"t={event['createdAt']},v1={mac}"

    def post(signature: str, payload: bytes = body) -> int:
        req = urllib.request.Request(url, data=payload, method="POST", headers={
            "content-type": "application/json", "x-didis-event-id": event["id"], "x-didis-signature": signature})
        try:
            return urllib.request.urlopen(req).status
        except urllib.error.HTTPError as e:
            return e.code

    print("genuine event      ->", post(sign(CFG["secret"])))
    print("same event again   ->", post(sign(CFG["secret"])))
    print("wrong secret       ->", post(sign("not-the-secret")))
    print("body changed       ->", post(sign(CFG["secret"]), body.replace(b"document.changed", b"resolution.failed")))
    server.shutdown()
