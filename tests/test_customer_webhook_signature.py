"""Independent Python receiver verification, no provider or network access."""
import hashlib
import hmac
import json
import time
import unittest
from didis import verify_customer_monitor_signature


class CustomerSignatureTests(unittest.TestCase):
    def setUp(self):
        self.now = int(time.time())
        self.secret = "synthetic-python-customer-webhook-secret"
        self.scope = dict(tenant_id="tenant_" + "a" * 64, project_id="project_" + "b" * 64, event_id="cevent_" + "c" * 64)

    def sample(self, timestamp=None):
        timestamp = self.now if timestamp is None else timestamp
        body = json.dumps(dict(specVersion="didis.customer-monitor.v1", id=self.scope["event_id"], tenantId=self.scope["tenant_id"], projectId=self.scope["project_id"], createdAt=timestamp, data={"note": "€ 😀"}), ensure_ascii=False).encode()
        signature = f"t={timestamp},v1={hmac.new(self.secret.encode(), str(timestamp).encode() + b'.' + body, hashlib.sha256).hexdigest()}"
        return body, signature

    def test_exact_raw_body_and_explicit_owner_scope(self):
        body, signature = self.sample()
        self.assertTrue(verify_customer_monitor_signature(self.secret, body, signature, **self.scope))
        self.assertFalse(verify_customer_monitor_signature(self.secret, body + b" ", signature, **self.scope))
        wrong = dict(self.scope, project_id="project_" + "d" * 64)
        self.assertFalse(verify_customer_monitor_signature(self.secret, body, signature, **wrong))

    def test_immutable_retry_time_not_admin_five_minute_tolerance(self):
        body, signature = self.sample(self.now - 3600)
        self.assertTrue(verify_customer_monitor_signature(self.secret, body, signature, **self.scope))
        for ts in [self.now - 30 * 86400, self.now + 120]:
            body, signature = self.sample(ts)
            self.assertFalse(verify_customer_monitor_signature(self.secret, body, signature, **self.scope))

    def test_malformed_header_and_invalid_limits_are_refused(self):
        body, signature = self.sample()
        for header in [signature + ",v1=other", "t=0,v1=short", "", signature.replace("t=", "t=0")]:
            self.assertFalse(verify_customer_monitor_signature(self.secret, body, header, **self.scope))
        for age in [0, -1, 2592001, True]:
            self.assertFalse(verify_customer_monitor_signature(self.secret, body, signature, max_age_seconds=age, **self.scope))


if __name__ == "__main__":
    unittest.main()
