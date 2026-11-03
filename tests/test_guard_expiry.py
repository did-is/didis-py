"""Synthetic authorization-producer negatives, not evidence of a core authorization bypass."""
import asyncio
import unittest
from contextlib import contextmanager
from datetime import datetime, timezone
from unittest.mock import patch
from types import SimpleNamespace

from didis import AsyncDidisGuard, DidisGuard, DidisGuardError, didis_guard, pin_tool_definitions
from test_guard import FakeClient, FakeAsyncClient, AGENT, ROOT, allow

EPOCH = datetime(2030, 1, 1, tzinfo=timezone.utc).timestamp()
DEFINITION = {"name": "tool", "description": "approved"}
TOOL = "cap:run"


def iso(offset):
    return datetime.fromtimestamp(EPOCH + offset, timezone.utc).isoformat()


@contextmanager
def clock():
    now = [0.0]
    fake_time = SimpleNamespace(time=lambda: EPOCH + now[0], monotonic=lambda: 1000 + now[0])
    with patch("didis.guard.time", fake_time):
        yield lambda seconds: now.__setitem__(0, seconds)


class ExpiryTests(unittest.TestCase):
    def refused(self, run, code="TOOL_NOT_AUTHORIZED"):
        with self.assertRaises(DidisGuardError) as ctx:
            run()
        self.assertEqual(ctx.exception.code, code)

    def test_first_stale_and_equal_allow_never_executes_including_zero_cache(self):
        with clock():
            for ttl in [0, 30]:
                for expiry in [-1, 0]:
                    with self.subTest(ttl=ttl, expiry=expiry):
                        client = FakeClient(lambda _: allow(TOOL, expires=iso(expiry)))
                        effects = []
                        run = didis_guard(client, AGENT, TOOL, ROOT, allow_cache_seconds=ttl)(lambda: effects.append(1))
                        self.refused(run)
                        self.refused(run)
                        self.assertEqual(effects, [])
                        self.assertEqual(len(client.calls), 2)

    def test_optional_expiry_retains_ttl_only_behavior(self):
        with clock() as set_time:
            for extra in [{}, {"expires": None}, {"expires": ""}, {"expires": "not-a-date"}]:
                with self.subTest(extra=extra):
                    set_time(0)
                    client = FakeClient(lambda _: allow(TOOL, **extra))
                    guard = DidisGuard(client, AGENT, ROOT, allow_cache_seconds=1)
                    run = guard.tool(TOOL)(lambda: "ok")
                    self.assertEqual(run(), "ok")
                    set_time(0.9)
                    self.assertEqual(run(), "ok")
                    self.assertEqual(len(client.calls), 1)
                    set_time(1)
                    self.assertEqual(run(), "ok")
                    self.assertEqual(len(client.calls), 2)

    def test_valid_cache_ttl_and_expiry_refresh_deny_expired_error_or_valid(self):
        with clock() as set_time:
            for ttl in [0.5, 5]:
                for refresh in ["deny", "expired", "error", "valid"]:
                    with self.subTest(ttl=ttl, refresh=refresh):
                        set_time(0)
                        answer = {"deny": allow(TOOL, decision="DENY", authorized=False), "expired": allow(TOOL, expires=iso(1)), "error": RuntimeError("offline"), "valid": allow(TOOL, expires=iso(10))}[refresh]
                        client = FakeClient([allow(TOOL, expires=iso(1)), answer, answer])
                        effects = []
                        run = DidisGuard(client, AGENT, ROOT, allow_cache_seconds=ttl).tool(TOOL)(lambda: effects.append(1))
                        run()
                        set_time(0.49)
                        run()
                        self.assertEqual(len(client.calls), 1)
                        set_time(1)
                        if refresh == "valid":
                            run()
                        else:
                            code = "GUARD_UNAVAILABLE" if refresh == "error" else "TOOL_NOT_AUTHORIZED"
                            self.refused(run, code)
                            self.refused(run, code)
                        self.assertEqual(len(effects), 3 if refresh == "valid" else 2)
                        self.assertEqual(len(client.calls), 2 if refresh == "valid" else 3)

    def test_sync_pin_refresh_and_decision_hook_deadline(self):
        with clock() as set_time:
            pins = pin_tool_definitions([DEFINITION])
            for cached in [False, True]:
                set_time(0)
                client = FakeClient([allow(TOOL, expires=iso(1))])
                guard = DidisGuard(client, AGENT, ROOT, pins=pins)
                if cached:
                    guard.check("tool", DEFINITION, capability=TOOL)
                reads = []
                effects = []

                def definition():
                    reads.append(1)
                    if len(reads) == 2:
                        set_time(1)
                    return DEFINITION

                run = guard.tool("tool", definition, capability=TOOL)(lambda: effects.append(1))
                self.refused(run)
                self.assertEqual((effects, len(reads), len(client.calls)), ([], 2, 1))
            set_time(0)
            guard = DidisGuard(FakeClient([allow(TOOL, expires=iso(1))]), AGENT, ROOT, on_decision=lambda e: set_time(1) if e["allowed"] else None)
            self.refused(guard.tool(TOOL)(lambda: self.fail("must not execute")))

    def test_sync_pin_drift_during_verify_is_blocked(self):
        current = [DEFINITION]
        pins = pin_tool_definitions([DEFINITION])

        def answer(_):
            current[0] = {**DEFINITION, "description": "drift"}
            return allow(TOOL)

        guard = DidisGuard(FakeClient(answer), AGENT, ROOT, pins=pins)
        self.refused(guard.tool("tool", lambda: current[0], capability=TOOL)(lambda: self.fail("must not execute")), "TOOL_DRIFT")


class AsyncExpiryTests(unittest.IsolatedAsyncioTestCase):
    async def refused(self, run, code="TOOL_NOT_AUTHORIZED"):
        with self.assertRaises(DidisGuardError) as ctx:
            await run()
        self.assertEqual(ctx.exception.code, code)

    async def test_async_first_expired_and_equal_with_zero_or_default_cache(self):
        with clock():
            for ttl in [0, 30]:
                for expiry in [-1, 0]:
                    client = FakeAsyncClient([allow(TOOL, expires=iso(expiry))] * 2)
                    effects = []

                    @didis_guard(client, AGENT, TOOL, ROOT, allow_cache_seconds=ttl)
                    async def run():
                        effects.append(1)

                    await self.refused(run)
                    await self.refused(run)
                    self.assertEqual((effects, len(client.calls)), ([], 2))

    async def test_async_valid_cache_and_all_refresh_outcomes(self):
        with clock() as set_time:
            for ttl in [0.5, 5]:
                for refresh in ["deny", "expired", "error", "valid"]:
                    set_time(0)
                    answer = {"deny": allow(TOOL, decision="DENY", authorized=False), "expired": allow(TOOL, expires=iso(1)), "error": RuntimeError("offline"), "valid": allow(TOOL, expires=iso(10))}[refresh]
                    client = FakeAsyncClient([allow(TOOL, expires=iso(1)), answer, answer])
                    effects = []

                    @AsyncDidisGuard(client, AGENT, ROOT, allow_cache_seconds=ttl).tool(TOOL)
                    async def run():
                        effects.append(1)

                    await run()
                    set_time(0.49)
                    await run()
                    self.assertEqual(len(client.calls), 1)
                    set_time(1)
                    if refresh == "valid":
                        await run()
                    else:
                        code = "GUARD_UNAVAILABLE" if refresh == "error" else "TOOL_NOT_AUTHORIZED"
                        await self.refused(run, code)
                        await self.refused(run, code)
                    self.assertEqual(len(effects), 3 if refresh == "valid" else 2)
                    self.assertEqual(len(client.calls), 2 if refresh == "valid" else 3)

    async def test_expiry_during_verify_await(self):
        with clock() as set_time:
            class Delayed(FakeAsyncClient):
                async def verify_tool(self, agent, tool, root=None):
                    answer = await super().verify_tool(agent, tool, root)
                    await asyncio.sleep(0)
                    set_time(1)
                    return answer

            client = Delayed([allow(TOOL, expires=iso(1))])

            @AsyncDidisGuard(client, AGENT, ROOT).tool(TOOL)
            async def run():
                self.fail("must not execute")

            await self.refused(run)

    async def test_async_pin_refresh_expiry_fresh_cached_and_cache_ttl(self):
        with clock() as set_time:
            pins = pin_tool_definitions([DEFINITION])
            for mode in ["fresh", "cached", "ttl"]:
                set_time(0)
                client = FakeAsyncClient([allow(TOOL, expires=iso(10 if mode == "ttl" else 1))])
                guard = AsyncDidisGuard(client, AGENT, ROOT, pins=pins, allow_cache_seconds=1)
                if mode != "fresh":
                    await guard.check("tool", DEFINITION, capability=TOOL)
                reads = []

                async def definition():
                    reads.append(1)
                    await asyncio.sleep(0)
                    if len(reads) == 2:
                        set_time(1)
                    return DEFINITION

                @guard.tool("tool", definition, capability=TOOL)
                async def run():
                    self.fail("must not execute")

                await self.refused(run)
                self.assertEqual((len(reads), len(client.calls)), (2, 1))

    async def test_async_pin_drift_during_verify(self):
        current = [DEFINITION]
        pins = pin_tool_definitions([DEFINITION])

        class Drifting(FakeAsyncClient):
            async def verify_tool(self, agent, tool, root=None):
                await asyncio.sleep(0)
                current[0] = {**DEFINITION, "description": "drift"}
                return await super().verify_tool(agent, tool, root)

        @AsyncDidisGuard(Drifting([allow(TOOL)]), AGENT, ROOT, pins=pins).tool("tool", lambda: current[0], capability=TOOL)
        async def run():
            self.fail("must not execute")

        await self.refused(run, "TOOL_DRIFT")

    async def test_pin_allow_toctou_snapshot_survives_concurrent_longer_cache_refresh(self):
        with clock() as set_time:
            pins = pin_tool_definitions([DEFINITION])
            client = FakeAsyncClient([allow(TOOL, expires=iso(1)), allow(TOOL, expires=iso(10))])
            guard = AsyncDidisGuard(client, AGENT, ROOT, pins=pins)
            blocked, resume = asyncio.Event(), asyncio.Event()
            reads = []

            async def definition():
                reads.append(1)
                if len(reads) == 2:
                    blocked.set()
                    await resume.wait()
                return DEFINITION

            @guard.tool("tool", definition, capability=TOOL)
            async def run():
                self.fail("must not execute")

            pending = asyncio.create_task(run())
            await blocked.wait()
            set_time(1)
            await guard.check("tool", DEFINITION, capability=TOOL)
            resume.set()
            with self.assertRaises(DidisGuardError) as ctx:
                await pending
            self.assertEqual(ctx.exception.code, "TOOL_NOT_AUTHORIZED")
            self.assertEqual(len(client.calls), 2)


if __name__ == "__main__":
    unittest.main()
