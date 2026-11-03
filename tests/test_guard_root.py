"""Application-owned execution root is required before any transport or handler work."""
import asyncio
import unittest
from didis import DidisGuard, AsyncDidisGuard, DidisGuardError, didis_guard
from test_guard import FakeClient, FakeAsyncClient, AGENT, ROOT, allow

class RootTests(unittest.TestCase):
    def test_all_execution_entrypoints_require_root_before_work(self):
        effects = []
        for cls, client in [(DidisGuard, FakeClient([])), (AsyncDidisGuard, FakeAsyncClient([]))]:
            for options in [{}, *[{"root": r} for r in [None, "", " ", "\t\n", 42, " " + ROOT, ROOT + " "]]]:
                with self.subTest(cls=cls.__name__, options=options):
                    with self.assertRaises(DidisGuardError) as ctx:
                        cls(client, AGENT, **options).tool("run")(lambda: effects.append(1))
                    self.assertEqual(ctx.exception.code, "GUARD_MISCONFIGURED")
                    with self.assertRaises(DidisGuardError) as ctx:
                        didis_guard(client, AGENT, "run", **options)
                    self.assertEqual(ctx.exception.code, "GUARD_MISCONFIGURED")
            self.assertEqual(client.calls, [])
        self.assertEqual(effects, [])

    def test_root_filters_sync_and_async_answers(self):
        for cls, client in [(DidisGuard, FakeClient([allow("run"), allow("run", root="did:key:zAttacker")])), (AsyncDidisGuard, FakeAsyncClient([allow("run"), allow("run", root="did:key:zAttacker")]))]:
            effects = []
            guard = cls(client, AGENT, ROOT, allow_cache_seconds=0)
            if cls is DidisGuard:
                run = guard.tool("run")(lambda: effects.append(1))
                run()
                with self.assertRaises(DidisGuardError) as ctx:
                    run()
                self.assertEqual(ctx.exception.code, "TOOL_NOT_AUTHORIZED")
            else:
                @guard.tool("run")
                async def run(): effects.append(1)
                async def scenario():
                    await run()
                    with self.assertRaises(DidisGuardError) as ctx:
                        await run()
                    self.assertEqual(ctx.exception.code, "TOOL_NOT_AUTHORIZED")
                asyncio.run(scenario())
            self.assertEqual(effects, [1])
            self.assertEqual(client.calls, [(AGENT, "run", ROOT)] * 2)

    def test_captured_root_is_readonly_and_not_response_derived(self):
        client = FakeClient([allow("run")])
        guard = DidisGuard(client, AGENT, ROOT)
        with self.assertRaises(AttributeError):
            guard._core.root = "did:key:zAttacker"
        guard.check("run")
        self.assertEqual(client.calls, [(AGENT, "run", ROOT)])
