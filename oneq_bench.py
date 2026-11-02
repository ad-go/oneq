#!/usr/bin/env python3
"""oneq_bench: randomised 48-hour test harness for oneq nodes.

Usage:
    python oneq_bench.py --relay https://x.example.com:8443 --relay https://y.example.com:8443 \
        --community oneq --user alice --password-file /etc/oneq/alice.pw \
        --cafile /etc/oneq/ca.crt [--duration 48h] [--update]

The script self-updates from the relay on startup (--update flag).
Test functions are registered via @bench.test(...) and run with random spacing.
Results are POSTed to /v1/c/{comm}/perf every 60 s.
"""

import argparse
import asyncio
import json
import logging
import os
import random
import ssl
import sys
import time
from dataclasses import dataclass, field
from typing import Callable, List, Optional

log = logging.getLogger("oneq_bench")

# ---------------------------------------------------------------------------
# Self-update: download latest version from relay and re-exec
# ---------------------------------------------------------------------------

async def self_update(relay_url: str, cafile: Optional[str] = None):
    """Download the latest oneq_bench.py from the relay and restart if newer."""
    try:
        import aiohttp
        ctx = ssl.create_default_context(cafile=cafile) if cafile else None
        url = relay_url.rstrip("/") + "/v1/bench"
        async with aiohttp.ClientSession() as s:
            async with s.get(url, ssl=ctx, timeout=aiohttp.ClientTimeout(total=15)) as r:
                if r.status != 200:
                    log.warning("self-update: HTTP %d from %s", r.status, url)
                    return
                new_src = await r.read()
        current = open(__file__, "rb").read()
        if new_src == current:
            log.info("bench script is up to date")
            return
        tmp = __file__ + ".new"
        with open(tmp, "wb") as f:
            f.write(new_src)
        os.replace(tmp, __file__)
        log.info("self-update: restarting with new version")
        os.execv(sys.executable, [sys.executable] + sys.argv)
    except Exception as exc:
        log.warning("self-update failed: %s", exc)


# ---------------------------------------------------------------------------
# Test registry
# ---------------------------------------------------------------------------

@dataclass
class TestEntry:
    name: str
    fn: Callable
    min_interval: float   # seconds
    max_interval: float
    weight: float = 1.0
    next_run: float = field(default_factory=time.monotonic)


class BenchRunner:
    def __init__(self, relay_urls: List[str], community: str, user: str,
                 password: str, cafile: Optional[str] = None):
        self.relay_urls = relay_urls
        self.community = community
        self.user = user
        self.password = password
        self.cafile = cafile
        self.token: Optional[str] = None
        self.base: Optional[str] = None
        self._tests: List[TestEntry] = []
        self._results: list = []

    def test(self, name: str, min_interval: float = 60, max_interval: float = 300, weight: float = 1.0):
        """Decorator: register a coroutine as a bench test."""
        def decorator(fn):
            jitter = random.uniform(0, max_interval)
            entry = TestEntry(name=name, fn=fn,
                              min_interval=min_interval, max_interval=max_interval,
                              weight=weight,
                              next_run=time.monotonic() + jitter)
            self._tests.append(entry)
            return fn
        return decorator

    def _emit(self, name: str, ok: bool, ms: float, **extra):
        rec = {"t": round(time.time(), 3), "e": "bench_result",
               "test": name, "ok": ok, "ms": round(ms, 2), **extra}
        log.info("%s", json.dumps(rec, separators=(",", ":")))
        self._results.append(rec)

    async def _login(self):
        import aiohttp
        ctx = ssl.create_default_context(cafile=self.cafile) if self.cafile else None
        for url in self.relay_urls:
            try:
                async with aiohttp.ClientSession() as s:
                    async with s.post(url.rstrip("/") + "/v1/login",
                                      json={"community": self.community,
                                            "user": self.user,
                                            "password": self.password},
                                      ssl=ctx,
                                      timeout=aiohttp.ClientTimeout(total=10)) as r:
                        if r.status == 200:
                            d = await r.json()
                            self.token = d["token"]
                            self.base = url.rstrip("/")
                            log.info("logged in to %s", self.base)
                            return True
            except Exception as exc:
                log.warning("login to %s: %s", url, exc)
        return False

    async def _flush_results(self):
        if not self._results or not self.token:
            return
        batch, self._results = self._results[:500], self._results[500:]
        import aiohttp
        ctx = ssl.create_default_context(cafile=self.cafile) if self.cafile else None
        try:
            url = f"{self.base}/v1/c/{self.community}/perf"
            hdrs = {"Authorization": f"Bearer {self.token}"}
            async with aiohttp.ClientSession() as s:
                async with s.post(url, json={"events": batch}, headers=hdrs,
                                  ssl=ctx, timeout=aiohttp.ClientTimeout(total=15)) as r:
                    if r.status not in (200, 204):
                        log.warning("flush HTTP %d", r.status)
        except Exception as exc:
            log.warning("flush: %s", exc)

    async def run(self, duration_s: float = 48 * 3600):
        if not await self._login():
            log.error("could not log in to any relay — aborting")
            return

        deadline = time.monotonic() + duration_s
        last_flush = time.monotonic()

        while time.monotonic() < deadline:
            now = time.monotonic()

            # Flush every 60 s
            if now - last_flush >= 60:
                await self._flush_results()
                last_flush = now

            # Find all tests due now
            due = [e for e in self._tests if e.next_run <= now]
            if due:
                entry = random.choices(due, weights=[e.weight for e in due])[0]
                t0 = time.monotonic()
                try:
                    await entry.fn(self)
                    ok = True
                except Exception as exc:
                    log.warning("test %s failed: %s", entry.name, exc)
                    self._emit(entry.name, ok=False, ms=(time.monotonic()-t0)*1000, error=str(exc))
                    ok = False
                entry.next_run = now + random.uniform(entry.min_interval, entry.max_interval)
            else:
                await asyncio.sleep(1)

        await self._flush_results()
        log.info("bench run complete (%.0f s)", duration_s)


# ---------------------------------------------------------------------------
# Built-in test stubs  (replace with real implementations)
# ---------------------------------------------------------------------------

def register_builtin_tests(bench: BenchRunner):

    @bench.test("ping_relay", min_interval=30, max_interval=120)
    async def test_ping_relay(b: BenchRunner):
        """Check relay health endpoint."""
        import aiohttp
        ctx = ssl.create_default_context(cafile=b.cafile) if b.cafile else None
        t0 = time.monotonic()
        async with aiohttp.ClientSession() as s:
            async with s.get(b.base + "/v1/health", ssl=ctx,
                             timeout=aiohttp.ClientTimeout(total=5)) as r:
                ok = r.status == 200
        b._emit("ping_relay", ok=ok, ms=(time.monotonic()-t0)*1000)

    @bench.test("list_nodes", min_interval=60, max_interval=300)
    async def test_list_nodes(b: BenchRunner):
        """Fetch member list and measure latency."""
        import aiohttp
        ctx = ssl.create_default_context(cafile=b.cafile) if b.cafile else None
        hdrs = {"Authorization": f"Bearer {b.token}"}
        t0 = time.monotonic()
        async with aiohttp.ClientSession() as s:
            async with s.get(f"{b.base}/v1/c/{b.community}/nodes",
                             headers=hdrs, ssl=ctx,
                             timeout=aiohttp.ClientTimeout(total=10)) as r:
                d = await r.json() if r.status == 200 else {}
        b._emit("list_nodes", ok=r.status == 200, ms=(time.monotonic()-t0)*1000,
                node_count=len(d.get("nodes", [])))

    # --- Stubs: implement after deciding what to measure ---

    @bench.test("session_latency", min_interval=120, max_interval=600)
    async def test_session_latency(_b: BenchRunner):
        """Placeholder: measure round-trip latency to a specific peer."""
        # TODO: send a probe packet and wait for CTL_PROBE_REPLY via the node API
        pass

    @bench.test("crypto_bench", min_interval=300, max_interval=900)
    async def test_crypto_bench(b: BenchRunner):
        """Placeholder: local crypto benchmark (init_create + resp_create timing)."""
        # TODO: run N init_create + resp_create calls and report distribution
        pass

    @bench.test("throughput_burst", min_interval=600, max_interval=1800)
    async def test_throughput_burst(_b: BenchRunner):
        """Placeholder: send a burst of frames and measure throughput."""
        # TODO: open a TAP/socket, send N frames, measure time
        pass


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def parse_duration(s: str) -> float:
    if s.endswith("h"):
        return float(s[:-1]) * 3600
    if s.endswith("m"):
        return float(s[:-1]) * 60
    return float(s)


def main():
    ap = argparse.ArgumentParser(description="oneq 48-hour bench harness")
    ap.add_argument("--relay", action="append", dest="relays", required=True,
                    metavar="URL", help="relay URL (repeat for multiple)")
    ap.add_argument("--community", required=True)
    ap.add_argument("--user", required=True)
    ap.add_argument("--password-file", required=True, dest="password_file")
    ap.add_argument("--cafile", default=None, help="CA certificate (PEM)")
    ap.add_argument("--duration", default="48h", help="run duration, e.g. 48h / 30m (default: 48h)")
    ap.add_argument("--update", action="store_true", help="self-update from relay before starting")
    ap.add_argument("--log-file", dest="log_file", default=None,
                    help="JSON-lines perf log file (default: stdout)")
    args = ap.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
        handlers=[
            logging.StreamHandler(),
            *(([logging.FileHandler(args.log_file)] if args.log_file else []))
        ]
    )

    password = open(args.password_file).read().strip()
    duration_s = parse_duration(args.duration)

    async def run():
        if args.update:
            await self_update(args.relays[0], cafile=args.cafile)

        bench = BenchRunner(
            relay_urls=args.relays,
            community=args.community,
            user=args.user,
            password=password,
            cafile=args.cafile,
        )
        register_builtin_tests(bench)
        await bench.run(duration_s=duration_s)

    asyncio.run(run())


if __name__ == "__main__":
    main()
