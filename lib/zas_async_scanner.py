# ZAS Async Scanner Module
# High-performance async scanning with connection pooling

import asyncio
import time
import random
from typing import Optional, Dict, Any, List


class AsyncScanner:
    """Async exploit scanner with connection pooling and rate limiting."""

    def __init__(self, max_concurrent=100, timeout=15, rate_limit=10.0):
        self.max_concurrent = max_concurrent
        self.timeout = timeout
        self.rate_limit = rate_limit
        self._semaphore = None
        self._rate_semaphore = None
        self._connections = {}
        self._stats = {"total": 0, "done": 0, "vuln": 0, "exploited": 0, "errors": 0}
        self._results = []
        self._lock = asyncio.Lock()

    async def _get_session(self, host):
        """Get or create aiohttp session for host (connection pooling)."""
        try:
            import aiohttp
        except ImportError:
            raise ImportError("aiohttp required: pip install aiohttp")

        if host not in self._connections:
            connector = aiohttp.TCPConnector(
                limit=10,
                limit_per_host=5,
                ttl_dns_cache=300,
                enable_cleanup_closed=True,
            )
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            self._connections[host] = aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
            )
        return self._connections[host]

    async def _rate_wait(self):
        """Rate limiting delay."""
        if self.rate_limit > 0:
            await asyncio.sleep(1.0 / self.rate_limit)

    async def _scan_one(self, url, exploit_module, mode="exploit", extra_args=None):
        """Scan single target with one exploit module."""
        async with self._semaphore:
            await self._rate_wait()

            try:
                from urllib.parse import urlparse
                host = urlparse(url).hostname

                session = await self._get_session(host)

                if mode == "exploit":
                    result = await self._run_exploit(session, url, exploit_module, extra_args or {})
                else:
                    result = {"ok": False, "reason": f"Unknown mode: {mode}"}

                async with self._lock:
                    self._stats["done"] += 1
                    if result.get("ok"):
                        self._stats["exploited"] += 1
                    self._results.append({"url": url, "module": exploit_module.__name__, "result": result})

                return result

            except Exception as e:
                async with self._lock:
                    self._stats["errors"] += 1
                    self._stats["done"] += 1
                return {"ok": False, "error": str(e)}

    async def _run_exploit(self, session, url, mod, extra_args):
        """Run exploit in thread pool."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None, lambda: mod.exploit(url, timeout=self.timeout, **extra_args)
        )

    async def scan_targets(self, targets, exploits, mode="exploit", extra_args=None, callback=None):
        """Scan multiple targets with multiple exploits concurrently.

        Args:
            targets: List of URLs
            exploits: Dict of {name: module} or list of modules
            mode: "exploit"
            extra_args: Additional args for exploit()
            callback: async def callback(url, module_name, result) called per-result

        Returns:
            Dict with stats and results
        """
        self._semaphore = asyncio.Semaphore(self.max_concurrent)
        self._stats = {"total": 0, "done": 0, "vuln": 0, "exploited": 0, "errors": 0}
        self._results = []

        if isinstance(exploits, dict):
            exploit_list = [(name, mod) for name, mod in exploits.items()]
        else:
            exploit_list = [(mod.__name__, mod) for mod in exploits]

        tasks = []
        for target in targets:
            for name, mod in exploit_list:
                self._stats["total"] += 1
                tasks.append(self._scan_one(target, mod, mode, extra_args))

        if callback:
            for task in asyncio.as_completed(tasks):
                result = await task
                if callback:
                    await callback(result.get("url", ""), result.get("module", ""), result)
        else:
            await asyncio.gather(*tasks, return_exceptions=True)

        return {
            "stats": dict(self._stats),
            "results": self._results,
        }

    async def close(self):
        """Close all sessions."""
        for session in self._connections.values():
            await session.close()
        self._connections.clear()


async def async_scan(targets, exploits, mode="exploit", max_concurrent=100,
                     timeout=15, rate_limit=10.0, extra_args=None, callback=None):
    """High-level async scanning function.

    Usage:
        import asyncio
        from async_scanner import async_scan

        results = asyncio.run(async_scan(
            targets=["http://target1.com", "http://target2.com"],
            exploits={"wp_filemanager": wp_filemanager_rce},
            mode="exploit",
            max_concurrent=50,
        ))
    """
    scanner = AsyncScanner(
        max_concurrent=max_concurrent,
        timeout=timeout,
        rate_limit=rate_limit,
    )
    try:
        return await scanner.scan_targets(targets, exploits, mode, extra_args, callback)
    finally:
        await scanner.close()


def run_async_scan(targets, exploits, mode="exploit", max_concurrent=100,
                   timeout=15, rate_limit=10.0, extra_args=None):
    """Synchronous wrapper for async_scan."""
    return asyncio.run(async_scan(
        targets, exploits, mode, max_concurrent, timeout, rate_limit, extra_args
    ))
