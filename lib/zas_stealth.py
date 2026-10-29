"""
ZAS Stealth — Domain fronting, request signing, random delays, proxy rotation.
Provides stealth capabilities for evading WAFs and rate limiting.
"""

import random
import time
import threading
import urllib.request
import ssl


# ─── Domain Fronting ───────────────────────────────────────────────────────────

class DomainFronting:
    """Domain fronting via CDN (Cloudfront, Azure CDN, Google CDN)."""
    
    # Known CDN fronting domains
    CDN_DOMAINS = {
        "cloudfront": [
            ".cloudfront.net",
            ".amazonaws.com",
        ],
        "azure": [
            ".azureedge.net",
            ".azurewebsites.net",
            ".trafficmanager.net",
        ],
        "google": [
            ".googleusercontent.com",
            ".appspot.com",
            ".firebaseapp.com",
        ],
        "akamai": [
            ".akamaized.net",
            ".akamai.net",
        ],
    }
    
    @staticmethod
    def get_fronting_headers(target_host, cdn_host):
        """Generate headers for domain fronting.
        
        Args:
            target_host: actual target hostname
            cdn_host: CDN hostname to use for SNI
        
        Returns:
            dict of headers
        """
        return {
            "Host": target_host,
            "X-Forwarded-Host": target_host,
            "X-Original-URL": "/",
            "X-Rewrite-URL": "/",
        }
    
    @staticmethod
    def test_fronting(cdn_host, target_host, timeout=10):
        """Test if domain fronting works for a CDN/target combination.
        
        Args:
            cdn_host: CDN hostname
            target_host: target hostname
            timeout: request timeout
        
        Returns:
            bool: True if fronting works
        """
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            
            headers = DomainFronting.get_fronting_headers(target_host, cdn_host)
            url = f"https://{cdn_host}/"
            
            req = urllib.request.Request(url, headers=headers)
            resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
            
            # Check if response is from target
            body = resp.read(1000).decode(errors="ignore")
            return target_host.lower() in body.lower() or resp.status == 200
        except Exception:
            return False


# ─── Request Signing ───────────────────────────────────────────────────────────

class RequestSigner:
    """Sign requests to bypass WAF signature detection."""
    
    @staticmethod
    def random_case(payload):
        """Random case transformation for payload obfuscation.
        
        Args:
            payload: string to transform
        
        Returns:
            str: randomly cased string
        """
        return "".join(c.upper() if random.random() > 0.5 else c.lower() for c in payload)
    
    @staticmethod
    def unicode_encode(payload):
        """Unicode encoding for payload obfuscation.
        
        Args:
            payload: string to encode
        
        Returns:
            str: unicode encoded string
        """
        result = []
        for c in payload:
            if random.random() > 0.5 and c.isalpha():
                result.append(f"\\u{ord(c):04x}")
            else:
                result.append(c)
        return "".join(result)
    
    @staticmethod
    def double_url_encode(payload):
        """Double URL encoding for payload obfuscation.
        
        Args:
            payload: string to encode
        
        Returns:
            str: double URL encoded string
        """
        import urllib.parse
        first = urllib.parse.quote(payload, safe="")
        return urllib.parse.quote(first, safe="")
    
    @staticmethod
    def chunked_encode(payload):
        """Chunked transfer encoding for payload obfuscation.
        
        Args:
            payload: string to encode
        
        Returns:
            list of chunks
        """
        chunk_size = random.randint(3, 8)
        chunks = []
        for i in range(0, len(payload), chunk_size):
            chunk = payload[i:i + chunk_size]
            chunks.append(f"{len(chunk):x}\r\n{chunk}\r\n")
        chunks.append("0\r\n\r\n")
        return chunks
    
    @staticmethod
    def comment_injection(payload):
        """SQL comment injection for WAF bypass.
        
        Args:
            payload: SQL payload
        
        Returns:
            str: payload with random comments
        """
        keywords = ["SELECT", "UNION", "FROM", "WHERE", "AND", "OR", "ORDER", "GROUP"]
        result = payload
        for kw in keywords:
            if kw.lower() in result.lower():
                # Insert comment after keyword
                result = result.replace(kw, f"{kw}/**/")
                result = result.replace(kw.lower(), f"{kw.lower()}/**/")
        return result
    
    @staticmethod
    def null_byte_injection(payload):
        """Null byte injection for payload obfuscation.
        
        Args:
            payload: string to obfuscate
        
        Returns:
            str: payload with null bytes
        """
        result = []
        for c in payload:
            if random.random() > 0.7:
                result.append("%00")
            result.append(c)
        return "".join(result)


# ─── Random Delays ─────────────────────────────────────────────────────────────

class AdaptiveDelays:
    """Adaptive delay system that adjusts based on target response."""
    
    def __init__(self, min_delay=0.3, max_delay=2.0, adaptive=True):
        self.min_delay = min_delay
        self.max_delay = max_delay
        self.adaptive = adaptive
        self.current_factor = 1.0
        self.lock = threading.Lock()
        self.consecutive_blocks = 0
        self.consecutive_successes = 0
    
    def get_delay(self):
        """Get current delay based on adaptive state.
        
        Returns:
            float: delay in seconds
        """
        with self.lock:
            base = random.uniform(self.min_delay, self.max_delay)
            return base * self.current_factor
    
    def report_success(self):
        """Report successful request — may decrease delay."""
        with self.lock:
            self.consecutive_successes += 1
            self.consecutive_blocks = 0
            
            # Decrease delay after 5+ successes
            if self.consecutive_successes >= 5:
                self.current_factor = max(0.5, self.current_factor * 0.9)
                self.consecutive_successes = 0
    
    def report_block(self):
        """Report blocked request — increase delay."""
        with self.lock:
            self.consecutive_blocks += 1
            self.consecutive_successes = 0
            
            # Exponential backoff
            self.current_factor = min(10.0, self.current_factor * (1.5 ** self.consecutive_blocks))
    
    def report_rate_limit(self):
        """Report rate limiting — significant delay increase."""
        with self.lock:
            self.current_factor = min(20.0, self.current_factor * 3.0)
    
    def reset(self):
        """Reset to default delays."""
        with self.lock:
            self.current_factor = 1.0
            self.consecutive_blocks = 0
            self.consecutive_successes = 0
    
    def wait(self):
        """Wait for current delay."""
        delay = self.get_delay()
        time.sleep(delay)
        return delay


# ─── Proxy Rotation ────────────────────────────────────────────────────────────

class ProxyRotator:
    """Proxy rotation with health checking and failover."""
    
    def __init__(self):
        self.proxies = []
        self.current_index = 0
        self.failed = set()
        self.lock = threading.Lock()
    
    def load_proxies(self, proxy_list):
        """Load proxies from list.
        
        Args:
            proxy_list: list of proxy strings (http://host:port or socks5://host:port)
        
        Returns:
            int: number of proxies loaded
        """
        with self.lock:
            self.proxies = []
            self.failed = set()
            self.current_index = 0
            
            for proxy in proxy_list:
                proxy = proxy.strip()
                if proxy and not proxy.startswith("#"):
                    self.proxies.append(proxy)
            
            return len(self.proxies)
    
    def load_from_file(self, filepath):
        """Load proxies from file.
        
        Args:
            filepath: path to proxy file (one per line)
        
        Returns:
            int: number of proxies loaded
        """
        try:
            with open(filepath, "r") as f:
                lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]
            return self.load_proxies(lines)
        except Exception:
            return 0
    
    def get_proxy(self):
        """Get next proxy in rotation.
        
        Returns:
            dict: proxy dict for requests, or None if no proxies
        """
        with self.lock:
            if not self.proxies:
                return None
            
            # Skip failed proxies
            attempts = 0
            while attempts < len(self.proxies):
                proxy = self.proxies[self.current_index]
                self.current_index = (self.current_index + 1) % len(self.proxies)
                
                if proxy not in self.failed:
                    return self._make_proxy_dict(proxy)
                
                attempts += 1
            
            # All proxies failed — reset
            self.failed.clear()
            return self._make_proxy_dict(self.proxies[0])
    
    def _make_proxy_dict(self, proxy_str):
        """Convert proxy string to dict for requests.
        
        Args:
            proxy_str: proxy string
        
        Returns:
            dict: proxy dict
        """
        return {
            "http": proxy_str,
            "https": proxy_str,
        }
    
    def mark_failed(self, proxy_str):
        """Mark a proxy as failed.
        
        Args:
            proxy_str: proxy string to mark failed
        """
        with self.lock:
            self.failed.add(proxy_str)
    
    def get_stats(self):
        """Get proxy statistics.
        
        Returns:
            dict with total, active, failed counts
        """
        with self.lock:
            return {
                "total": len(self.proxies),
                "active": len(self.proxies) - len(self.failed),
                "failed": len(self.failed),
            }
    
    def test_proxy(self, proxy_str, test_url="http://httpbin.org/ip", timeout=10):
        """Test if a proxy is working.
        
        Args:
            proxy_str: proxy string
            test_url: URL to test against
            timeout: request timeout
        
        Returns:
            bool: True if proxy works
        """
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            
            proxy_handler = urllib.request.ProxyHandler({
                "http": proxy_str,
                "https": proxy_str,
            })
            opener = urllib.request.build_opener(proxy_handler)
            
            req = urllib.request.Request(test_url, headers={"User-Agent": "ZAS/5.1"})
            resp = opener.open(req, timeout=timeout)
            return resp.status == 200
        except Exception:
            return False
    
    def test_all(self, test_url="http://httpbin.org/ip", timeout=10):
        """Test all proxies and remove failed ones.
        
        Args:
            test_url: URL to test against
            timeout: request timeout
        
        Returns:
            dict with working and failed counts
        """
        working = 0
        failed = 0
        
        for proxy in self.proxies[:]:
            if self.test_proxy(proxy, test_url, timeout):
                working += 1
            else:
                failed += 1
                self.proxies.remove(proxy)
        
        return {"working": working, "failed": failed}


# ─── Stealth Session ───────────────────────────────────────────────────────────

class StealthSession:
    """Combined stealth session with all evasion features."""
    
    def __init__(self, proxy_file=None, min_delay=0.3, max_delay=2.0):
        self.delays = AdaptiveDelays(min_delay, max_delay)
        self.proxies = ProxyRotator()
        self.signer = RequestSigner()
        self.fronting = DomainFronting()
        
        if proxy_file:
            self.proxies.load_from_file(proxy_file)
        
        self.request_count = 0
        self.block_count = 0
    
    def get_request_args(self, url, extra_headers=None):
        """Get stealth request arguments.
        
        Args:
            url: target URL
            extra_headers: additional headers
        
        Returns:
            dict with headers, proxies, delay
        """
        # Get random User-Agent
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/119.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
        ]
        
        headers = {
            "User-Agent": random.choice(user_agents),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        }
        
        if extra_headers:
            headers.update(extra_headers)
        
        # Get proxy
        proxy = self.proxies.get_proxy()
        
        # Get delay
        delay = self.delays.get_delay()
        
        self.request_count += 1
        
        return {
            "headers": headers,
            "proxies": proxy,
            "delay": delay,
            "verify": False,
        }
    
    def report_response(self, status_code):
        """Report response status for adaptive delays.
        
        Args:
            status_code: HTTP status code
        """
        if status_code == 200:
            self.delays.report_success()
        elif status_code in (403, 406, 429):
            self.delays.report_block()
            self.block_count += 1
        elif status_code == 429:
            self.delays.report_rate_limit()
    
    def get_stats(self):
        """Get session statistics.
        
        Returns:
            dict with stats
        """
        return {
            "requests": self.request_count,
            "blocks": self.block_count,
            "proxies": self.proxies.get_stats(),
            "delay_factor": self.delays.current_factor,
        }