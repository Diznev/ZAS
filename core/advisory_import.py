"""Fetch public advisory JSON only; reference URLs and PoC code are never fetched."""

from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import json
import math
import re
import ssl
import threading
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener

from core.candidate_catalog import candidate_identity, make_candidate, validate_source_url


ENDPOINTS = {
    "GHSA": "https://api.github.com/advisories",
    "NVD": "https://services.nvd.nist.gov/rest/json/cves/2.0",
}
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}\Z", re.I)
GHSA_PATTERN = re.compile(r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}\Z", re.I)
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_ADVISORIES = 20
MAX_PREVIEW = 40


class AdvisoryError(ValueError):
    pass


class AdvisoryRateLimit(AdvisoryError):
    def __init__(self, provider, seconds):
        self.retry_after = max(1, math.ceil(seconds))
        super().__init__(f"{provider}: wait {self.retry_after} seconds before another request. No automatic retry was made.")


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise AdvisoryError("Advisory API redirected the request; redirects are not followed.")


def _text(value, maximum=2000):
    if not isinstance(value, str):
        return ""
    return "".join(char for char in value if ord(char) >= 32 or char in "\n\t").strip()[:maximum]


def _url(value):
    if not isinstance(value, str) or len(value) > 2000:
        return ""
    try:
        return validate_source_url(value.strip(), required=True)
    except ValueError:
        return ""


def _list(value, limit):
    return value[:limit] if isinstance(value, list) else []


def _cve(value):
    if not isinstance(value, str) or len(value) > 40:
        return None
    value = value.strip().upper()
    return value if CVE_PATTERN.fullmatch(value) else None


def _card(provider, advisory_id, cve, product, versions, advisory_url,
          description, references, updated, fetched_at, exploit_refs=()):
    references = list(dict.fromkeys(url for url in map(_url, references) if url))[:8]
    exploit_refs = [url for url in map(_url, exploit_refs) if url]
    source = exploit_refs[0] if exploit_refs else advisory_url
    poc_status = "NVD-labelled reference (unverified)" if exploit_refs else "No PoC identified"
    notes = (f"Imported metadata from {provider}\nAdvisory: {advisory_id}\nFetched at (UTC): {fetched_at}\n"
             f"Source updated: {_text(updated, 100) or 'Not provided'}\n"
             f"PoC status: {poc_status}. Reference tags are not evidence of a working PoC.\n"
             "CVE/product/version attribution, web scope and prerequisites require independent review.\n\n"
             f"Description:\n{_text(description, 2200)}\n\nReferences:\n" + "\n".join(references))[:10_000]
    candidate = make_candidate({
        "cve": cve, "product": _text(product, 200) or f"Product not specified ({advisory_id})",
        "versions": _text(versions, 1000),
        "preconditions": "Not established by this importer. Review the original advisory before lab testing.",
        "poc_url": source, "advisory_url": advisory_url, "revision": "", "notes": notes, "status": "new",
    })
    return {"candidate": candidate, "provider": provider, "advisory_id": advisory_id,
            "poc_status": poc_status}


def parse_ghsa(data, fetched_at):
    if not isinstance(data, list):
        raise AdvisoryError("GHSA returned an unexpected JSON structure.")
    cards = []
    skipped = 0
    for advisory in data[:MAX_ADVISORIES]:
        if not isinstance(advisory, dict):
            skipped += 1
            continue
        ghsa_id = _text(advisory.get("ghsa_id"), 40)
        if advisory.get("withdrawn_at") or advisory.get("type") == "malware" or not GHSA_PATTERN.fullmatch(ghsa_id):
            skipped += 1
            continue
        cve = _cve(advisory.get("cve_id")) or "CVE-UNVERIFIED"
        products = {}
        for vulnerability in _list(advisory.get("vulnerabilities"), 20):
            if not isinstance(vulnerability, dict) or not isinstance(vulnerability.get("package"), dict):
                continue
            package = _text(vulnerability["package"].get("name"), 200)
            if package:
                ranges = products.setdefault(package, set())
                version = _text(vulnerability.get("vulnerable_version_range"), 300)
                if version:
                    ranges.add(version)
        if not products:
            products = {f"Product not specified ({ghsa_id})": set()}
        refs = advisory.get("references") if isinstance(advisory.get("references"), list) else []
        url = f"https://github.com/advisories/{ghsa_id}"
        description = _text(advisory.get("summary"), 500) + "\n" + _text(advisory.get("description"), 1700)
        for product, versions in list(products.items())[:5]:
            cards.append(_card("GHSA", ghsa_id, cve, product, "; ".join(sorted(versions)), url,
                               description, refs, advisory.get("updated_at"), fetched_at))
    return cards, skipped


def _nvd_products(cve):
    """Retain CPE application constraints as claims, not a solved applicability rule."""
    products = {}
    pending = _list(cve.get("configurations"), 100)
    visited = 0
    while pending and visited < 500:
        node = pending.pop()
        visited += 1
        if not isinstance(node, dict) or node.get("negate"):
            continue
        for key in ("nodes", "children"):
            if isinstance(node.get(key), list):
                pending.extend(node[key][:100])
        for match in _list(node.get("cpeMatch"), 100):
            if not isinstance(match, dict) or match.get("vulnerable") is not True:
                continue
            fields = re.split(r"(?<!\\):", _text(match.get("criteria"), 2000))
            if len(fields) < 6 or fields[:3] != ["cpe", "2.3", "a"]:
                continue
            product = fields[4]
            constraints = []
            if fields[5] not in ("*", "-"):
                constraints.append("= " + fields[5])
            for key, operator in (("versionStartIncluding", ">="), ("versionStartExcluding", ">"),
                                  ("versionEndIncluding", "<="), ("versionEndExcluding", "<")):
                if isinstance(match.get(key), str):
                    constraints.append(operator + " " + _text(match[key], 100))
            products.setdefault(product, set()).add("CPE constraint: " + (", ".join(constraints) or "unspecified") + " (review full applicability)")
    return products


def parse_nvd(data, fetched_at):
    if not isinstance(data, dict) or not isinstance(data.get("vulnerabilities"), list):
        raise AdvisoryError("NVD returned an unexpected JSON structure.")
    cards = []
    skipped = 0
    for entry in data["vulnerabilities"][:MAX_ADVISORIES]:
        cve = entry.get("cve") if isinstance(entry, dict) else None
        if not isinstance(cve, dict):
            skipped += 1
            continue
        cve_id = _cve(cve.get("id"))
        if cve_id is None or str(cve.get("vulnStatus", "")).lower() == "rejected":
            skipped += 1
            continue
        description = next((_text(item.get("value"), 2200) for item in _list(cve.get("descriptions"), 100)
                            if isinstance(item, dict) and item.get("lang") == "en"), "No English description provided.")
        refs, exploit_refs = [], []
        for reference in _list(cve.get("references"), 50):
            if not isinstance(reference, dict):
                continue
            url = _url(reference.get("url"))
            if url:
                refs.append(url)
                tags = reference.get("tags") if isinstance(reference.get("tags"), list) else []
                if "Exploit" in tags:
                    exploit_refs.append(url)
        products = _nvd_products(cve) or {f"Product not specified ({cve_id})": set()}
        for product, versions in list(products.items())[:5]:
            cards.append(_card("NVD", cve_id, cve_id, product, "; ".join(sorted(versions)),
                               f"https://nvd.nist.gov/vuln/detail/{cve_id}", description, refs,
                               cve.get("lastModified"), fetched_at, exploit_refs))
    return cards, skipped


def classify_preview(cards, existing, modules=None):
    known = {candidate_identity(record) for record in existing}
    known_cves = {record["cve"] for record in existing if record["cve"] != "CVE-UNVERIFIED"}
    covered = {}
    for name, metadata in (modules or {}).items():
        for cve in re.findall(r"CVE-\d{4}-\d{4,}", str(metadata.get("cve", "")), re.I):
            covered.setdefault(cve.upper(), []).append(name)
    seen = set()
    result = []
    for item in cards[:MAX_PREVIEW]:
        record = item["candidate"]
        key = candidate_identity(record)
        addable = key not in known and key not in seen
        if key in known:
            match = "Already in catalog"
        elif key in seen:
            match = "Duplicate in results"
        elif record["cve"] in covered:
            match = "Existing module: " + ", ".join(sorted(covered[record["cve"]]))
        elif record["cve"] in known_cves:
            match = "Same CVE, different product"
        else:
            match = "New"
        result.append(dict(item, match=match, addable=addable))
        seen.add(key)
    return result


def _retry_seconds(headers, now):
    value = headers.get("Retry-After", "")
    try:
        seconds = float(value)
    except (ValueError, TypeError):
        try:
            seconds = parsedate_to_datetime(value).timestamp() - now
        except (ValueError, TypeError, OverflowError):
            try:
                seconds = float(headers.get("X-RateLimit-Reset", "")) - now
            except (ValueError, TypeError):
                seconds = 60
    if not math.isfinite(seconds):
        seconds = 60
    return max(1, min(3600, math.ceil(seconds)))


class AdvisoryClient:
    """Fixed HTTPS endpoints with independent TLS, bounded reads and cooldowns."""

    def __init__(self, opener=None, clock=time.monotonic):
        self._opener = opener or build_opener(ProxyHandler({}), HTTPSHandler(context=ssl.create_default_context()), NoRedirects())
        self._clock = clock
        self._next_request = {}
        self._lock = threading.Lock()

    def fetch(self, provider, query=""):
        if not isinstance(provider, str) or provider not in ENDPOINTS:
            raise AdvisoryError("Choose GHSA or NVD.")
        if not isinstance(query, str) or len(query) > 200 or any(ord(char) < 32 for char in query):
            raise AdvisoryError("Query must be a single line of at most 200 characters.")
        query = query.strip()
        exact_cve = bool(CVE_PATTERN.fullmatch(query))
        if query.upper().startswith("CVE-") and not exact_cve:
            raise AdvisoryError("Enter a complete CVE ID such as CVE-2025-3248.")
        if provider == "GHSA":
            parameters = {"type": "reviewed", "per_page": MAX_ADVISORIES, "sort": "updated", "direction": "desc"}
            if query:
                parameters["cve_id" if exact_cve else "affects"] = query.upper() if exact_cve else query
        else:
            if not query:
                raise AdvisoryError("Enter a CVE ID or keyword for NVD.")
            parameters = {"resultsPerPage": MAX_ADVISORIES, "startIndex": 0,
                          "cveId" if exact_cve else "keywordSearch": query.upper() if exact_cve else query}
        with self._lock:
            remaining = self._next_request.get(provider, 0) - self._clock()
            if remaining > 0:
                raise AdvisoryRateLimit(provider, remaining)
            self._next_request[provider] = self._clock() + (30 if provider == "NVD" else 1)
        request = Request(ENDPOINTS[provider] + "?" + urlencode(parameters),
                          headers={"User-Agent": "ZAS-advisory-import/5.3", "Accept": "application/json"})
        try:
            with self._opener.open(request, timeout=10) as response:
                chunks = []
                size = 0
                deadline = self._clock() + 25
                reader = getattr(response, "read1", response.read)
                while True:
                    if self._clock() > deadline:
                        raise AdvisoryError(f"{provider}: response time limit exceeded.")
                    chunk = reader(min(65536, MAX_RESPONSE_BYTES + 1 - size))
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > MAX_RESPONSE_BYTES:
                        raise AdvisoryError(f"{provider}: response exceeds the 2 MiB limit.")
                    chunks.append(chunk)
                headers = response.headers
                if headers.get("X-RateLimit-Remaining") == "0":
                    with self._lock:
                        self._next_request[provider] = self._clock() + _retry_seconds(headers, time.time())
                try:
                    data = json.loads(b"".join(chunks).decode("utf-8-sig"))
                except (ValueError, UnicodeError, RecursionError) as exc:
                    raise AdvisoryError(f"{provider}: expected JSON metadata, not an HTML page or invalid response.") from exc
        except HTTPError as exc:
            try:
                if exc.code == 429 or (exc.code == 403 and exc.headers.get("X-RateLimit-Remaining") == "0"):
                    seconds = _retry_seconds(exc.headers, time.time())
                    with self._lock:
                        self._next_request[provider] = self._clock() + seconds
                    raise AdvisoryRateLimit(provider, seconds) from exc
                raise AdvisoryError(f"{provider}: HTTP {exc.code}. No catalog changes were made.") from exc
            finally:
                exc.close()
        except (URLError, OSError, TimeoutError) as exc:
            raise AdvisoryError(f"{provider}: unable to reach the advisory API. Check connectivity and retry later.") from exc
        fetched_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        cards, skipped = parse_ghsa(data, fetched_at) if provider == "GHSA" else parse_nvd(data, fetched_at)
        if exact_cve:
            cards = [item for item in cards if item["candidate"]["cve"] == query.upper()]
        more = len(cards) > MAX_PREVIEW or (provider == "GHSA" and (len(data) >= MAX_ADVISORIES or 'rel="next"' in headers.get("Link", "")))
        if provider == "NVD":
            more = more or (isinstance(data.get("totalResults"), int) and data["totalResults"] > MAX_ADVISORIES)
        return {"items": cards[:MAX_PREVIEW], "skipped": skipped, "more": bool(more),
                "provider": provider, "fetched_at": fetched_at}
