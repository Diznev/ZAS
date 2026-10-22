"""
ZAS Recon — Shodan/Censys integration for target discovery.
Search for vulnerable hosts by CVE, software version, or technology.
"""

import json
import urllib.request
import urllib.parse
import ssl


# Disable SSL verification for API calls
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE


class ShodanAPI:
    """Shodan API client for target discovery."""
    
    BASE_URL = "https://api.shodan.io"
    
    def __init__(self, api_key=None):
        self.api_key = api_key
    
    def _request(self, endpoint, params=None):
        """Make API request."""
        if not self.api_key:
            return {"error": "No API key configured"}
        
        if params is None:
            params = {}
        params["key"] = self.api_key
        
        url = f"{self.BASE_URL}{endpoint}?{urllib.parse.urlencode(params)}"
        
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "ZAS/5.1"})
            resp = urllib.request.urlopen(req, timeout=30, context=ctx)
            return json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            return {"error": f"HTTP {e.code}: {e.reason}"}
        except Exception as e:
            return {"error": str(e)}
    
    def search(self, query, limit=100):
        """Search Shodan for hosts matching query.
        
        Args:
            query: Shodan search query (e.g., '"X-Powered-By: WordPress" port:443')
            limit: Max results to return
        
        Returns:
            list of dicts with ip, port, hostnames, org, os, vulns
        """
        result = self._request("/shodan/host/search", {"query": query, "limit": limit})
        
        if "error" in result:
            return result
        
        hosts = []
        for match in result.get("matches", []):
            host = {
                "ip": match.get("ip_str"),
                "port": match.get("port"),
                "hostnames": match.get("hostnames", []),
                "org": match.get("org", ""),
                "os": match.get("os", ""),
                "vulns": match.get("vulns", []),
                "product": match.get("product", ""),
                "version": match.get("version", ""),
                "banner": match.get("data", "")[:200],
            }
            hosts.append(host)
        
        return {"total": result.get("total", 0), "hosts": hosts}
    
    def host_info(self, ip):
        """Get detailed info about a specific host.
        
        Args:
            ip: IP address
        
        Returns:
            dict with host details
        """
        result = self._request(f"/shodan/host/{ip}")
        
        if "error" in result:
            return result
        
        return {
            "ip": result.get("ip_str"),
            "hostnames": result.get("hostnames", []),
            "org": result.get("org", ""),
            "os": result.get("os"),
            "ports": result.get("ports", []),
            "vulns": result.get("vulns", []),
            "services": [
                {
                    "port": s.get("port"),
                    "transport": s.get("transport"),
                    "product": s.get("product"),
                    "version": s.get("version"),
                    "banner": s.get("data", "")[:200],
                }
                for s in result.get("data", [])
            ],
        }
    
    def count(self, query):
        """Count hosts matching query (no API key needed for count).
        
        Args:
            query: Shodan search query
        
        Returns:
            int: number of matching hosts
        """
        result = self._request("/shodan/host/count", {"query": query})
        return result.get("total", 0)
    
    def wordpress_search(self, version=None, limit=100):
        """Search for WordPress installations.
        
        Args:
            version: specific WP version (optional)
            limit: max results
        
        Returns:
            search results
        """
        query = '"X-Powered-By: WordPress"'
        if version:
            query += f' "WordPress {version}"'
        return self.search(query, limit)
    
    def joomla_search(self, version=None, limit=100):
        """Search for Joomla installations."""
        query = '"X-Content-Encoded-By: Joomla"'
        if version:
            query += f' "Joomla {version}"'
        return self.search(query, limit)
    
    def cve_search(self, cve_id, limit=100):
        """Search for hosts vulnerable to specific CVE.
        
        Args:
            cve_id: CVE identifier (e.g., "CVE-2026-64638")
            limit: max results
        
        Returns:
            search results
        """
        query = f'vuln:{cve_id}'
        return self.search(query, limit)
    
    def tech_search(self, technology, limit=100):
        """Search for hosts using specific technology.
        
        Args:
            technology: technology name (e.g., "nginx", "apache", "php")
            limit: max results
        
        Returns:
            search results
        """
        return self.search(f'product:{technology}', limit)


class CensysAPI:
    """Censys API client for target discovery."""
    
    BASE_URL = "https://search.censys.io/api/v2"
    
    def __init__(self, api_id=None, api_secret=None):
        self.api_id = api_id
        self.api_secret = api_secret
    
    def _request(self, endpoint, data=None, method="GET"):
        """Make API request."""
        if not self.api_id or not self.api_secret:
            return {"error": "No API credentials configured"}
        
        url = f"{self.BASE_URL}{endpoint}"
        
        try:
            if method == "POST":
                req = urllib.request.Request(url, data=json.dumps(data or {}).encode(), method="POST")
            else:
                req = urllib.request.Request(url)
            
            req.add_header("Content-Type", "application/json")
            
            # Basic auth
            import base64
            credentials = base64.b64encode(f"{self.api_id}:{self.api_secret}".encode()).decode()
            req.add_header("Authorization", f"Basic {credentials}")
            
            resp = urllib.request.urlopen(req, timeout=30, context=ctx)
            return json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            return {"error": f"HTTP {e.code}: {e.reason}"}
        except Exception as e:
            return {"error": str(e)}
    
    def search_hosts(self, query, per_page=25, cursor=None):
        """Search Censys for hosts.
        
        Args:
            query: Censys search query
            per_page: results per page
            cursor: pagination cursor
        
        Returns:
            dict with hits and metadata
        """
        data = {"q": query, "per_page": per_page}
        if cursor:
            data["cursor"] = cursor
        
        result = self._request("/hosts/search", data, "POST")
        
        if "error" in result:
            return result
        
        hits = []
        for hit in result.get("result", {}).get("hits", []):
            hits.append({
                "ip": hit.get("ip"),
                "services": [
                    {
                        "port": s.get("port"),
                        "service_name": s.get("service_name"),
                        "transport_protocol": s.get("transport_protocol"),
                    }
                    for s in hit.get("services", [])
                ],
                "location": hit.get("location", {}),
                "autonomous_system": hit.get("autonomous_system", {}),
                "operating_system": hit.get("operating_system", {}),
            })
        
        return {
            "total": result.get("result", {}).get("total", 0),
            "hits": hits,
            "cursor": result.get("result", {}).get("cursor"),
        }
    
    def search_certificates(self, query, per_page=25):
        """Search Censys for certificates.
        
        Args:
            query: search query
            per_page: results per page
        
        Returns:
            search results
        """
        data = {"q": query, "per_page": per_page}
        result = self._request("/certificates/search", data, "POST")
        
        if "error" in result:
            return result
        
        certs = []
        for hit in result.get("result", {}).get("hits", []):
            certs.append({
                "fingerprint": hit.get("fingerprint_sha256"),
                "names": hit.get("names", []),
                "issuer": hit.get("issuer", {}),
                "subject": hit.get("subject", {}),
                "validity": hit.get("validity", {}),
            })
        
        return {
            "total": result.get("result", {}).get("total", 0),
            "certificates": certs,
        }


class FofaAPI:
    """FOFA API client for target discovery (alternative to Shodan)."""
    
    BASE_URL = "https://fofa.info/api/v1"
    
    def __init__(self, email=None, api_key=None):
        self.email = email
        self.api_key = api_key
    
    def search(self, query, size=100, fields="ip,port,host,title"):
        """Search FOFA for hosts.
        
        Args:
            query: FOFA search query (base64 encoded)
            size: max results
            fields: fields to return
        
        Returns:
            search results
        """
        import base64
        
        if not self.email or not self.api_key:
            return {"error": "No API credentials configured"}
        
        query_b64 = base64.b64encode(query.encode()).decode()
        
        params = {
            "email": self.email,
            "key": self.api_key,
            "qbase64": query_b64,
            "size": size,
            "fields": fields,
        }
        
        url = f"{self.BASE_URL}/search/all?{urllib.parse.urlencode(params)}"
        
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "ZAS/5.1"})
            resp = urllib.request.urlopen(req, timeout=30, context=ctx)
            data = json.loads(resp.read().decode())
            
            if data.get("error"):
                return {"error": data["errmsg"]}
            
            results = []
            for item in data.get("results", []):
                results.append({
                    "ip": item[0] if len(item) > 0 else None,
                    "port": item[1] if len(item) > 1 else None,
                    "host": item[2] if len(item) > 2 else None,
                    "title": item[3] if len(item) > 3 else None,
                })
            
            return {"total": data.get("size", 0), "hosts": results}
        except Exception as e:
            return {"error": str(e)}


# ─── Convenience Functions ─────────────────────────────────────────────────────

def search_targets(cms=None, version=None, cve=None, country=None, shodan_key=None):
    """Search for targets across multiple sources.
    
    Args:
        cms: CMS name (wordpress, joomla, etc.)
        version: specific version
        cve: CVE identifier
        country: country code
        shodan_key: Shodan API key
    
    Returns:
        list of target URLs
    """
    targets = []
    
    if shodan_key:
        shodan = ShodanAPI(shodan_key)
        
        if cms == "wordpress":
            result = shodan.wordpress_search(version)
        elif cms == "joomla":
            result = shodan.joomla_search(version)
        elif cve:
            result = shodan.cve_search(cve)
        else:
            return {"error": "Specify cms, version, or cve"}
        
        if "error" not in result:
            for host in result.get("hosts", []):
                ip = host["ip"]
                port = host["port"]
                scheme = "https" if port == 443 else "http"
                if port in (80, 443):
                    targets.append(f"{scheme}://{ip}")
                else:
                    targets.append(f"{scheme}://{ip}:{port}")
    
    return {"targets": targets, "total": len(targets)}