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
            try:
                return json.loads(resp.read().decode())
            finally:
                resp.close()
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

# CensysAPI, FofaAPI and search_targets() were removed: defined but
# never called from anywhere in the tool. ShodanAPI is the only client
# the GUI uses (Shodan panel).
