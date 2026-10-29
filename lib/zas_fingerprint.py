"""
ZAS Passive Fingerprinting — CMS/Version detection without active probing.
Uses headers, meta tags, HTML patterns, and favicon hashes.
"""

import re


# ─── CMS Signatures ────────────────────────────────────────────────────────────

CMS_SIGNATURES = {
    "wordpress": {
        "headers": ["x-powered-by: wordpress", "link:.*wp-json"],
        "meta": ['content="WordPress', 'name="generator".*WordPress'],
        "html": ["/wp-content/", "/wp-includes/", "wp-embed.min.js"],
        "cookies": ["wordpress_logged_in", "wordpress_test_cookie", "wp-settings"],
        "favicon": None,
    },
    "joomla": {
        "headers": ["x-content-encoded-by: joomla"],
        "meta": ['content="joomla!', 'name="generator".*joomla'],
        "html": ["/media/jui/", "/components/com_", "option=com_"],
        "cookies": ["joomla_user_state"],
        "favicon": None,
    },
    "drupal": {
        "headers": ["x-generator: drupal", "x-drupal-cache"],
        "meta": ['name="generator".*drupal'],
        "html": ["/sites/default/files/", "drupal.js", "drupal.settings.js"],
        "cookies": ["drupal.uid", "sse_sess"],
        "favicon": None,
    },
    "magento": {
        "headers": ["x-magento-*"],
        "meta": [],
        "html": ["/skin/frontend/", "mage/cookies.js", "magentocommerce.com"],
        "cookies": ["frontend", "adminhtml"],
        "favicon": None,
    },
    "laravel": {
        "headers": ["set-cookie:.*laravel_session"],
        "meta": [],
        "html": [],
        "cookies": ["laravel_session", "XSRF-TOKEN"],
        "favicon": None,
    },
    "django": {
        "headers": ["x-frame-options: deny"],
        "meta": [],
        "html": ["csrfmiddlewaretoken", "__admin_media_prefix__"],
        "cookies": ["csrftoken", "sessionid"],
        "favicon": None,
    },
    "nginx": {
        "headers": ["server: nginx"],
        "meta": [],
        "html": ["nginx"],
        "cookies": [],
        "favicon": None,
    },
    "apache": {
        "headers": ["server: apache"],
        "meta": [],
        "html": [],
        "cookies": [],
        "favicon": None,
    },
}

# WordPress version patterns
WP_VERSION_PATTERNS = [
    r'content="WordPress\s+([\d.]+)"',
    r'ver=([\d.]+)',
    r'wp-includes/js/jquery/jquery\.min\.js\?ver=([\d.]+)',
    r'/wp-admin/load-scripts\.php\?.*ver=([\d.]+)',
]

# Joomla version patterns
JOOMLA_VERSION_PATTERNS = [
    r'<version>([\d.]+)</version>',
    r'Joomla!\s+([\d.]+)',
    r'/media/jui/js/.*\?ver=([\d.]+)',
]


def fingerprint_cms(response_text, response_headers, cookies=None):
    """Detect CMS from HTTP response (passive, no extra requests).
    
    Args:
        response_text: HTML body
        response_headers: dict of response headers
        cookies: dict of cookies (optional)
    
    Returns:
        dict with keys: cms, version, confidence, details
    """
    result = {
        "cms": "unknown",
        "version": "unknown",
        "confidence": 0,
        "details": {},
        "technologies": [],
    }
    
    headers_str = "\n".join(f"{k}: {v}" for k, v in response_headers.items()).lower()
    body_lower = response_text.lower() if response_text else ""
    cookies_str = " ".join(cookies.keys()).lower() if cookies else ""
    
    scores = {}
    
    for cms, sigs in CMS_SIGNATURES.items():
        score = 0
        matched = []
        
        # Check headers
        for pattern in sigs["headers"]:
            if re.search(pattern.lower(), headers_str):
                score += 30
                matched.append(f"header:{pattern}")
        
        # Check meta tags
        for pattern in sigs["meta"]:
            if re.search(pattern.lower(), body_lower):
                score += 25
                matched.append(f"meta:{pattern}")
        
        # Check HTML patterns
        for pattern in sigs["html"]:
            if pattern.lower() in body_lower:
                score += 20
                matched.append(f"html:{pattern}")
        
        # Check cookies
        for pattern in sigs["cookies"]:
            if pattern.lower() in cookies_str:
                score += 15
                matched.append(f"cookie:{pattern}")
        
        if score > 0:
            scores[cms] = {"score": score, "matched": matched}
    
    if scores:
        best_cms = max(scores, key=lambda k: scores[k]["score"])
        best_score = scores[best_cms]["score"]
        
        if best_score >= 20:
            result["cms"] = best_cms
            result["confidence"] = min(100, best_score)
            result["details"] = scores[best_cms]
            result["technologies"] = list(scores.keys())
            
            # Extract version
            if best_cms == "wordpress":
                result["version"] = _extract_wp_version(response_text)
            elif best_cms == "joomla":
                result["version"] = _extract_joomla_version(response_text)
    
    # Detect server
    server = response_headers.get("Server", "")
    if server:
        result["server"] = server
    
    # Detect PHP version
    powered_by = response_headers.get("X-Powered-By", "")
    if "PHP/" in powered_by:
        result["php_version"] = powered_by.replace("PHP/", "")
    
    # Detect additional technologies
    if "cloudflare" in headers_str or "cf-ray" in headers_str:
        result["technologies"].append("cloudflare")
    if "x-aspnet-version" in headers_str:
        result["technologies"].append("asp.net")
    if "x-powered-by: express" in headers_str:
        result["technologies"].append("express.js")
    
    return result


def _extract_wp_version(html):
    """Extract WordPress version from HTML."""
    if not html:
        return "unknown"
    
    for pattern in WP_VERSION_PATTERNS:
        m = re.search(pattern, html, re.I)
        if m:
            return m.group(1)
    
    return "unknown"


def _extract_joomla_version(html):
    """Extract Joomla version from HTML."""
    if not html:
        return "unknown"
    
    for pattern in JOOMLA_VERSION_PATTERNS:
        m = re.search(pattern, html, re.I)
        if m:
            return m.group(1)
    
    return "unknown"
def fingerprint_technologies(response_text, response_headers):
    """Detect additional technologies from response.
    
    Returns:
        list of detected technologies
    """
    techs = []
    
    headers_str = "\n".join(f"{k}: {v}" for k, v in response_headers.items()).lower()
    body_lower = response_text.lower() if response_text else ""
    
    # JavaScript frameworks
    js_frameworks = {
        "react": ["react.production.min.js", "data-reactroot"],
        "vue": ["vue.min.js", "vue.runtime", "data-v-"],
        "angular": ["angular.min.js", "ng-app", "ng-controller"],
        "jquery": ["jquery.min.js", "jquery-"],
        "bootstrap": ["bootstrap.min.css", "bootstrap.min.js"],
    }
    
    for tech, patterns in js_frameworks.items():
        if any(p in body_lower for p in patterns):
            techs.append(tech)
    
    # Analytics/Tracking
    analytics = {
        "google_analytics": ["google-analytics.com", "gtag/js", "ga.js"],
        "google_tag_manager": ["googletagmanager.com"],
        "facebook_pixel": ["connect.facebook.net", "fbq("],
        "yandex_metrika": ["mc.yandex.ru"],
    }
    
    for tech, patterns in analytics.items():
        if any(p in body_lower for p in patterns):
            techs.append(tech)
    
    # Security headers
    security_headers = {
        "hsts": "strict-transport-security",
        "csp": "content-security-policy",
        "x-frame-options": "x-frame-options",
        "x-content-type": "x-content-type-options",
    }
    
    for tech, header in security_headers.items():
        if header in headers_str:
            techs.append(f"header:{tech}")
    
    return techs


def generate_shodan_query(fingerprint_result):
    """Generate Shodan query from fingerprint result.
    
    Returns:
        str: Shodan query string
    """
    parts = []
    
    cms = fingerprint_result.get("cms", "unknown")
    version = fingerprint_result.get("version", "unknown")
    
    if cms != "unknown":
        if cms == "wordpress":
            parts.append('"X-Powered-By: WordPress"')
            if version != "unknown":
                parts.append(f'"WordPress {version}"')
        elif cms == "joomla":
            parts.append('"X-Content-Encoded-By: Joomla"')
        elif cms == "drupal":
            parts.append('"X-Generator: Drupal"')
    
    server = fingerprint_result.get("server", "")
    if server:
        parts.append(f'"Server: {server}"')
    
    return " ".join(parts) if parts else None