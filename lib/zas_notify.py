"""
ZAS Notifications — Telegram/Slack/Discord/Email alerts for scan results.
Sends real-time notifications when vulnerabilities are found.
"""

import json
import html as _html
import urllib.request
import urllib.parse
import ssl
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


def _ssl_context(verify=True):
    """Build SSL context for outbound notifications."""
    if verify:
        return ssl.create_default_context()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _esc(value):
    """HTML-escape for Telegram parse_mode=HTML."""
    return _html.escape(str(value if value is not None else ""), quote=True)


def _urlopen(req, timeout=15):
    """urlopen with SSL verify respecting zas_core.ignore_ssl setting."""
    verify = True
    try:
        from zas_core import get_verify
        verify = get_verify()
    except Exception:
        pass
    return urllib.request.urlopen(req, timeout=timeout, context=_ssl_context(verify))


class TelegramNotifier:
    """Send notifications via Telegram Bot API."""
    
    def __init__(self, bot_token=None, chat_id=None):
        self.bot_token = bot_token
        self.chat_id = chat_id
        self.base_url = f"https://api.telegram.org/bot{bot_token}" if bot_token else None
    
    def send(self, message, parse_mode="HTML"):
        """Send message to Telegram.
        
        Args:
            message: message text
            parse_mode: HTML or Markdown
        
        Returns:
            dict with status
        """
        if not self.bot_token or not self.chat_id:
            return {"ok": False, "error": "Not configured"}
        
        url = f"{self.base_url}/sendMessage"
        data = json.dumps({
            "chat_id": self.chat_id,
            "text": message,
            "parse_mode": parse_mode,
            "disable_web_page_preview": True,
        }).encode()
        
        try:
            req = urllib.request.Request(url, data=data, headers={
                "Content-Type": "application/json",
                "User-Agent": "ZAS/5.1",
            })
            resp = _urlopen(req, timeout=15)
            result = json.loads(resp.read().decode())
            return {"ok": True, "message_id": result.get("result", {}).get("message_id")}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def send_vuln_alert(self, cve, url, status, details=None):
        """Send vulnerability alert.

        Args:
            cve: CVE identifier
            url: target URL
            status: exploit status
            details: additional details
        """
        emoji = "🔴" if status == "exploited" else "🟡" if status == "vulnerable" else "⚪"

        message = f"""
{emoji} <b>ZAS Alert</b>

<b>CVE:</b> <code>{_esc(cve)}</code>
<b>URL:</b> <code>{_esc(url)}</code>
<b>Status:</b> {_esc(str(status).upper())}
"""
        if details:
            if details.get("shell_url"):
                message += f"<b>Shell:</b> <code>{_esc(details['shell_url'])}</code>\n"
            if details.get("output"):
                message += f"<b>Output:</b> <code>{_esc(details['output'][:200])}</code>\n"

        return self.send(message)
    
    def send_scan_summary(self, stats):
        """Send scan summary notification.
        
        Args:
            stats: dict with scan statistics
        """
        message = f"""
📊 <b>ZAS Scan Complete</b>

<b>Targets:</b> {stats.get('total', 0)}
<b>Vulnerable:</b> {stats.get('vuln', 0)}
<b>Exploited:</b> {stats.get('exploited', 0)}
<b>Errors:</b> {stats.get('errors', 0)}
<b>Duration:</b> {stats.get('duration', 'N/A')}
"""
        return self.send(message)
    
    def send_creds_alert(self, url, creds_count, cred_types):
        """Send credential harvest alert.
        
        Args:
            url: target URL
            creds_count: number of credentials found
            cred_types: list of credential types
        """
        message = f"""
🔑 <b>Credentials Found</b>

<b>Target:</b> <code>{_esc(url)}</code>
<b>Count:</b> {creds_count}
<b>Types:</b> {_esc(', '.join(cred_types))}
"""
        return self.send(message)


class SlackNotifier:
    """Send notifications via Slack Webhook."""
    
    def __init__(self, webhook_url=None):
        self.webhook_url = webhook_url
    
    def send(self, message, channel=None, username="ZAS"):
        """Send message to Slack.
        
        Args:
            message: message text
            channel: channel name (optional)
            username: bot username
        
        Returns:
            dict with status
        """
        if not self.webhook_url:
            return {"ok": False, "error": "Not configured"}
        
        data = {
            "text": message,
            "username": username,
        }
        if channel:
            data["channel"] = channel
        
        try:
            req = urllib.request.Request(
                self.webhook_url,
                data=json.dumps(data).encode(),
                headers={"Content-Type": "application/json"},
            )
            resp = _urlopen(req, timeout=15)
            return {"ok": True}
        except Exception as e:
            return {"ok": False, "error": str(e)}
    
    def send_vuln_alert(self, cve, url, status, details=None):
        """Send vulnerability alert."""
        emoji = ":red_circle:" if status == "exploited" else ":yellow_circle:" if status == "vulnerable" else ":white_circle:"
        
        blocks = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": f"{emoji} ZAS Alert"}
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*CVE:*\n`{cve}`"},
                    {"type": "mrkdwn", "text": f"*Status:*\n{status.upper()}"},
                ]
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*URL:*\n`{url}`"}
            },
        ]
        
        if details and details.get("shell_url"):
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Shell:*\n`{details['shell_url']}`"}
            })
        
        data = {"blocks": blocks}
        
        try:
            req = urllib.request.Request(
                self.webhook_url,
                data=json.dumps(data).encode(),
                headers={"Content-Type": "application/json"},
            )
            resp = _urlopen(req, timeout=15)
            return {"ok": True}
        except Exception as e:
            return {"ok": False, "error": str(e)}


class DiscordNotifier:
    """Send notifications via Discord Webhook."""
    
    def __init__(self, webhook_url=None):
        self.webhook_url = webhook_url
    
    def send(self, message, username="ZAS"):
        """Send message to Discord.
        
        Args:
            message: message text
            username: bot username
        
        Returns:
            dict with status
        """
        if not self.webhook_url:
            return {"ok": False, "error": "Not configured"}
        
        data = {
            "content": message,
            "username": username,
        }
        
        try:
            req = urllib.request.Request(
                self.webhook_url,
                data=json.dumps(data).encode(),
                headers={"Content-Type": "application/json"},
            )
            resp = _urlopen(req, timeout=15)
            return {"ok": True}
        except Exception as e:
            return {"ok": False, "error": str(e)}
    
    def send_vuln_alert(self, cve, url, status, details=None):
        """Send vulnerability alert with embed."""
        color = 0xFF0000 if status == "exploited" else 0xFFFF00 if status == "vulnerable" else 0x808080
        
        embed = {
            "title": "ZAS Alert",
            "color": color,
            "fields": [
                {"name": "CVE", "value": f"`{cve}`", "inline": True},
                {"name": "Status", "value": status.upper(), "inline": True},
                {"name": "URL", "value": f"`{url}`", "inline": False},
            ],
        }
        
        if details and details.get("shell_url"):
            embed["fields"].append({"name": "Shell", "value": f"`{details['shell_url']}`", "inline": False})
        
        data = {"embeds": [embed]}
        
        try:
            req = urllib.request.Request(
                self.webhook_url,
                data=json.dumps(data).encode(),
                headers={"Content-Type": "application/json"},
            )
            resp = _urlopen(req, timeout=15)
            return {"ok": True}
        except Exception as e:
            return {"ok": False, "error": str(e)}


class EmailNotifier:
    """Send notifications via email (SMTP)."""
    
    def __init__(self, smtp_host=None, smtp_port=587, username=None, password=None, from_addr=None, to_addr=None):
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.username = username
        self.password = password
        self.from_addr = from_addr
        self.to_addr = to_addr
    
    def send(self, subject, message):
        """Send email notification.
        
        Args:
            subject: email subject
            message: email body
        
        Returns:
            dict with status
        """
        if not all([self.smtp_host, self.username, self.password, self.from_addr, self.to_addr]):
            return {"ok": False, "error": "Not configured"}
        
        try:
            msg = MIMEMultipart()
            msg["From"] = self.from_addr
            msg["To"] = self.to_addr
            msg["Subject"] = subject
            
            msg.attach(MIMEText(message, "plain"))
            
            server = smtplib.SMTP(self.smtp_host, self.smtp_port)
            server.starttls()
            server.login(self.username, self.password)
            server.send_message(msg)
            server.quit()
            
            return {"ok": True}
        except Exception as e:
            return {"ok": False, "error": str(e)}
    
    def send_vuln_alert(self, cve, url, status, details=None):
        """Send vulnerability alert email."""
        subject = f"[ZAS] {status.upper()}: {cve} @ {url}"
        
        message = f"ZAS Alert\n\n"
        message += f"CVE: {cve}\n"
        message += f"URL: {url}\n"
        message += f"Status: {status.upper()}\n"
        
        if details:
            if details.get("shell_url"):
                message += f"Shell: {details['shell_url']}\n"
            if details.get("output"):
                message += f"Output: {details['output'][:500]}\n"
        
        return self.send(subject, message)


class NotificationManager:
    """Manage multiple notification channels."""
    
    def __init__(self):
        self.channels = {}
    
    def add_telegram(self, bot_token, chat_id):
        """Add Telegram notification channel."""
        self.channels["telegram"] = TelegramNotifier(bot_token, chat_id)
    
    def add_slack(self, webhook_url):
        """Add Slack notification channel."""
        self.channels["slack"] = SlackNotifier(webhook_url)
    
    def add_discord(self, webhook_url):
        """Add Discord notification channel."""
        self.channels["discord"] = DiscordNotifier(webhook_url)
    
    def add_email(self, smtp_host, smtp_port, username, password, from_addr, to_addr):
        """Add Email notification channel."""
        self.channels["email"] = EmailNotifier(smtp_host, smtp_port, username, password, from_addr, to_addr)
    
    def notify_vuln(self, cve, url, status, details=None):
        """Send vulnerability notification to all channels.
        
        Returns:
            dict with results per channel
        """
        results = {}
        for name, notifier in self.channels.items():
            results[name] = notifier.send_vuln_alert(cve, url, status, details)
        return results
    
    def notify_scan_complete(self, stats):
        """Send scan completion notification to all channels.
        
        Returns:
            dict with results per channel
        """
        results = {}
        for name, notifier in self.channels.items():
            if hasattr(notifier, "send_scan_summary"):
                results[name] = notifier.send_scan_summary(stats)
        return results
    
    def notify_creds(self, url, creds_count, cred_types):
        """Send credential harvest notification to all channels.
        
        Returns:
            dict with results per channel
        """
        results = {}
        for name, notifier in self.channels.items():
            if hasattr(notifier, "send_creds_alert"):
                results[name] = notifier.send_creds_alert(url, creds_count, cred_types)
        return results
    
    def get_configured_channels(self):
        """Get list of configured notification channels.
        
        Returns:
            list of channel names
        """
        return list(self.channels.keys())