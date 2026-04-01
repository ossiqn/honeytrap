import logging
import requests
from typing import Dict

logger = logging.getLogger("honeytrap.telegram")

SEVERITY_EMOJI = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🟢",
}

TRAP_EMOJI = {
    "http":  "🌐",
    "ssh":   "🔐",
    "ftp":   "📁",
    "smtp":  "📧",
    "tcp":   "🔌",
}


class TelegramNotifier:
    def __init__(self, config: Dict):
        self.bot_token = config.get("bot_token", "")
        self.chat_id   = config.get("chat_id", "")
        self.threshold = config.get("severity_threshold", "medium")
        self.severity_order = ["low", "medium", "high", "critical"]
        self.api_base  = f"https://api.telegram.org/bot{self.bot_token}"

    def _should_notify(self, severity: str) -> bool:
        try:
            return self.severity_order.index(severity) >= self.severity_order.index(self.threshold)
        except ValueError:
            return True

    def _send(self, text: str) -> bool:
        if not self.bot_token or not self.chat_id:
            return False
        try:
            response = requests.post(
                f"{self.api_base}/sendMessage",
                json={
                    "chat_id": self.chat_id,
                    "text": text[:4096],
                    "parse_mode": "HTML",
                    "disable_web_page_preview": True
                },
                timeout=10
            )
            return response.status_code == 200
        except Exception as e:
            logger.error(f"[ossiqn] Telegram send failed: {e}")
            return False

    def send_attack(self, attack: Dict) -> bool:
        severity = attack.get("severity", "low")
        if not self._should_notify(severity):
            return False

        trap_type = attack.get("trap_type", "unknown")
        emoji_sev  = SEVERITY_EMOJI.get(severity, "⚪")
        emoji_trap = TRAP_EMOJI.get(trap_type, "⚡")

        msg = (
            f"{emoji_sev} <b>HONEYTRAP ATTACK DETECTED</b> {emoji_trap}\n"
            f"{'━' * 32}\n"
            f"<b>Type     :</b> <code>{attack.get('attack_type', '').replace('_', ' ').upper()}</code>\n"
            f"<b>Severity :</b> <code>{severity.upper()}</code>\n"
            f"<b>Trap     :</b> <code>{trap_type.upper()}</code>\n"
            f"<b>IP       :</b> <code>{attack.get('attacker_ip', 'Unknown')}</code>\n"
            f"<b>Country  :</b> <code>{attack.get('country', 'Unknown')}</code>\n"
            f"<b>City     :</b> <code>{attack.get('city', 'Unknown')}</code>\n"
            f"<b>ISP      :</b> <code>{attack.get('isp', 'Unknown')}</code>\n"
            f"<b>Score    :</b> <code>{attack.get('threat_score', 0)}/100</code>\n"
            f"<b>VPN/Proxy:</b> <code>{'YES' if attack.get('is_vpn') else 'NO'}</code>\n"
        )

        if attack.get("username"):
            msg += f"<b>Username :</b> <code>{attack.get('username')}</code>\n"
        if attack.get("password"):
            msg += f"<b>Password :</b> <code>{attack.get('password')}</code>\n"
        if attack.get("endpoint"):
            msg += f"<b>Endpoint :</b> <code>{attack.get('endpoint')}</code>\n"
        if attack.get("payload"):
            preview = attack.get("payload", "")[:150]
            msg += f"<b>Payload  :</b>\n<code>{preview}</code>\n"

        msg += (
            f"\n<i>⏰ {attack.get('timestamp', '')[:19]}</i>\n"
            f"<i>🔧 HoneyTrap Network by ossiqn | ossiqn.com.tr</i>"
        )

        return self._send(msg)

    def send_summary(self, stats: Dict):
        msg = (
            f"📊 <b>HONEYTRAP DAILY SUMMARY</b>\n"
            f"{'━' * 32}\n"
            f"<b>Total Attacks  :</b> {stats.get('total', 0)}\n"
            f"<b>Unique IPs     :</b> {stats.get('unique_ips', 0)}\n"
            f"<b>Last 24h       :</b> {stats.get('recent_24h', 0)}\n"
            f"<b>IOC Count      :</b> {stats.get('ioc_count', 0)}\n\n"
            f"🔴 Critical : {stats.get('severity_counts', {}).get('critical', 0)}\n"
            f"🟠 High     : {stats.get('severity_counts', {}).get('high', 0)}\n"
            f"🟡 Medium   : {stats.get('severity_counts', {}).get('medium', 0)}\n"
            f"🟢 Low      : {stats.get('severity_counts', {}).get('low', 0)}\n\n"
            f"<i>🔧 HoneyTrap Network by ossiqn | ossiqn.com.tr</i>"
        )
        self._send(msg)