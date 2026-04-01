import logging
from typing import Dict, List
from discord_webhook import DiscordWebhook, DiscordEmbed

logger = logging.getLogger("honeytrap.discord")

SEVERITY_COLORS = {"critical": 0xFF0000, "high": 0xFF6600, "medium": 0xFFAA00, "low": 0x00FF88}
TRAP_EMOJI      = {"http": "🌐", "ssh": "🔐", "ftp": "📁", "smtp": "📧", "tcp": "🔌"}
SEVERITY_EMOJI  = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}


class DiscordNotifier:
    def __init__(self, config: Dict):
        self.webhook_url    = config.get("webhook_url", "")
        self.threshold      = config.get("severity_threshold", "medium")
        self.severity_order = ["low", "medium", "high", "critical"]

    def _should_notify(self, severity: str) -> bool:
        try:
            return self.severity_order.index(severity) >= self.severity_order.index(self.threshold)
        except ValueError:
            return True

    def send_attack(self, attack: Dict) -> bool:
        if not self.webhook_url:
            return False
        severity = attack.get("severity", "low")
        if not self._should_notify(severity):
            return False
        try:
            webhook   = DiscordWebhook(url=self.webhook_url, rate_limit_retry=True)
            trap_type = attack.get("trap_type", "unknown")
            embed     = DiscordEmbed(
                title=f"{SEVERITY_EMOJI.get(severity,'⚪')} {TRAP_EMOJI.get(trap_type,'⚡')} HoneyTrap Attack Detected",
                description=f"**{attack.get('attack_type','').replace('_',' ').upper()}**",
                color=SEVERITY_COLORS.get(severity, 0x888888)
            )
            embed.add_embed_field(name="🎯 Severity",     value=f"`{severity.upper()}`",                        inline=True)
            embed.add_embed_field(name="🪤 Trap",         value=f"`{trap_type.upper()}`",                       inline=True)
            embed.add_embed_field(name="🌍 Country",      value=f"`{attack.get('country','Unknown')}`",          inline=True)
            embed.add_embed_field(name="🖥️ IP",           value=f"`{attack.get('attacker_ip','Unknown')}`",     inline=True)
            embed.add_embed_field(name="🏙️ City",         value=f"`{attack.get('city','Unknown')}`",            inline=True)
            embed.add_embed_field(name="📡 ISP",          value=f"`{attack.get('isp','Unknown')}`",             inline=True)
            embed.add_embed_field(name="🔥 Score",        value=f"`{attack.get('threat_score',0)}/100`",        inline=True)
            embed.add_embed_field(name="🔒 VPN",          value=f"`{'YES' if attack.get('is_vpn') else 'NO'}`", inline=True)
            if attack.get("username"):
                embed.add_embed_field(name="👤 Username", value=f"`{attack.get('username')}`", inline=True)
            if attack.get("password"):
                embed.add_embed_field(name="🔑 Password", value=f"`{attack.get('password')}`", inline=True)
            if attack.get("endpoint"):
                embed.add_embed_field(name="🔗 Endpoint", value=f"`{attack.get('endpoint')}`", inline=False)
            if attack.get("payload"):
                embed.add_embed_field(name="📦 Payload",  value=f"```{attack.get('payload','')[:200]}```", inline=False)
            embed.set_footer(text="HoneyTrap Network — ossiqn | ossiqn.com.tr")
            embed.set_timestamp()
            webhook.add_embed(embed)
            webhook.execute()
            return True
        except Exception as e:
            logger.error(f"[ossiqn] Discord notification failed: {e}")
            return False

    def send_summary(self, stats: Dict):
        if not self.webhook_url:
            return
        try:
            webhook = DiscordWebhook(url=self.webhook_url, rate_limit_retry=True)
            embed   = DiscordEmbed(title="📊 HoneyTrap Network — Daily Summary",
                                   description=f"Total attacks: **{stats.get('total',0)}**", color=0x00AAFF)
            embed.add_embed_field(name="🖥️ Unique IPs", value=str(stats.get("unique_ips",0)),  inline=True)
            embed.add_embed_field(name="⏱️ Last 24h",   value=str(stats.get("recent_24h",0)),  inline=True)
            embed.add_embed_field(name="🧬 IOCs",        value=str(stats.get("ioc_count",0)),   inline=True)
            embed.add_embed_field(name="🔴 Critical",    value=str(stats.get("severity_counts",{}).get("critical",0)), inline=True)
            embed.add_embed_field(name="🟠 High",        value=str(stats.get("severity_counts",{}).get("high",0)),     inline=True)
            embed.add_embed_field(name="🟡 Medium",      value=str(stats.get("severity_counts",{}).get("medium",0)),   inline=True)
            embed.set_footer(text="HoneyTrap Network — ossiqn | ossiqn.com.tr")
            embed.set_timestamp()
            webhook.add_embed(embed)
            webhook.execute()
        except Exception as e:
            logger.error(f"[ossiqn] Discord summary failed: {e}")
