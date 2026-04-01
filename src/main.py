import os
import sys
import time
import yaml
import signal
import logging
import threading
import schedule
from datetime import datetime
from dotenv import load_dotenv

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.logger import setup_logger, print_banner, console
from core.db import Database
from core.geoip import GeoIP
from core.ioc import IOCManager
from traps.http_trap import HTTPTrap
from traps.ssh_trap import SSHTrap
from traps.ftp_trap import FTPTrap
from traps.tcp_trap import TCPTrap
from notifier.discord import DiscordNotifier
from notifier.telegram import TelegramNotifier
from web.app import init_web, run_web

load_dotenv()

PRODUCER = "ossiqn"
TOOL     = "HoneyTrap Network"
VERSION  = "1.0.0"

shutdown_event = threading.Event()


def load_config(path: str = "config.yml") -> dict:
    paths = [path, os.path.join(os.path.dirname(__file__), "..", path), "/app/config.yml"]
    for p in paths:
        if os.path.exists(p):
            with open(p) as f:
                return yaml.safe_load(f)
    return {}


def signal_handler(signum, frame):
    console.print(f"\n[bold red]⚠ [{PRODUCER}] Shutdown signal received. Stopping {TOOL}...[/bold red]")
    shutdown_event.set()


def main():
    signal.signal(signal.SIGINT,  signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    print_banner()

    config = load_config()

    log_cfg = config.get("logging", {})
    logger  = setup_logger("honeytrap", log_cfg.get("file", "data/honeytrap.log"), log_cfg.get("level", "INFO"))
    logger.info(f"{TOOL} v{VERSION} starting | produced by {PRODUCER}")

    db  = Database(config.get("database", {}).get("path", "data/honeytrap.db"))
    logger.info(f"[{PRODUCER}] Database initialized")

    geo = GeoIP(config.get("honeytrap", {}).get("geoip", {}))
    logger.info(f"[{PRODUCER}] GeoIP initialized")

    ioc = IOCManager(db, config.get("honeytrap", {}))
    logger.info(f"[{PRODUCER}] IOC Manager initialized")

    notifier = None
    discord_cfg  = config.get("notifications", {}).get("discord", {})
    telegram_cfg = config.get("notifications", {}).get("telegram", {})

    discord_wh  = os.environ.get("DISCORD_WEBHOOK_URL", discord_cfg.get("webhook_url", ""))
    telegram_tk = os.environ.get("TELEGRAM_BOT_TOKEN",  telegram_cfg.get("bot_token", ""))
    telegram_ci = os.environ.get("TELEGRAM_CHAT_ID",    telegram_cfg.get("chat_id", ""))

    discord_notifier  = None
    telegram_notifier = None

    if discord_wh:
        discord_cfg["webhook_url"] = discord_wh
        discord_notifier = DiscordNotifier(discord_cfg)
        console.print(f"[bold green]✓ [{PRODUCER}] Discord notifications ready[/bold green]")

    if telegram_tk and telegram_ci:
        telegram_cfg["bot_token"] = telegram_tk
        telegram_cfg["chat_id"]   = telegram_ci
        telegram_notifier = TelegramNotifier(telegram_cfg)
        console.print(f"[bold green]✓ [{PRODUCER}] Telegram notifications ready[/bold green]")

    class CombinedNotifier:
        def send_attack(self, attack):
            if discord_notifier:
                discord_notifier.send_attack(attack)
            if telegram_notifier:
                telegram_notifier.send_attack(attack)

        def send_summary(self, stats):
            if discord_notifier:
                discord_notifier.send_summary(stats)
            if telegram_notifier:
                telegram_notifier.send_summary(stats)

    notifier = CombinedNotifier()

    trap_config  = config.get("honeytrap", {}).get("traps", {})
    trap_status  = {
        "running":    True,
        "traps":      {},
        "started_at": datetime.utcnow().isoformat(),
        "produced_by": PRODUCER
    }

    traps = []

    if trap_config.get("http", {}).get("enabled", True):
        http_trap = HTTPTrap(trap_config["http"], db, geo, ioc, notifier)
        http_trap.start()
        trap_status["traps"]["http"] = "active"
        traps.append(http_trap)
        console.print(f"[bold green]✓ [{PRODUCER}] HTTP Trap active on port {trap_config['http'].get('port', 8080)}[/bold green]")

    if trap_config.get("ssh", {}).get("enabled", True):
        ssh_trap = SSHTrap(trap_config["ssh"], db, geo, ioc, notifier)
        ssh_trap.start()
        trap_status["traps"]["ssh"] = "active"
        traps.append(ssh_trap)
        console.print(f"[bold green]✓ [{PRODUCER}] SSH Trap active on port {trap_config['ssh'].get('port', 2222)}[/bold green]")

    if trap_config.get("ftp", {}).get("enabled", True):
        ftp_trap = FTPTrap(trap_config["ftp"], db, geo, ioc, notifier)
        ftp_trap.start()
        trap_status["traps"]["ftp"] = "active"
        traps.append(ftp_trap)
        console.print(f"[bold green]✓ [{PRODUCER}] FTP Trap active on port {trap_config['ftp'].get('port', 2121)}[/bold green]")

    if trap_config.get("tcp", {}).get("enabled", True):
        tcp_trap = TCPTrap(trap_config["tcp"], db, geo, ioc, notifier)
        tcp_trap.start()
        trap_status["traps"]["tcp"] = "active"
        traps.append(tcp_trap)
        console.print(f"[bold green]✓ [{PRODUCER}] TCP Traps active on {trap_config['tcp'].get('ports', [])}[/bold green]")

    web_cfg = config.get("web", {})
    if web_cfg.get("enabled", True):
        init_web(db, ioc, trap_status)
        threading.Thread(
            target=run_web,
            kwargs={"host": web_cfg.get("host", "0.0.0.0"), "port": web_cfg.get("port", 5000), "debug": False},
            daemon=True,
            name="WebServer"
        ).start()
        console.print(f"[bold green]✓ [{PRODUCER}] Web dashboard at http://localhost:{web_cfg.get('port', 5000)}[/bold green]")

    def daily_summary():
        stats = db.get_stats()
        notifier.send_summary(stats)
        logger.info(f"[{PRODUCER}] Daily summary sent")

    schedule.every().day.at("09:00").do(daily_summary)

    def scheduler_loop():
        while not shutdown_event.is_set():
            schedule.run_pending()
            time.sleep(1)

    threading.Thread(target=scheduler_loop, daemon=True, name="Scheduler").start()

    console.print(f"\n[bold red]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/bold red]")
    console.print(f"[bold green]✓ {TOOL} fully operational | {PRODUCER} | ossiqn.com.tr[/bold green]")
    console.print(f"[bold red]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/bold red]\n")
    console.print(f"[red]Press Ctrl+C to stop. | {PRODUCER} | ossiqn.com.tr[/red]\n")

    logger.info(f"[{PRODUCER}] {TOOL} fully operational. All traps active.")

    shutdown_event.wait()

    trap_status["running"] = False
    logger.info(f"[{PRODUCER}] {TOOL} shutdown complete.")
    console.print(f"\n[bold red]{TOOL} stopped | Produced by {PRODUCER}[/bold red]")
    sys.exit(0)


if __name__ == "__main__":
    main()