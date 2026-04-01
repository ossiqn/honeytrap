import logging
import os
from rich.console import Console
from rich.theme import Theme
from rich.logging import RichHandler
from colorama import init

init(autoreset=True)

custom_theme = Theme({
    "info": "cyan",
    "warning": "yellow",
    "error": "bold red",
    "critical": "bold white on red",
    "success": "bold green",
    "trap": "bold magenta",
    "attack": "bold red",
})

console = Console(theme=custom_theme)

BANNER = """
[bold red]
╔══════════════════════════════════════════════════════════════════════════╗
║                                                                          ║
║   ██╗  ██╗ ██████╗ ███╗   ██╗███████╗██╗   ██╗████████╗██████╗  █████╗ ██████╗  ║
║   ██║  ██║██╔═══██╗████╗  ██║██╔════╝╚██╗ ██╔╝╚══██╔══╝██╔══██╗██╔══██╗██╔══██╗ ║
║   ███████║██║   ██║██╔██╗ ██║█████╗   ╚████╔╝    ██║   ██████╔╝███████║██████╔╝ ║
║   ██╔══██║██║   ██║██║╚██╗██║██╔══╝    ╚██╔╝     ██║   ██╔══██╗██╔══██║██╔═══╝  ║
║   ██║  ██║╚██████╔╝██║ ╚████║███████╗   ██║      ██║   ██║  ██║██║  ██║██║      ║
║   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝   ╚═╝      ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝      ║
║                                                                          ║
║                    HoneyTrap Network v1.0.0                              ║
║              Advanced Honeypot & Threat Intelligence System              ║
║                                                                          ║
║   ┌───────────────────────────────────────────────────────────────┐     ║
║   │   Developed & Maintained by  ► ossiqn                         │     ║
║   │   Website                    ► ossiqn.com.tr                  │     ║
║   │   GitHub                     ► github.com/ossiqn              │     ║
║   │   License                    ► MIT © 2024 ossiqn              │     ║
║   └───────────────────────────────────────────────────────────────┘     ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝
[/bold red]
"""


def setup_logger(name: str, log_file: str = None, level: str = "INFO") -> logging.Logger:
    os.makedirs(os.path.dirname(log_file) if log_file and os.path.dirname(log_file) else "data", exist_ok=True)

    handlers = [RichHandler(console=console, rich_tracebacks=True, markup=True)]

    if log_file:
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(
            logging.Formatter("%(asctime)s | %(name)s | %(levelname)s | %(message)s | ossiqn")
        )
        handlers.append(file_handler)

    logging.basicConfig(
        level=getattr(logging, level.upper()),
        format="%(message)s",
        datefmt="[%X]",
        handlers=handlers,
        force=True
    )

    return logging.getLogger(name)


def print_banner():
    console.print(BANNER)
    console.print("[bold red]━━━━━━��━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/bold red]")
    console.print(
        "[red]  Status : [bold green]ONLINE[/bold green]  │  "
        "Mode   : [bold yellow]HONEYPOT ACTIVE[/bold yellow]  │  "
        "Owner  : [bold magenta]ossiqn[/bold magenta][/red]"
    )
    console.print(
        "[red]  Target : [bold white]INCOMING ATTACKERS[/bold white]  │  "
        "Build  : [bold white]v1.0.0[/bold white]  │  "
        "Site   : [bold white]ossiqn.com.tr[/bold white][/red]"
    )
    console.print("[bold red]━━━━━━��━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/bold red]\n")