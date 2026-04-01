🍯 HoneyTrap Network
Advanced Honeypot & Threat Intelligence System
Developed & Maintained by ossiqn

What is HoneyTrap Network?
HoneyTrap Network is a fully automated honeypot system that lures attackers into fake services, captures everything they do, and reports it in real time via a sleek dark-themed web dashboard, Discord and Telegram.

Deploy it. Watch attackers walk in. Collect their IPs, credentials, payloads and TTPs. Export IOC lists. All automated.

✨ Features
Feature	Description
🌐 HTTP Trap	Fake API endpoints, admin panels, .env, phpMyAdmin, WordPress login, GraphQL
🔐 SSH Trap	Fake SSH server that captures every brute force attempt and command
📁 FTP Trap	Fake FTP server with fake sensitive files, logs credentials and downloads
🔌 TCP Trap	Emulates MySQL, PostgreSQL, Redis, MongoDB, Elasticsearch, Jupyter ports
🌍 GeoIP	Real-time attacker geolocation — country, city, ISP, ASN
🧬 IOC Export	Auto-generates IOC lists from attacker IPs, payloads, credentials
🗺️ Attack Map	Visual world map of incoming attacks
🔥 Threat Score	Automatic threat scoring per attacker (VPN/proxy/hosting detection)
🚫 Auto Blacklist	Automatically blacklists IPs exceeding attack threshold
💬 Discord Alerts	Real-time webhook notifications with full attack details
📱 Telegram Alerts	Instant bot notifications for every captured attack
🖥️ Web Dashboard	Live dark terminal-themed dashboard with CRT scanline effect
🐳 Docker Ready	Single command deployment
📊 SQLite DB	All attacks, IOCs and sessions stored locally
🚀 Quick Start
With Docker (Recommended)
Bash

git clone https://github.com/ossiqn/honeytrap
cd honeytrap
cp .env.example .env
nano .env
docker-compose up -d
Manual
Bash

git clone https://github.com/ossiqn/honeytrap
cd honeytrap
pip install -r requirements.txt
cp .env.example .env
python src/main.py
Web Dashboard
text

http://localhost:5000
⚙️ Configuration
env

DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...
TELEGRAM_BOT_TOKEN=1234567890:AAxxxxxxxxx
TELEGRAM_CHAT_ID=-1001234567890
🪤 Trap Details
HTTP Trap :8080
Deploys a fully functional fake web server with endpoints that look real to attackers:

text

/api/login        → Captures credentials, returns fake JWT token
/api/admin        → Returns fake admin panel with user data
/api/config       → Returns fake AWS keys, DB passwords, API keys
/.env             → Returns realistic fake environment file
/wp-admin         → Fake WordPress login
/phpmyadmin       → Fake phpMyAdmin
/graphql          → Fake GraphQL with schema introspection
/shell, /console  → Captures RCE attempts
/backup           → Triggers fake file download
SSH Trap :2222
text

Captures every login attempt (username + password)
Logs every command executed after fake login
Returns realistic shell responses (ls, whoami, cat /etc/passwd...)
FTP Trap :2121
text

Lists fake sensitive files (passwords.txt, database.sql, secrets.txt)
Captures credentials on login
Logs every file download attempt
TCP Traps
text

:3306  → MySQL
:5432  → PostgreSQL
:6379  → Redis
:27017 → MongoDB
:9200  → Elasticsearch
:8888  → Jupyter Notebook
:4444  → Backdoor listener
📊 Web Dashboard
text

⚡ Live Attack Feed      — Real-time incoming attacks
🧬 IOC List             — All collected indicators of compromise
🗺️  Attack Map           — Geographic visualization
🚫 Blacklist Manager    — View and manage blocked IPs
🔍 Filter by Trap/Severity
📤 Export IOC as JSON
🔔 Notification Example
Discord:

text

🔴 SSH TRAP — CRITICAL
━━━━━━━━━━━━━━━━━━━━━━━
🎯 Severity   : CRITICAL
🪤 Trap       : SSH
🌍 Country    : Russia
🖥️ IP         : 185.xxx.xxx.xxx
🔥 Score      : 85/100
🔒 VPN/Proxy  : YES
👤 Username   : root
🔑 Password   : toor123
🛠️ Tech Stack
text

Language    : Python 3.11+
Web         : Flask + Threaded
SSH         : Paramiko
Database    : SQLite + SQLAlchemy
GeoIP       : ip-api.com
Notifications: Discord Webhook + Telegram Bot API
Frontend    : Vanilla JS + CSS3
Container   : Docker + Docker Compose
License     : MIT © 2024 ossiqn
📁 Project Structure
text

honeytrap/
├── src/
│   ├── main.py
│   ├── traps/
│   │   ├── http_trap.py
│   │   ├── ssh_trap.py
│   │   ├── ftp_trap.py
│   │   └── tcp_trap.py
│   ├── core/
│   │   ├── db.py
│   │   ├── geoip.py
│   │   └── ioc.py
│   ├── notifier/
│   │   ├── discord.py
│   │   └── telegram.py
│   └── web/
│       ├── app.py
│       ├── templates/
│       └── static/
├── config.yml
├── docker-compose.yml
└── requirements.txt
⚠️ Legal Disclaimer
This tool is designed for defensive security research only.

✅ Use on systems you own
✅ Use in authorized penetration testing
✅ Use for threat intelligence research
✅ Use for educational purposes
❌ Do NOT deploy against systems without explicit permission
Unauthorized use may violate local and international computer crime laws.

👤 Developer
ossiqn

🌐 Website: ossiqn.com.tr
🐙 GitHub: github.com/ossiqn
📜 License
MIT License — © 2024 ossiqn. All rights reserved.

Developed by ossiqn as a contribution to the global InfoSec community.
If this project helped you, consider giving it a ⭐ on GitHub.
