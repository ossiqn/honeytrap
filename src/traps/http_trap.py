import json
import logging
import threading
import hashlib
import random
import string
from datetime import datetime
from flask import Flask, request, jsonify, Response

logger = logging.getLogger("honeytrap.http")

FAKE_TOKENS = [
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoic3VwZXJhZG1pbiJ9.fake",
    "sk-proj-fakeopenaikey1234567890abcdefghijklmnop",
    "ghp_fakeGitHubToken1234567890abcdefghijk",
    "AKIAFAKEAWSACCESSKEYID",
]

FAKE_USERS = [
    {"id": 1, "username": "admin", "email": "admin@company.com", "role": "superadmin", "password_hash": "5f4dcc3b5aa765d61d8327deb882cf99"},
    {"id": 2, "username": "john.doe", "email": "john@company.com", "role": "user", "password_hash": "482c811da5d5b4bc6d497ffa98491e38"},
    {"id": 3, "username": "jane.smith", "email": "jane@company.com", "role": "manager", "password_hash": "d8578edf8458ce06fbc5bb76a58c5ca4"},
]

FAKE_CONFIG = {
    "database": {
        "host": "192.168.1.100",
        "port": 5432,
        "name": "production_db",
        "username": "postgres",
        "password": "Sup3rS3cur3P@ss!"
    },
    "aws": {
        "access_key": "AKIAFAKEAWSACCESSKEYID",
        "secret_key": "fakeAWSSecretKey1234567890abcdefghijk",
        "region": "us-east-1",
        "bucket": "company-production-data"
    },
    "api_keys": {
        "stripe": "sk_live_fakeStripeKeyForHoneypot1234567890",
        "sendgrid": "SG.fakeKey.fakeKey1234567890abcdefghijk",
        "openai": "sk-fakeOpenAIKey1234567890abcdefghijklmnop"
    }
}


class HTTPTrap:
    def __init__(self, config: Dict, db, geoip, ioc_manager, notifier):
        self.config = config
        self.db = db
        self.geoip = geoip
        self.ioc_manager = ioc_manager
        self.notifier = notifier
        self.app = Flask(f"honeytrap_http_{config.get('port', 8080)}")
        self.port = config.get("port", 8080)
        self._setup_routes()

    def _get_attacker_info(self) -> Dict:
        ip = request.headers.get("X-Forwarded-For", request.remote_addr)
        if ip and "," in ip:
            ip = ip.split(",")[0].strip()

        geo = self.geoip.lookup(ip)
        threat_score = self.geoip.get_threat_score(ip)

        return {
            "ip": ip,
            "geo": geo,
            "threat_score": threat_score,
            "is_blacklisted": self.db.is_blacklisted(ip)
        }

    def _log_attack(self, attacker_info: Dict, attack_type: str,
                    endpoint: str, payload: str = "", severity: str = "medium",
                    username: str = "", password: str = ""):
        geo = attacker_info.get("geo", {})

        attack = {
            "timestamp": datetime.utcnow().isoformat(),
            "trap_type": "http",
            "attacker_ip": attacker_info.get("ip", ""),
            "attacker_port": request.environ.get("REMOTE_PORT", 0),
            "country": geo.get("country", "Unknown"),
            "city": geo.get("city", "Unknown"),
            "latitude": geo.get("latitude", 0.0),
            "longitude": geo.get("longitude", 0.0),
            "isp": geo.get("isp", "Unknown"),
            "asn": geo.get("asn", "Unknown"),
            "severity": severity,
            "attack_type": attack_type,
            "payload": payload[:2000] if payload else "",
            "username": username,
            "password": password,
            "endpoint": endpoint,
            "headers": dict(request.headers),
            "user_agent": request.headers.get("User-Agent", ""),
            "is_vpn": geo.get("is_proxy", False),
            "threat_score": attacker_info.get("threat_score", 0),
            "raw_data": {
                "method": request.method,
                "args": dict(request.args),
                "form": dict(request.form),
                "json": request.get_json(silent=True),
                "produced_by": "ossiqn"
            }
        }

        attack_id = self.db.insert_attack(attack)
        attack["id"] = attack_id

        self.ioc_manager.process_attack(attack)

        logger.warning(
            f"[ossiqn HTTP] {severity.upper()} | {attack_type} | "
            f"{attacker_info.get('ip')} ({geo.get('country')}) | {endpoint}"
        )

        if self.notifier:
            self.notifier.send_attack(attack)

        return attack

    def _setup_routes(self):
        @self.app.route("/api/login", methods=["GET", "POST"])
        def fake_login():
            attacker = self._get_attacker_info()
            data = request.get_json(silent=True) or {}
            username = data.get("username", request.form.get("username", ""))
            password = data.get("password", request.form.get("password", ""))

            self._log_attack(
                attacker, "credential_harvesting", "/api/login",
                payload=json.dumps(data),
                severity="high",
                username=username,
                password=password
            )

            fake_token = random.choice(FAKE_TOKENS)
            return jsonify({
                "success": True,
                "token": fake_token,
                "user": {"id": 1, "username": username or "admin", "role": "admin"},
                "expires_in": 86400
            }), 200

        @self.app.route("/api/admin", methods=["GET", "POST"])
        def fake_admin():
            attacker = self._get_attacker_info()
            self._log_attack(attacker, "admin_panel_access", "/api/admin", severity="high")
            return jsonify({
                "panel": "Admin Control Panel",
                "version": "2.4.1",
                "users": FAKE_USERS,
                "server_info": {
                    "os": "Ubuntu 22.04 LTS",
                    "hostname": "prod-server-01",
                    "uptime": "15 days"
                }
            }), 200

        @self.app.route("/api/users", methods=["GET"])
        def fake_users():
            attacker = self._get_attacker_info()
            self._log_attack(attacker, "data_exfiltration", "/api/users", severity="medium")
            return jsonify({"users": FAKE_USERS, "total": len(FAKE_USERS)}), 200

        @self.app.route("/api/config", methods=["GET"])
        def fake_config():
            attacker = self._get_attacker_info()
            self._log_attack(attacker, "config_exfiltration", "/api/config", severity="critical")
            return jsonify(FAKE_CONFIG), 200

        @self.app.route("/api/keys", methods=["GET"])
        def fake_keys():
            attacker = self._get_attacker_info()
            self._log_attack(attacker, "api_key_theft", "/api/keys", severity="critical")
            return jsonify({
                "keys": {
                    "api_key": "".join(random.choices(string.ascii_letters + string.digits, k=40)),
                    "secret": "".join(random.choices(string.ascii_letters + string.digits, k=64)),
                    "webhook": "https://hooks.slack.com/services/FAKE/FAKE/fakeWebhookKey"
                }
            }), 200

        @self.app.route("/.env", methods=["GET"])
        def fake_env():
            attacker = self._get_attacker_info()
            self._log_attack(attacker, "env_file_access", "/.env", severity="critical")
            env_content = """APP_ENV=production
APP_KEY=base64:fakeAppKeyForHoneypotDoNotUse1234567890abc=
DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=production_db
DB_USERNAME=root
DB_PASSWORD=Sup3rS3cur3DBP@ss!
AWS_ACCESS_KEY_ID=AKIAFAKEAWSACCESSKEYID
AWS_SECRET_ACCESS_KEY=fakeAWSSecretKeyForHoneypot1234567890
STRIPE_SECRET=sk_live_fakeStripeSecretForHoneypot
OPENAI_API_KEY=sk-fakeOpenAIKeyForHoneypot1234567890
JWT_SECRET=fakeJWTSecretKeyForHoneypot1234567890abcdef"""
            return Response(env_content, mimetype="text/plain")

        @self.app.route("/wp-admin", methods=["GET", "POST"])
        def fake_wp_admin():
            attacker = self._get_attacker_info()
            self._log_attack(attacker, "wordpress_attack", "/wp-admin", severity="high")
            return """
            <html><head><title>WordPress Admin</title></head>
            <body>
            <form method="post">
                <input name="log" placeholder="Username">
                <input name="pwd" type="password" placeholder="Password">
                <button type="submit">Login</button>
            </form>
            </body></html>
            """, 200

        @self.app.route("/phpmyadmin", methods=["GET", "POST"])
        def fake_phpmyadmin():
            attacker = self._get_attacker_info()
            self._log_attack(attacker, "phpmyadmin_access", "/phpmyadmin", severity="high")
            return jsonify({"phpMyAdmin": "5.2.1", "server": "MySQL 8.0.35"}), 200

        @self.app.route("/api/v1/auth", methods=["POST"])
        def fake_auth():
            attacker = self._get_attacker_info()
            data = request.get_json(silent=True) or {}
            self._log_attack(
                attacker, "api_auth_attempt", "/api/v1/auth",
                payload=json.dumps(data),
                severity="high",
                username=data.get("username", ""),
                password=data.get("password", "")
            )
            return jsonify({
                "access_token": random.choice(FAKE_TOKENS),
                "token_type": "Bearer",
                "expires_in": 3600
            }), 200

        @self.app.route("/graphql", methods=["GET", "POST"])
        def fake_graphql():
            attacker = self._get_attacker_info()
            data = request.get_json(silent=True) or {}
            self._log_attack(
                attacker, "graphql_introspection", "/graphql",
                payload=json.dumps(data), severity="medium"
            )
            return jsonify({
                "data": {
                    "__schema": {
                        "types": [
                            {"name": "User", "fields": ["id", "email", "password", "role"]},
                            {"name": "Admin", "fields": ["id", "secret_key", "permissions"]}
                        ]
                    }
                }
            }), 200

        @self.app.route("/backup", methods=["GET"])
        def fake_backup():
            attacker = self._get_attacker_info()
            self._log_attack(attacker, "backup_access", "/backup", severity="critical")
            return Response(
                "PK fake backup file - honeytrap by ossiqn",
                mimetype="application/zip",
                headers={"Content-Disposition": "attachment; filename=backup_2024.zip"}
            )

        @self.app.route("/console", methods=["GET", "POST"])
        def fake_console():
            attacker = self._get_attacker_info()
            cmd = request.form.get("cmd", request.args.get("cmd", ""))
            self._log_attack(
                attacker, "rce_attempt", "/console",
                payload=cmd, severity="critical"
            )
            return jsonify({
                "output": f"bash: {cmd}: command not found",
                "exit_code": 127
            }), 200

        @self.app.route("/shell", methods=["GET", "POST"])
        def fake_shell():
            attacker = self._get_attacker_info()
            cmd = request.form.get("cmd", request.args.get("cmd", ""))
            self._log_attack(
                attacker, "webshell_access", "/shell",
                payload=cmd, severity="critical"
            )
            return f"<pre>$ {cmd}\nbash: permission denied</pre>", 200

        @self.app.route("/api/database", methods=["GET"])
        def fake_database():
            attacker = self._get_attacker_info()
            self._log_attack(attacker, "database_dump", "/api/database", severity="critical")
            return jsonify({
                "tables": ["users", "payments", "sessions", "admin_logs"],
                "connection_string": "postgresql://admin:Sup3rS3cur3P@ss@localhost:5432/prod",
                "records": 48291
            }), 200

        @self.app.errorhandler(404)
        def catch_all(e):
            attacker = self._get_attacker_info()
            self._log_attack(
                attacker, "path_scan", request.path,
                severity="low",
                payload=request.path
            )
            return jsonify({"error": "Not Found", "path": request.path}), 404

    def start(self):
        logger.info(f"[ossiqn] HTTP Trap starting on port {self.port}")
        thread = threading.Thread(
            target=lambda: self.app.run(
                host="0.0.0.0",
                port=self.port,
                debug=False,
                use_reloader=False,
                threaded=True
            ),
            daemon=True,
            name=f"HTTPTrap_{self.port}"
        )
        thread.start()
        logger.info(f"[ossiqn] HTTP Trap active on port {self.port}")