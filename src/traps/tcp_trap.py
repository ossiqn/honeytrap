import socket
import threading
import logging
from datetime import datetime
from typing import Dict, List

logger = logging.getLogger("honeytrap.tcp")

PORT_SERVICES = {
    3306:  ("MySQL",         "mysql_probe"),
    5432:  ("PostgreSQL",    "postgresql_probe"),
    6379:  ("Redis",         "redis_probe"),
    27017: ("MongoDB",       "mongodb_probe"),
    9200:  ("Elasticsearch", "elasticsearch_probe"),
    8888:  ("Jupyter",       "jupyter_probe"),
    4444:  ("Backdoor",      "backdoor_connect"),
    1433:  ("MSSQL",         "mssql_probe"),
    5900:  ("VNC",           "vnc_probe"),
    5984:  ("CouchDB",       "couchdb_probe"),
}

PORT_BANNERS = {
    3306:  b"\x4a\x00\x00\x00\x0a\x38\x2e\x30\x2e\x33\x35\x00",
    5432:  b"R\x00\x00\x00\x08\x00\x00\x00\x00",
    6379:  b"+PONG\r\n",
    27017: b"\x16\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00",
    9200:  b'{"name":"honeypot","cluster_name":"ossiqn"}',
    8888:  b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<title>Jupyter</title>",
    4444:  b"",
    1433:  b"\x04\x01\x00\x2b\x00\x00\x01\x00\x00\x00\x1a\x00\x06\x01",
    5900:  b"RFB 003.008\n",
}


class TCPTrap:
    def __init__(self, config: Dict, db, geoip, ioc_manager, notifier):
        self.config      = config
        self.db          = db
        self.geoip       = geoip
        self.ioc_manager = ioc_manager
        self.notifier    = notifier
        self.ports       = config.get("ports", list(PORT_SERVICES.keys()))
        self.running     = False

    def _handle_client(self, client_socket: socket.socket, client_ip: str, port: int):
        geo          = self.geoip.lookup(client_ip)
        service_name, attack_type = PORT_SERVICES.get(port, ("Unknown", "tcp_probe"))
        try:
            banner = PORT_BANNERS.get(port, b"")
            if banner:
                client_socket.send(banner)
            payload = b""
            try:
                client_socket.settimeout(5)
                payload = client_socket.recv(4096)
            except Exception:
                pass
            severity = "critical" if port in [4444, 6379, 27017] else "high"
            attack = {
                "timestamp":    datetime.utcnow().isoformat(),
                "trap_type":    "tcp",
                "attacker_ip":  client_ip,
                "attacker_port": port,
                "country":      geo.get("country", "Unknown"),
                "city":         geo.get("city", "Unknown"),
                "latitude":     geo.get("latitude", 0.0),
                "longitude":    geo.get("longitude", 0.0),
                "isp":          geo.get("isp", "Unknown"),
                "asn":          geo.get("asn", "Unknown"),
                "severity":     severity,
                "attack_type":  attack_type,
                "payload":      payload.hex() if payload else "",
                "endpoint":     f"tcp:{port}",
                "threat_score": self.geoip.get_threat_score(client_ip),
                "raw_data": {
                    "service":     service_name,
                    "port":        port,
                    "payload_raw": payload.decode("utf-8", errors="ignore")[:500],
                    "produced_by": "ossiqn"
                }
            }
            self.db.insert_attack(attack)
            self.ioc_manager.process_attack(attack)
            logger.warning(
                f"[ossiqn TCP] {attack_type.upper()} | {client_ip} ({geo.get('country')}) | "
                f"port={port} service={service_name}"
            )
            if self.notifier:
                self.notifier.send_attack(attack)
        except Exception as e:
            logger.debug(f"[ossiqn TCP] Error on port {port} from {client_ip}: {e}")
        finally:
            try:
                client_socket.close()
            except Exception:
                pass

    def _start_listener(self, port: int):
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind(("0.0.0.0", port))
            server_socket.listen(50)
            logger.info(f"[ossiqn] TCP Trap active on port {port} ({PORT_SERVICES.get(port, ('Unknown',))[0]})")
            while self.running:
                try:
                    client_socket, client_address = server_socket.accept()
                    threading.Thread(
                        target=self._handle_client,
                        args=(client_socket, client_address[0], port),
                        daemon=True
                    ).start()
                except Exception as e:
                    if self.running:
                        logger.error(f"[ossiqn TCP] Accept error on port {port}: {e}")
        except Exception as e:
            logger.error(f"[ossiqn TCP] Could not bind port {port}: {e}")

    def start(self):
        self.running = True
        for port in self.ports:
            threading.Thread(
                target=self._start_listener,
                args=(port,),
                daemon=True,
                name=f"TCPTrap_{port}"
            ).start()
