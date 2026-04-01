import socket
import threading
import logging
from datetime import datetime
from typing import Dict

logger = logging.getLogger("honeytrap.ftp")


class FTPTrap:
    def __init__(self, config: Dict, db, geoip, ioc_manager, notifier):
        self.config = config
        self.db = db
        self.geoip = geoip
        self.ioc_manager = ioc_manager
        self.notifier = notifier
        self.port = config.get("port", 2121)
        self.running = False
        self.fake_files = config.get("fake_files", [
            "passwords.txt", "config.bak", "database.sql",
            "users.csv", "secrets.txt", "backup.zip"
        ])

    def _handle_client(self, client_socket: socket.socket, client_ip: str):
        geo = self.geoip.lookup(client_ip)
        username = ""
        authenticated = False
        credentials_log = []

        try:
            banner = self.config.get("banner", "220 FTP Server Ready")
            client_socket.send(f"{banner}\r\n".encode())

            while True:
                try:
                    data = client_socket.recv(1024)
                    if not data:
                        break

                    command = data.decode("utf-8", errors="ignore").strip()
                    parts = command.split(" ", 1)
                    cmd = parts[0].upper() if parts else ""
                    arg = parts[1] if len(parts) > 1 else ""

                    if cmd == "USER":
                        username = arg
                        client_socket.send(b"331 Password required\r\n")

                    elif cmd == "PASS":
                        password = arg
                        credentials_log.append(f"{username}:{password}")

                        attack = {
                            "timestamp": datetime.utcnow().isoformat(),
                            "trap_type": "ftp",
                            "attacker_ip": client_ip,
                            "country": geo.get("country", "Unknown"),
                            "city": geo.get("city", "Unknown"),
                            "latitude": geo.get("latitude", 0.0),
                            "longitude": geo.get("longitude", 0.0),
                            "isp": geo.get("isp", "Unknown"),
                            "asn": geo.get("asn", "Unknown"),
                            "severity": "high",
                            "attack_type": "ftp_brute_force",
                            "username": username,
                            "password": password,
                            "threat_score": self.geoip.get_threat_score(client_ip),
                            "raw_data": {
                                "credentials_tried": credentials_log,
                                "produced_by": "ossiqn"
                            }
                        }

                        self.db.insert_attack(attack)
                        self.ioc_manager.process_attack(attack)

                        logger.warning(
                            f"[ossiqn FTP] BRUTE FORCE | {client_ip} ({geo.get('country')}) | "
                            f"user={username} pass={password}"
                        )

                        if self.notifier:
                            self.notifier.send_attack(attack)

                        if self.config.get("allow_anonymous") and username.lower() == "anonymous":
                            authenticated = True
                            client_socket.send(b"230 Login successful\r\n")
                        else:
                            authenticated = True
                            client_socket.send(b"230 Login successful\r\n")

                    elif cmd == "LIST" or cmd == "NLST":
                        if authenticated:
                            client_socket.send(b"150 Here comes the directory listing\r\n")
                            file_list = "\r\n".join(
                                [f"-rw-r--r-- 1 root root 4096 Jan 15 08:23 {f}" for f in self.fake_files]
                            )
                            client_socket.send(f"{file_list}\r\n".encode())
                            client_socket.send(b"226 Directory send OK\r\n")

                            attack = {
                                "timestamp": datetime.utcnow().isoformat(),
                                "trap_type": "ftp",
                                "attacker_ip": client_ip,
                                "country": geo.get("country", "Unknown"),
                                "city": geo.get("city", "Unknown"),
                                "latitude": geo.get("latitude", 0.0),
                                "longitude": geo.get("longitude", 0.0),
                                "isp": geo.get("isp", "Unknown"),
                                "asn": geo.get("asn", "Unknown"),
                                "severity": "medium",
                                "attack_type": "ftp_directory_listing",
                                "username": username,
                                "threat_score": self.geoip.get_threat_score(client_ip),
                                "raw_data": {"produced_by": "ossiqn"}
                            }
                            self.db.insert_attack(attack)

                    elif cmd == "RETR":
                        filename = arg
                        attack = {
                            "timestamp": datetime.utcnow().isoformat(),
                            "trap_type": "ftp",
                            "attacker_ip": client_ip,
                            "country": geo.get("country", "Unknown"),
                            "city": geo.get("city", "Unknown"),
                            "latitude": geo.get("latitude", 0.0),
                            "longitude": geo.get("longitude", 0.0),
                            "isp": geo.get("isp", "Unknown"),
                            "asn": geo.get("asn", "Unknown"),
                            "severity": "critical",
                            "attack_type": "ftp_file_download",
                            "payload": filename,
                            "username": username,
                            "threat_score": self.geoip.get_threat_score(client_ip),
                            "raw_data": {"filename": filename, "produced_by": "ossiqn"}
                        }
                        self.db.insert_attack(attack)
                        self.ioc_manager.process_attack(attack)

                        logger.warning(f"[ossiqn FTP] FILE DOWNLOAD ATTEMPT | {client_ip} | file={filename}")

                        client_socket.send(b"150 Opening data connection\r\n")
                        client_socket.send(f"Honeypot file: {filename} - ossiqn".encode())
                        client_socket.send(b"\r\n226 Transfer complete\r\n")

                    elif cmd == "QUIT":
                        client_socket.send(b"221 Goodbye\r\n")
                        break

                    elif cmd == "SYST":
                        client_socket.send(b"215 UNIX Type: L8\r\n")

                    elif cmd == "FEAT":
                        client_socket.send(b"211-Features:\r\n UTF8\r\n211 End\r\n")

                    elif cmd == "PWD":
                        client_socket.send(b'257 "/" is the current directory\r\n')

                    else:
                        client_socket.send(b"200 OK\r\n")

                except Exception:
                    break

        except Exception as e:
            logger.debug(f"[ossiqn FTP] Client {client_ip} error: {e}")
        finally:
            try:
                client_socket.close()
            except Exception:
                pass

    def start(self):
        self.running = True

        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(("0.0.0.0", self.port))
        server_socket.listen(100)

        logger.info(f"[ossiqn] FTP Trap active on port {self.port}")

        def accept_loop():
            while self.running:
                try:
                    client_socket, client_address = server_socket.accept()
                    threading.Thread(
                        target=self._handle_client,
                        args=(client_socket, client_address[0]),
                        daemon=True
                    ).start()
                except Exception as e:
                    if self.running:
                        logger.error(f"[ossiqn FTP] Accept error: {e}")

        threading.Thread(target=accept_loop, daemon=True, name="FTPTrap").start()