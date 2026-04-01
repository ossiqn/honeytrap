import socket
import threading
import logging
import paramiko
from datetime import datetime
from typing import Dict

logger    = logging.getLogger("honeytrap.ssh")
SSH_KEY   = paramiko.RSAKey.generate(2048)


class FakeSSHServer(paramiko.ServerInterface):
    def __init__(self, client_ip: str, db, geoip, ioc_manager, notifier, config: Dict):
        self.client_ip    = client_ip
        self.db           = db
        self.geoip        = geoip
        self.ioc_manager  = ioc_manager
        self.notifier     = notifier
        self.config       = config
        self.credentials_tried = []
        self.event        = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username: str, password: str) -> int:
        geo = self.geoip.lookup(self.client_ip)
        attack = {
            "timestamp":    datetime.utcnow().isoformat(),
            "trap_type":    "ssh",
            "attacker_ip":  self.client_ip,
            "country":      geo.get("country", "Unknown"),
            "city":         geo.get("city", "Unknown"),
            "latitude":     geo.get("latitude", 0.0),
            "longitude":    geo.get("longitude", 0.0),
            "isp":          geo.get("isp", "Unknown"),
            "asn":          geo.get("asn", "Unknown"),
            "severity":     "high",
            "attack_type":  "ssh_brute_force",
            "username":     username,
            "password":     password,
            "is_vpn":       geo.get("is_proxy", False),
            "threat_score": self.geoip.get_threat_score(self.client_ip),
            "raw_data":     {"auth_method": "password", "produced_by": "ossiqn"}
        }
        self.credentials_tried.append(f"{username}:{password}")
        attack_id    = self.db.insert_attack(attack)
        attack["id"] = attack_id
        self.ioc_manager.process_attack(attack)
        logger.warning(
            f"[ossiqn SSH] BRUTE FORCE | {self.client_ip} ({geo.get('country')}) | "
            f"user={username} pass={password}"
        )
        if self.notifier:
            self.notifier.send_attack(attack)
        for cred in self.config.get("fake_credentials", []):
            if cred.get("username") == username and cred.get("password") == password:
                return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True


class SSHTrap:
    def __init__(self, config: Dict, db, geoip, ioc_manager, notifier):
        self.config      = config
        self.db          = db
        self.geoip       = geoip
        self.ioc_manager = ioc_manager
        self.notifier    = notifier
        self.port        = config.get("port", 2222)
        self.running     = False

    def _handle_client(self, client_socket: socket.socket, client_address: tuple):
        client_ip = client_address[0]
        try:
            transport              = paramiko.Transport(client_socket)
            transport.local_version = self.config.get("banner", "SSH-2.0-OpenSSH_8.9p1")
            transport.add_server_key(SSH_KEY)
            server = FakeSSHServer(
                client_ip, self.db, self.geoip,
                self.ioc_manager, self.notifier, self.config
            )
            transport.start_server(server=server)
            channel = transport.accept(30)
            if channel:
                channel.send("\r\nWelcome to Ubuntu 22.04.3 LTS\r\n")
                channel.send("Last login: Mon Jan 15 08:23:11 2024 from 10.0.0.1\r\n")
                channel.send("$ ")
                commands_log = []
                buffer       = ""
                fake_responses = {
                    "ls":              "bin  boot  dev  etc  home  lib  media  mnt  opt  proc  root  run  srv  sys  tmp  usr  var",
                    "pwd":             "/root",
                    "whoami":          "root",
                    "id":              "uid=0(root) gid=0(root) groups=0(root)",
                    "uname -a":        "Linux prod-server 5.15.0-88-generic #98-Ubuntu SMP x86_64 GNU/Linux",
                    "cat /etc/passwd": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
                    "cat /etc/shadow": "root:$6$fakeHashForHoneypot$abcdefghijk:19000:0:99999:7:::",
                    "ifconfig":        "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST> mtu 1500\n        inet 192.168.1.100",
                    "ps aux":          "root         1  0.0  0.0  nginx\nroot       123  0.1  mysql",
                    "netstat -an":     "tcp    0.0.0.0:22    LISTEN\ntcp    0.0.0.0:80    LISTEN",
                    "history":         "1  ls -la\n2  cat /etc/passwd\n3  wget http://malicious.site/payload",
                    "crontab -l":      "*/5 * * * * /usr/bin/backup.sh",
                }
                while transport.is_active():
                    try:
                        data = channel.recv(1024)
                        if not data:
                            break
                        decoded = data.decode("utf-8", errors="ignore")
                        buffer += decoded
                        if "\n" in buffer or "\r" in buffer:
                            cmd = buffer.strip()
                            if cmd:
                                commands_log.append(cmd)
                                geo    = self.geoip.lookup(client_ip)
                                attack = {
                                    "timestamp":    datetime.utcnow().isoformat(),
                                    "trap_type":    "ssh",
                                    "attacker_ip":  client_ip,
                                    "country":      geo.get("country", "Unknown"),
                                    "city":         geo.get("city", "Unknown"),
                                    "latitude":     geo.get("latitude", 0.0),
                                    "longitude":    geo.get("longitude", 0.0),
                                    "isp":          geo.get("isp", "Unknown"),
                                    "asn":          geo.get("asn", "Unknown"),
                                    "severity":     "critical",
                                    "attack_type":  "ssh_command_execution",
                                    "payload":      cmd,
                                    "threat_score": self.geoip.get_threat_score(client_ip),
                                    "raw_data": {
                                        "command":      cmd,
                                        "all_commands": commands_log,
                                        "produced_by":  "ossiqn"
                                    }
                                }
                                self.db.insert_attack(attack)
                                self.ioc_manager.process_attack(attack)
                                logger.warning(f"[ossiqn SSH] COMMAND | {client_ip} | cmd: {cmd}")
                                response = fake_responses.get(cmd, f"bash: {cmd}: command not found")
                                channel.send(f"\r\n{response}\r\n$ ")
                            buffer = ""
                    except Exception:
                        break
                channel.close()
        except Exception as e:
            logger.debug(f"[ossiqn SSH] Client {client_ip} disconnected: {e}")
        finally:
            try:
                client_socket.close()
            except Exception:
                pass

    def start(self):
        self.running  = True
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(("0.0.0.0", self.port))
        server_socket.listen(100)
        logger.info(f"[ossiqn] SSH Trap active on port {self.port}")

        def accept_loop():
            while self.running:
                try:
                    client_socket, client_address = server_socket.accept()
                    threading.Thread(
                        target=self._handle_client,
                        args=(client_socket, client_address),
                        daemon=True
                    ).start()
                except Exception as e:
                    if self.running:
                        logger.error(f"[ossiqn SSH] Accept error: {e}")

        threading.Thread(target=accept_loop, daemon=True, name="SSHTrap").start()
