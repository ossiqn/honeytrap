import logging
from datetime import datetime
from typing import Dict, List

logger = logging.getLogger("honeytrap.ioc")


class IOCManager:
    def __init__(self, db, config: Dict):
        self.db           = db
        self.config       = config
        self.attack_counts = {}

    def process_attack(self, attack: Dict):
        ip = attack.get("attacker_ip", "")
        if ip:
            self.db.insert_ioc(
                ioc_type="ip",
                ioc_value=ip,
                threat_score=attack.get("threat_score", 50),
                tags=[attack.get("trap_type", ""), attack.get("attack_type", "")]
            )
        if attack.get("username") or attack.get("password"):
            cred = f"{attack.get('username', '')}:{attack.get('password', '')}"
            self.db.insert_ioc(
                ioc_type="credential",
                ioc_value=cred,
                threat_score=60,
                tags=["brute_force", attack.get("trap_type", "")]
            )
        if attack.get("user_agent"):
            self.db.insert_ioc(
                ioc_type="user_agent",
                ioc_value=attack.get("user_agent"),
                threat_score=30,
                tags=["http", "scanner"]
            )
        if ip:
            if ip not in self.attack_counts:
                self.attack_counts[ip] = 0
            self.attack_counts[ip] += 1
            threshold = self.config.get("detection", {}).get("brute_force_threshold", 10)
            if self.attack_counts[ip] >= threshold:
                if self.config.get("detection", {}).get("auto_blacklist", True):
                    self.db.add_to_blacklist(ip, "auto_blacklist_threshold_exceeded")
                    logger.warning(f"[ossiqn] Auto-blacklisted IP: {ip} (hits: {self.attack_counts[ip]})")

    def export_ioc(self) -> Dict:
        iocs   = self.db.get_ioc_list(limit=10000)
        result = {
            "generated_at": datetime.utcnow().isoformat(),
            "produced_by":  "ossiqn",
            "tool":         "HoneyTrap Network",
            "version":      "1.0.0",
            "total_iocs":   len(iocs),
            "ioc_types":    {},
            "iocs":         iocs
        }
        for ioc in iocs:
            t = ioc.get("ioc_type", "unknown")
            result["ioc_types"][t] = result["ioc_types"].get(t, 0) + 1
        return result
