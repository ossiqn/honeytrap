import logging
import requests
from typing import Dict

logger = logging.getLogger("honeytrap.geoip")


class GeoIP:
    def __init__(self, config: Dict):
        self.config = config
        self.cache = {}
        self.fallback_url = "http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,lat,lon,isp,as,query,proxy,hosting"

    def lookup(self, ip: str) -> Dict:
        if ip in self.cache:
            return self.cache[ip]

        if ip.startswith(("10.", "172.", "192.168.", "127.")):
            return {
                "country": "Local",
                "country_code": "LO",
                "city": "Local Network",
                "latitude": 0.0,
                "longitude": 0.0,
                "isp": "Local",
                "asn": "Local",
                "is_proxy": False,
                "is_hosting": False
            }

        try:
            response = requests.get(
                self.fallback_url.format(ip=ip),
                timeout=5
            )

            if response.status_code == 200:
                data = response.json()

                if data.get("status") == "success":
                    result = {
                        "country": data.get("country", "Unknown"),
                        "country_code": data.get("countryCode", "XX"),
                        "city": data.get("city", "Unknown"),
                        "latitude": data.get("lat", 0.0),
                        "longitude": data.get("lon", 0.0),
                        "isp": data.get("isp", "Unknown"),
                        "asn": data.get("as", "Unknown"),
                        "is_proxy": data.get("proxy", False),
                        "is_hosting": data.get("hosting", False)
                    }

                    self.cache[ip] = result
                    return result

        except Exception as e:
            logger.error(f"[ossiqn] GeoIP lookup failed for {ip}: {e}")

        return {
            "country": "Unknown",
            "country_code": "XX",
            "city": "Unknown",
            "latitude": 0.0,
            "longitude": 0.0,
            "isp": "Unknown",
            "asn": "Unknown",
            "is_proxy": False,
            "is_hosting": False
        }

    def get_threat_score(self, ip: str) -> int:
        geo = self.lookup(ip)
        score = 0

        high_risk_countries = ["CN", "RU", "KP", "IR", "NG", "BR", "UA", "RO"]
        if geo.get("country_code") in high_risk_countries:
            score += 20

        if geo.get("is_proxy"):
            score += 30

        if geo.get("is_hosting"):
            score += 25

        return min(score, 100)