import sqlite3
import json
import os
from datetime import datetime
from typing import List, Dict, Optional


class Database:
    def __init__(self, db_path: str):
        os.makedirs(os.path.dirname(db_path) if os.path.dirname(db_path) else ".", exist_ok=True)
        self.db_path = db_path
        self.init_db()

    def get_connection(self):
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def init_db(self):
        with self.get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS attacks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    trap_type TEXT NOT NULL,
                    attacker_ip TEXT NOT NULL,
                    attacker_port INTEGER,
                    country TEXT,
                    city TEXT,
                    latitude REAL,
                    longitude REAL,
                    isp TEXT,
                    asn TEXT,
                    severity TEXT DEFAULT 'medium',
                    attack_type TEXT,
                    payload TEXT,
                    username TEXT,
                    password TEXT,
                    endpoint TEXT,
                    headers TEXT,
                    user_agent TEXT,
                    raw_data TEXT,
                    is_tor INTEGER DEFAULT 0,
                    is_vpn INTEGER DEFAULT 0,
                    is_blacklisted INTEGER DEFAULT 0,
                    threat_score INTEGER DEFAULT 0,
                    produced_by TEXT DEFAULT 'ossiqn'
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS ioc_list (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    ioc_type TEXT NOT NULL,
                    ioc_value TEXT NOT NULL,
                    threat_score INTEGER DEFAULT 0,
                    first_seen TEXT,
                    last_seen TEXT,
                    hit_count INTEGER DEFAULT 1,
                    tags TEXT,
                    produced_by TEXT DEFAULT 'ossiqn'
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS blacklist (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT UNIQUE NOT NULL,
                    added_at TEXT NOT NULL,
                    expires_at TEXT,
                    reason TEXT,
                    hit_count INTEGER DEFAULT 1,
                    produced_by TEXT DEFAULT 'ossiqn'
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT UNIQUE NOT NULL,
                    attacker_ip TEXT NOT NULL,
                    trap_type TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    ended_at TEXT,
                    commands TEXT,
                    credentials_tried TEXT,
                    produced_by TEXT DEFAULT 'ossiqn'
                )
            """)

            conn.execute("CREATE INDEX IF NOT EXISTS idx_attacks_ip ON attacks(attacker_ip)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_attacks_timestamp ON attacks(timestamp)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_attacks_trap ON attacks(trap_type)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_ioc_value ON ioc_list(ioc_value)")
            conn.commit()

    def insert_attack(self, attack: Dict) -> int:
        with self.get_connection() as conn:
            cursor = conn.execute("""
                INSERT INTO attacks (
                    timestamp, trap_type, attacker_ip, attacker_port,
                    country, city, latitude, longitude, isp, asn,
                    severity, attack_type, payload, username, password,
                    endpoint, headers, user_agent, raw_data,
                    is_tor, is_vpn, is_blacklisted, threat_score, produced_by
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                attack.get("timestamp", datetime.utcnow().isoformat()),
                attack.get("trap_type", "unknown"),
                attack.get("attacker_ip", ""),
                attack.get("attacker_port", 0),
                attack.get("country", "Unknown"),
                attack.get("city", "Unknown"),
                attack.get("latitude", 0.0),
                attack.get("longitude", 0.0),
                attack.get("isp", "Unknown"),
                attack.get("asn", "Unknown"),
                attack.get("severity", "medium"),
                attack.get("attack_type", "unknown"),
                attack.get("payload", ""),
                attack.get("username", ""),
                attack.get("password", ""),
                attack.get("endpoint", ""),
                json.dumps(attack.get("headers", {})),
                attack.get("user_agent", ""),
                json.dumps(attack.get("raw_data", {})),
                1 if attack.get("is_tor") else 0,
                1 if attack.get("is_vpn") else 0,
                1 if attack.get("is_blacklisted") else 0,
                attack.get("threat_score", 0),
                "ossiqn"
            ))
            conn.commit()
            return cursor.lastrowid

    def get_attacks(self, limit: int = 100, offset: int = 0,
                    trap_type: str = None, severity: str = None,
                    attacker_ip: str = None) -> List[Dict]:
        query = "SELECT * FROM attacks WHERE 1=1"
        params = []

        if trap_type:
            query += " AND trap_type = ?"
            params.append(trap_type)

        if severity:
            query += " AND severity = ?"
            params.append(severity)

        if attacker_ip:
            query += " AND attacker_ip = ?"
            params.append(attacker_ip)

        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        with self.get_connection() as conn:
            rows = conn.execute(query, params).fetchall()
            return [dict(row) for row in rows]

    def get_stats(self) -> Dict:
        with self.get_connection() as conn:
            total = conn.execute("SELECT COUNT(*) FROM attacks").fetchone()[0]

            trap_counts = {}
            for row in conn.execute("SELECT trap_type, COUNT(*) as count FROM attacks GROUP BY trap_type").fetchall():
                trap_counts[row[0]] = row[1]

            country_counts = {}
            for row in conn.execute("SELECT country, COUNT(*) as count FROM attacks GROUP BY country ORDER BY count DESC LIMIT 10").fetchall():
                country_counts[row[0]] = row[1]

            severity_counts = {}
            for row in conn.execute("SELECT severity, COUNT(*) as count FROM attacks GROUP BY severity").fetchall():
                severity_counts[row[0]] = row[1]

            recent_24h = conn.execute("""
                SELECT COUNT(*) FROM attacks
                WHERE timestamp > datetime('now', '-24 hours')
            """).fetchone()[0]

            top_attackers = []
            for row in conn.execute("""
                SELECT attacker_ip, country, COUNT(*) as count
                FROM attacks GROUP BY attacker_ip
                ORDER BY count DESC LIMIT 10
            """).fetchall():
                top_attackers.append(dict(row))

            unique_ips = conn.execute("SELECT COUNT(DISTINCT attacker_ip) FROM attacks").fetchone()[0]

            ioc_count = conn.execute("SELECT COUNT(*) FROM ioc_list").fetchone()[0]

            return {
                "total": total,
                "unique_ips": unique_ips,
                "recent_24h": recent_24h,
                "trap_counts": trap_counts,
                "country_counts": country_counts,
                "severity_counts": severity_counts,
                "top_attackers": top_attackers,
                "ioc_count": ioc_count,
                "produced_by": "ossiqn"
            }

    def add_to_blacklist(self, ip: str, reason: str, expires_at: str = None):
        with self.get_connection() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO blacklist (ip_address, added_at, expires_at, reason, produced_by)
                VALUES (?, ?, ?, ?, ?)
            """, (ip, datetime.utcnow().isoformat(), expires_at, reason, "ossiqn"))
            conn.commit()

    def is_blacklisted(self, ip: str) -> bool:
        with self.get_connection() as conn:
            row = conn.execute(
                "SELECT id FROM blacklist WHERE ip_address = ?", (ip,)
            ).fetchone()
            return row is not None

    def insert_ioc(self, ioc_type: str, ioc_value: str, threat_score: int = 50, tags: list = None):
        with self.get_connection() as conn:
            existing = conn.execute(
                "SELECT id, hit_count FROM ioc_list WHERE ioc_value = ?", (ioc_value,)
            ).fetchone()

            if existing:
                conn.execute("""
                    UPDATE ioc_list SET hit_count = hit_count + 1, last_seen = ?, threat_score = ?
                    WHERE ioc_value = ?
                """, (datetime.utcnow().isoformat(), threat_score, ioc_value))
            else:
                now = datetime.utcnow().isoformat()
                conn.execute("""
                    INSERT INTO ioc_list (timestamp, ioc_type, ioc_value, threat_score, first_seen, last_seen, tags, produced_by)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (now, ioc_type, ioc_value, threat_score, now, now, json.dumps(tags or []), "ossiqn"))
            conn.commit()

    def get_ioc_list(self, limit: int = 100) -> List[Dict]:
        with self.get_connection() as conn:
            rows = conn.execute("""
                SELECT * FROM ioc_list ORDER BY threat_score DESC, hit_count DESC LIMIT ?
            """, (limit,)).fetchall()
            return [dict(row) for row in rows]

    def get_geo_data(self) -> List[Dict]:
        with self.get_connection() as conn:
            rows = conn.execute("""
                SELECT attacker_ip, country, city, latitude, longitude, COUNT(*) as count
                FROM attacks
                WHERE latitude != 0 AND longitude != 0
                GROUP BY attacker_ip
                ORDER BY count DESC
                LIMIT 500
            """).fetchall()
            return [dict(row) for row in rows]