import os
import json
import logging
from datetime import datetime
from flask import Flask, render_template, jsonify, request, abort

logger = logging.getLogger("honeytrap.web")

app = Flask(__name__)
app.config["SECRET_KEY"] = os.urandom(32).hex()

_db         = None
_ioc        = None
_trap_status = {
    "running":   False,
    "traps":     {},
    "started_at": None,
    "produced_by": "ossiqn"
}


def init_web(db, ioc, trap_status: dict):
    global _db, _ioc, _trap_status
    _db          = db
    _ioc         = ioc
    _trap_status = trap_status
    _trap_status["produced_by"] = "ossiqn"


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/attacks")
def get_attacks():
    if not _db:
        return jsonify({"error": "not initialized"}), 500

    limit     = min(int(request.args.get("limit", 100)), 1000)
    offset    = int(request.args.get("offset", 0))
    trap_type = request.args.get("trap_type") or None
    severity  = request.args.get("severity") or None

    attacks = _db.get_attacks(limit=limit, offset=offset, trap_type=trap_type, severity=severity)

    return jsonify({
        "attacks":     attacks,
        "count":       len(attacks),
        "offset":      offset,
        "produced_by": "ossiqn"
    })


@app.route("/api/stats")
def get_stats():
    if not _db:
        return jsonify({"error": "not initialized"}), 500

    stats = _db.get_stats()
    stats["trap_status"] = _trap_status
    stats["produced_by"] = "ossiqn"

    return jsonify(stats)


@app.route("/api/ioc")
def get_ioc():
    if not _db:
        return jsonify({"error": "not initialized"}), 500

    iocs = _db.get_ioc_list(limit=500)
    return jsonify({
        "iocs":        iocs,
        "count":       len(iocs),
        "produced_by": "ossiqn"
    })


@app.route("/api/ioc/export")
def export_ioc():
    if not _ioc:
        return jsonify({"error": "not initialized"}), 500

    data = _ioc.export_ioc()
    return jsonify(data)


@app.route("/api/geo")
def get_geo():
    if not _db:
        return jsonify({"error": "not initialized"}), 500

    geo_data = _db.get_geo_data()
    return jsonify({
        "points":      geo_data,
        "count":       len(geo_data),
        "produced_by": "ossiqn"
    })


@app.route("/api/blacklist", methods=["GET"])
def get_blacklist():
    if not _db:
        return jsonify({"error": "not initialized"}), 500

    with _db.get_connection() as conn:
        rows = conn.execute("SELECT * FROM blacklist ORDER BY added_at DESC LIMIT 100").fetchall()
        return jsonify({
            "blacklist":   [dict(r) for r in rows],
            "produced_by": "ossiqn"
        })


@app.route("/api/blacklist/<ip>", methods=["POST"])
def add_blacklist(ip):
    if not _db:
        abort(500)
    reason = request.json.get("reason", "manual") if request.json else "manual"
    _db.add_to_blacklist(ip, reason)
    return jsonify({"success": True, "ip": ip, "produced_by": "ossiqn"})


@app.route("/api/status")
def get_status():
    return jsonify({**_trap_status, "produced_by": "ossiqn"})


@app.route("/api/info")
def get_info():
    return jsonify({
        "tool":        "HoneyTrap Network",
        "version":     "1.0.0",
        "produced_by": "ossiqn",
        "website":     "ossiqn.com.tr",
        "github":      "github.com/ossiqn",
        "license":     "MIT © 2024 ossiqn"
    })


def run_web(host: str = "0.0.0.0", port: int = 5000, debug: bool = False):
    logger.info(f"[ossiqn] Web dashboard starting on http://{host}:{port}")
    app.run(
        host=host,
        port=port,
        debug=debug,
        use_reloader=False,
        threaded=True
    )