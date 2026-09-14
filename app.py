import ipaddress
import json
import os
import socket
import sqlite3
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

import requests
from flask import Flask, jsonify, render_template, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from scanner.advanced import analyze_advanced
from scanner.cookies import analyze_cookies
from scanner.crawler import discover_links
from scanner.headers import analyze_headers
from scanner.risk_score import calculate_score

app = Flask(__name__)
DB = os.getenv("WEBGUARD_DB", "webguard.db")
TIMEOUT = int(os.getenv("SCAN_TIMEOUT", "8"))
MAX_REDIRECTS = 3
ALLOW_PRIVATE = os.getenv("ALLOW_PRIVATE_TARGETS", "0").lower() in {"1", "true", "yes"}

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["120 per minute"],
    storage_uri="memory://",
)


def db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = db()
    conn.execute("""CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target TEXT NOT NULL,
        score INTEGER NOT NULL,
        level TEXT NOT NULL,
        findings TEXT NOT NULL,
        created_at TEXT NOT NULL
    )""")
    conn.commit()
    conn.close()


def _resolved_addresses(hostname):
    try:
        return {item[4][0] for item in socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)}
    except socket.gaierror as exc:
        raise ValueError("Target hostname could not be resolved.") from exc


def validate_target(target):
    parsed = urlparse(target)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Enter a complete HTTP or HTTPS URL.")
    if parsed.username or parsed.password:
        raise ValueError("Credentials in URLs are not supported.")

    addresses = _resolved_addresses(parsed.hostname)
    if not ALLOW_PRIVATE:
        blocked = []
        for raw in addresses:
            ip = ipaddress.ip_address(raw)
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
                blocked.append(raw)
        if blocked:
            raise ValueError("Private, loopback, link-local, or reserved targets are disabled. Set ALLOW_PRIVATE_TARGETS=1 for authorized local labs.")
    return target.rstrip("/")


def safe_get(target):
    current = validate_target(target)
    session = requests.Session()
    session.headers.update({"User-Agent": "WebGuard/2.0 (authorized-security-assessment)"})
    for _ in range(MAX_REDIRECTS + 1):
        response = session.get(current, timeout=TIMEOUT, allow_redirects=False, stream=False)
        if response.is_redirect or response.is_permanent_redirect:
            location = response.headers.get("Location")
            if not location:
                break
            current = validate_target(urljoin(current, location))
            continue
        return response
    raise ValueError("Too many redirects or an invalid redirect target was encountered.")


def perform_scan(target):
    target = validate_target(target)
    response = safe_get(target)
    findings = []
    findings.extend(analyze_headers(response.headers))
    findings.extend(analyze_cookies(response))
    findings.extend(analyze_advanced(response))

    if response.url.startswith("http://"):
        findings.append({
            "category": "Transport Security",
            "title": "Target is served over HTTP",
            "severity": "high",
            "description": "The final URL does not use HTTPS.",
            "recommendation": "Serve authenticated and sensitive content exclusively over HTTPS and redirect HTTP to HTTPS.",
        })

    links = discover_links(response.url, response.text)
    score, level = calculate_score(findings)
    counts = {severity: sum(1 for f in findings if f.get("severity") == severity) for severity in ("critical", "high", "medium", "low")}
    return {
        "target": target,
        "final_url": response.url,
        "status_code": response.status_code,
        "content_type": response.headers.get("Content-Type", "unknown"),
        "response_time_ms": round(response.elapsed.total_seconds() * 1000, 2),
        "score": score,
        "level": level,
        "counts": counts,
        "links": links,
        "findings": findings,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
    }


@app.after_request
def security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    response.headers.setdefault("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; base-uri 'self'; frame-ancestors 'none'")
    return response


@app.get("/health")
def health():
    return jsonify({"status": "ok", "service": "WebGuard", "version": "2.0"})


@app.route("/")
def index():
    init_db()
    conn = db()
    scans = conn.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 10").fetchall()
    conn.close()
    return render_template("index.html", scans=scans)


@app.post("/scan")
@limiter.limit("5 per minute")
def scan():
    target = request.form.get("target", "").strip()
    try:
        result = perform_scan(target)
        init_db()
        conn = db()
        cursor = conn.execute(
            "INSERT INTO scans(target, score, level, findings, created_at) VALUES (?, ?, ?, ?, ?)",
            (result["target"], result["score"], result["level"], json.dumps(result["findings"]), result["scanned_at"]),
        )
        result["scan_id"] = cursor.lastrowid
        conn.commit()
        conn.close()
        return render_template("report.html", result=result)
    except (requests.RequestException, ValueError) as exc:
        init_db()
        conn = db()
        scans = conn.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 10").fetchall()
        conn.close()
        return render_template("index.html", scans=scans, error=str(exc)), 400


@app.get("/api/scans")
def api_scans():
    init_db()
    conn = db()
    rows = conn.execute("SELECT id, target, score, level, created_at FROM scans ORDER BY id DESC LIMIT 20").fetchall()
    conn.close()
    return jsonify([dict(row) for row in rows])


@app.get("/api/scans/<int:scan_id>")
def api_scan(scan_id):
    init_db()
    conn = db()
    row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    conn.close()
    if row is None:
        return jsonify({"error": "Scan not found"}), 404
    result = dict(row)
    result["findings"] = json.loads(result["findings"])
    return jsonify(result)


init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=False)
