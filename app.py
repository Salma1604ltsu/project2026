import json
import os
import sqlite3
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests
from flask import Flask, jsonify, render_template, request

from scanner.cookies import analyze_cookies
from scanner.crawler import discover_links
from scanner.headers import analyze_headers
from scanner.risk_score import calculate_score

app = Flask(__name__)
DB = os.getenv("WEBGUARD_DB", "webguard.db")
TIMEOUT = 8


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


def validate_target(target):
    parsed = urlparse(target)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("Enter a complete HTTP or HTTPS URL.")
    if parsed.username or parsed.password:
        raise ValueError("Credentials in URLs are not supported.")
    return target.rstrip("/")


def perform_scan(target):
    target = validate_target(target)
    response = requests.get(
        target,
        timeout=TIMEOUT,
        allow_redirects=True,
        headers={"User-Agent": "WebGuard/1.0 (authorized-security-assessment)"},
    )
    findings = []
    findings.extend(analyze_headers(response.headers))
    findings.extend(analyze_cookies(response))

    if response.url.startswith("http://"):
        findings.append({
            "category": "Transport Security",
            "title": "Target is served over HTTP",
            "severity": "high",
            "description": "The final URL does not use HTTPS.",
            "recommendation": "Serve authenticated and sensitive content exclusively over HTTPS and redirect HTTP to HTTPS.",
        })

    links = discover_links(target, response.text)
    score, level = calculate_score(findings)
    return {
        "target": target,
        "final_url": response.url,
        "status_code": response.status_code,
        "score": score,
        "level": level,
        "links": links,
        "findings": findings,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
    }


@app.route("/")
def index():
    init_db()
    conn = db()
    scans = conn.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 10").fetchall()
    conn.close()
    return render_template("index.html", scans=scans)


@app.post("/scan")
def scan():
    target = request.form.get("target", "").strip()
    try:
        result = perform_scan(target)
        init_db()
        conn = db()
        conn.execute(
            "INSERT INTO scans(target, score, level, findings, created_at) VALUES (?, ?, ?, ?, ?)",
            (result["target"], result["score"], result["level"], json.dumps(result["findings"]), result["scanned_at"]),
        )
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
    rows = conn.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 20").fetchall()
    conn.close()
    return jsonify([dict(row) for row in rows])


init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=False)
