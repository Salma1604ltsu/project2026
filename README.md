# 🛡️ WebGuard 2.0

**Defensive Web Application Security Assessment Platform**

WebGuard is a Python/Flask security assessment dashboard for **authorized** web applications. It performs passive, non-destructive checks and turns configuration signals into severity-rated findings and remediation guidance.

## 🚀 What WebGuard checks

- Security headers: CSP, HSTS, X-Frame-Options, Referrer-Policy, Permissions-Policy, MIME sniffing protection
- Cookie flags: Secure, HttpOnly, SameSite
- HTTPS / transport security
- CORS wildcard configuration indicators
- Cache-Control configuration indicators
- Password forms submitting over HTTP
- Potential mixed-content references
- Same-site link discovery
- Severity-weighted risk score (0–100)
- Scan history in SQLite
- JSON API for scan history and individual reports
- Health endpoint for deployment monitoring
- Production Gunicorn configuration
- GitHub Actions CI test workflow

## 🔎 API Security Testing Tool

The repository now includes a separate defensive API assessment module at `api_security_tool/`.

It checks:

- Authentication behavior and unauthenticated exposure
- Authorization differences between two supplied test principals
- Security response headers
- Wildcard CORS
- Small-sample rate-limit signals
- Verbose error disclosure
- JSON/content-type consistency

Example:

```bash
python -m api_security_tool --url https://api.example.com/v1/users
```

Authenticated check:

```bash
python -m api_security_tool --url https://api.example.com/v1/users --token "$API_TOKEN"
```

Two-principal authorization comparison:

```bash
python -m api_security_tool \
  --url https://api.example.com/v1/users/123 \
  --token-a "$USER_A_TOKEN" \
  --token-b "$USER_B_TOKEN"
```

JSON report:

```bash
python -m api_security_tool --url https://api.example.com/v1/users --json
```

The API module is deliberately non-destructive. It uses GET/HEAD/OPTIONS only and a small rate-limit sample. Authorization differences are reported as observations for manual validation, not automatically classified as vulnerabilities.

## 🧱 Architecture

```text
Browser
   │
   ▼
Flask Dashboard ───────► SQLite Scan History
   │
   ├── Web Security Scanner
   │
   └── API Security Tool
          │
          ├── Target validation + DNS/IP safety checks
          ├── Authentication checks
          ├── Authorization comparison
          ├── Headers / CORS
          ├── Rate-limit signals
          └── Error/content-type analysis
```

## 🔐 Safety controls

WebGuard is deliberately designed as a **defensive assessment tool**, not an exploitation framework. It does not brute-force credentials, inject attack payloads, execute JavaScript against targets, or attempt destructive actions.

For a public deployment, private/loopback/link-local/reserved targets are blocked by default to reduce SSRF risk. Set `ALLOW_PRIVATE_TARGETS=1` **only in a controlled, authorized local lab**.

The API tool also blocks state-changing HTTP methods by default.

## 🛠️ Tech Stack

- Python 3.11+
- Flask
- Requests
- BeautifulSoup 4
- Flask-Limiter
- SQLite
- Gunicorn
- GitHub Actions
- HTML/CSS/JavaScript

## ▶️ Local setup

```bash
python -m venv .venv

# Windows
.venv\\Scripts\\activate

# Linux/macOS
source .venv/bin/activate

pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000`.

To scan an authorized local/private lab target, set:

```text
ALLOW_PRIVATE_TARGETS=1
```

## ☁️ Render deployment

The repository includes `render.yaml` with the production build/start configuration:

```text
Build: pip install -r requirements.txt
Start: gunicorn app:app
```

## 🔌 API

- `GET /health` — service health and version
- `GET /api/scans` — recent scan metadata
- `GET /api/scans/<id>` — a saved scan with findings

## 📁 Project structure

```text
WebGuard/
├── app.py
├── requirements.txt
├── render.yaml
├── .env.example
├── .gitignore
├── api_security_tool/
│   ├── __init__.py
│   ├── __main__.py
│   ├── cli.py
│   ├── scanner.py
│   └── README.md
├── scanner/
│   ├── __init__.py
│   ├── advanced.py
│   ├── headers.py
│   ├── cookies.py
│   ├── crawler.py
│   └── risk_score.py
├── templates/
│   ├── base.html
│   ├── index.html
│   └── report.html
├── static/
│   └── style.css
├── tests/
│   ├── test_scanner.py
│   └── test_api_security_tool.py
└── .github/
    └── workflows/
        └── ci.yml
```

## ⚠️ Responsible use

Only assess systems you own or where you have explicit authorization. Findings are indicators for defensive review and should be manually validated before remediation.

## 📌 Portfolio

**Live Demo:** https://webguard-ygyx.onrender.com/

**GitHub:** https://github.com/Salma1604ltsu/project2026
