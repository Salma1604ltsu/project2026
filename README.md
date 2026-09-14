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

## 🧱 Architecture

```text
Browser
   │
   ▼
Flask Dashboard ───────► SQLite Scan History
   │
   ▼
Safe HTTP Client
   │
   ├── Target validation + DNS/IP safety checks
   ├── Redirect validation (max 3)
   └── Passive response analysis
          ├── Headers
          ├── Cookies
          ├── HTML/forms
          ├── CORS/cache indicators
          └── Link discovery
```

## 🔐 Safety controls

WebGuard is deliberately designed as a **defensive assessment tool**, not an exploitation framework. It does not brute-force credentials, inject attack payloads, execute JavaScript against targets, or attempt destructive actions.

For a public deployment, private/loopback/link-local/reserved targets are blocked by default to reduce SSRF risk. Set `ALLOW_PRIVATE_TARGETS=1` **only in a controlled, authorized local lab**.

The `/scan` endpoint is rate-limited to help protect a public deployment from abuse.

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
│   └── test_scanner.py
└── .github/
    └── workflows/
        └── ci.yml
```

## ⚠️ Responsible use

Only assess systems you own or where you have explicit authorization. Findings are indicators for defensive review and should be manually validated before remediation.

## 📌 Portfolio

**Live Demo:** https://webguard-ygyx.onrender.com/

**GitHub:** https://github.com/Salma1604ltsu/project2026
