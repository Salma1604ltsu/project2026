# 🛡️ WebGuard

A defensive, resume-ready web application security assessment dashboard built with Python and Flask.

## Features

- Security header analysis
- Cookie security auditing
- HTTPS/TLS configuration indicators
- HTTP method checks
- Basic endpoint discovery for authorized targets
- Risk scoring with severity levels
- Scan history stored in SQLite
- Clean responsive dashboard
- JSON security report export

> **Authorized-use only:** WebGuard is designed for localhost, lab environments, and web applications you own or have explicit permission to assess. It intentionally avoids destructive exploitation and credential attacks.

## Tech Stack

- Python 3.11+
- Flask
- Requests
- BeautifulSoup 4
- SQLite
- HTML/CSS/JavaScript

## Quick Start

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

## Project Structure

```text
WebGuard/
├── app.py
├── requirements.txt
├── scanner/
│   ├── __init__.py
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
└── README.md
```

## Responsible Use

Only scan systems for which you have explicit authorization. Findings are indicators for defensive assessment and should be manually validated before remediation.
