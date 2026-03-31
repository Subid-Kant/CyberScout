# CyberScout v2.0 — Web Vulnerability Assessment Tool

A production-ready web vulnerability scanner built with Flask.

---

## Features

| Module | What it checks |
|---|---|
| **Headers** | 10 security headers, CSP misconfig, HSTS, cookie flags, CORS |
| **SSL/TLS** | Cert expiry (tiered), SAN, wildcard, weak ciphers, HSTS preload |
| **Ports** | 30+ ports, CVE hints, OS risk notes, banner grabbing |
| **SQLi** | Error-based, boolean-blind, time-based SQL injection |
| **XSS** | Reflected, stored, DOM sink detection |
| **Dir Brute** | 100+ paths, severity tiers, backup extension second pass |
| **Reports** | PDF with Risk Score (0–100), executive summary, color-coded findings |

**Production features:** User auth (bcrypt), scan history DB (SQLite/SQLAlchemy), rate limiting (5/min per IP), Docker support.

---

## Quick Start

### Local
```bash
pip install -r requirements.txt
python app.py --web
# Open http://localhost:5000
```

### Docker
```bash
docker-compose up --build
# Open http://localhost:5000
```

### CLI Mode
```bash
python app.py --target https://example.com --mode full
python app.py --target https://example.com --mode headers
python app.py --target 192.168.1.1 --mode ports --range 1-65535
```

---

## API

| Endpoint | Method | Description |
|---|---|---|
| `POST /api/scan` | POST | Start a scan |
| `GET /api/status/<id>` | GET | Poll scan progress |
| `GET /api/results/<id>` | GET | Get findings + risk score |
| `GET /api/report/<id>` | GET | Download PDF report |
| `GET /api/history` | GET | Scan history (auth required) |
| `DELETE /api/history/<id>` | DELETE | Delete scan (auth required) |
| `GET /api/stats` | GET | Aggregate statistics (auth required) |
| `POST /auth/register` | POST | Create account |
| `POST /auth/login` | POST | Log in |
| `POST /auth/logout` | POST | Log out |
| `GET /auth/me` | GET | Current user info |

### Scan request body
```json
{
  "target": "https://example.com",
  "modules": ["headers", "ssl", "sqli", "xss", "ports", "dirs"],
  "scan_id": "optional-custom-id"
}
```

---

## Running Tests
```bash
pip install pytest responses
pytest tests/ -v
```

---

## ⚠️ Legal Notice

Only scan systems you own or have **explicit written permission** to test.
Unauthorized scanning may be illegal under the CFAA, Computer Misuse Act, or equivalent laws.
