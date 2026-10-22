# Web Checker

Automated web vulnerability checker for the five most common online
vulnerabilities: **SQL Injection, Cross-Site Scripting (XSS), Broken Access
Control, Cryptographic Failures, and Identification & Authentication Failures.**

Black-box (DAST) scanner built with a **Python/Flask** engine + **React/Vite**
dashboard + **SQLite** storage.

## Project layout

```
web-checker/
├── backend/                  # Python scanning engine + API
│   ├── app.py                # Flask app entry point
│   ├── config.py             # Settings / .env config
│   ├── api/                  # HTTP routes (auth, scan, report)
│   ├── core/                 # crawler, request handler, orchestrator
│   ├── scanners/             # 5 vulnerability scanners
│   ├── payloads/             # test payload wordlists
│   ├── models/               # User / Session / Scan / Vulnerability models
│   ├── database/             # schema + db helpers
│   ├── reports/              # JSON report + PDF export
│   ├── auth/                 # password hashing, tokens, login decorator
│   └── tests/                # vulnerable demo target (port 5001)
└── frontend/                 # React dashboard (Vite)
    ├── src/
    │   ├── components/       # Register/Login/Scan/Progress/Table/Remediation
    │   ├── pages/            # Dashboard, Scan, Report, Login, Register
    │   ├── api/apiClient.js  # fetch wrapper (uses Vite /api proxy)
    │   └── styles/main.css
    ├── index.html
    └── vite.config.js        # dev port 5173 + /api → :5000 proxy
```

## Prerequisites

- Python 3.10+
- Node.js 18+
- (Optional) Chrome for Selenium/SPA crawling — the scanner falls back
  gracefully when Chrome is not available.

## Setup

### Backend

```bash
cd web-checker/backend
python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env              # optional: customise SECRET_KEY / DB path
```

### Frontend

```bash
cd web-checker/frontend
npm install
```

## Run

Terminal 1 — backend API (http://localhost:5000):

```bash
cd web-checker
PYTHONPATH=$PWD backend/venv/bin/python backend/app.py
```

Terminal 2 — frontend (http://localhost:5173):

```bash
cd web-checker/frontend
npm run dev
```

Open http://localhost:5173, register/login, enter a target URL and view the
report (results + remediation). The report is also exportable as PDF
(`/api/report/pdf/<scan_id>`).

### Local testing target

`backend/tests/vulnerable_target.py` is an intentionally vulnerable demo app
used to validate the scanner. Run it on port 5001 and scan
`http://127.0.0.1:5001`:

```bash
cd web-checker
PYTHONPATH=$PWD backend/venv/bin/python backend/tests/vulnerable_target.py
```

## API

All scan/report endpoints require a valid bearer token. Obtain one from
`/api/auth/register` or `/api/auth/login` and send it as
`Authorization: Bearer <token>`. Passwords are stored as scrypt hashes and
token digests are stored hashed (SHA-256); login is rate limited (5 failures
per 15 minutes).

| Method | Endpoint                         | Description                        | Auth |
|--------|----------------------------------|------------------------------------|------|
| POST   | `/api/auth/register`             | Register a user (auto-login)       | –    |
| POST   | `/api/auth/login`                | Login → returns bearer token       | –    |
| GET    | `/api/auth/me`                   | Current user                       | ✓    |
| POST   | `/api/auth/logout`               | Revoke the current token           | ✓    |
| POST   | `/api/scan/start`                | Run a scan on a URL                | ✓    |
| GET    | `/api/scan/status/<scan_id>`     | Scan status / progress             | ✓    |
| GET    | `/api/scan/result/<scan_id>`     | Full scan result                   | ✓    |
| GET    | `/api/report/generate/<scan_id>` | Structured report                  | ✓    |
| GET    | `/api/report/pdf/<scan_id>`      | PDF report download                | ✓    |

### Example

```bash
TOKEN=$(curl -s -X POST localhost:5000/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"demo","password":"secret123"}' | python3 -c \
  "import sys,json;print(json.load(sys.stdin)['token'])")

curl -X POST localhost:5000/api/scan/start \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"targetUrl":"http://127.0.0.1:5001"}'
```

## Safety note

Only scan applications you are explicitly authorised to test. The scanner
sends real requests (GET/POST with payloads) to the target.