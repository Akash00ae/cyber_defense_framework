# Intelligent Cyber Defense Framework

A **behavior-based intrusion detection and cyber deception** system that analyzes user input for malicious patterns, calculates risk scores, and redirects attackers to realistic decoy environments while logging all activity for monitoring and analysis.

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Running the Application](#running-the-application)
- [Project Structure](#project-structure)
- [How It Works](#how-it-works)
- [Attack Detection](#attack-detection)
- [Decoy Website System](#decoy-website-system)
- [Routing Logic](#routing-logic)
- [Admin Dashboard](#admin-dashboard)
- [API Reference](#api-reference)
- [Logging](#logging)
- [Configuration](#configuration)
- [Testing](#testing)
- [Security Notes](#security-notes)

---

## Overview

The framework acts as a **secure gateway**: users enter a keyword or query (optionally with a target site name). The system:

1. **Extracts** the target website keyword (e.g. `amazon`, `youtube`).
2. **Analyzes** the full input for malicious patterns (SQL injection, XSS, command injection, etc.).
3. **Scores** the request using configurable risk weights.
4. **Redirects** the user:
   - **Safe requests** → Real website or Google search.
   - **Malicious requests** → Brand-specific decoy page (if the site is supported) or a generic decoy.

All requests and decoy interactions are **logged** for security monitoring and analytics.

---

## Features

- **Behavior analysis** – Pattern-based detection of SQL injection, XSS, command injection, path traversal, path injection, encoded attacks, and anomalous input length/special characters.
- **Dynamic risk scoring** – Configurable weights and threshold; score ≥ threshold → abnormal.
- **Brand-specific decoys** – 10 supported sites (Amazon, Netflix, Flipkart, YouTube, BookMyShow, MakeMyTrip, Instagram, Facebook, Google, Twitter) with UI-mimic decoy pages.
- **Generic decoy** – For malicious requests when the target site is not in the supported list.
- **Real-time dashboard** – Statistics, charts (monthly activity, hourly trend, risk distribution, top IPs), activity feed, and configurable risk parameters.
- **Logging** – Every request logs: timestamp, user input, risk score, status, IP, details, detected site, and redirect destination. Decoy page interactions are also logged.
- **CSV export** – Export security logs for external analysis.
- **No intrusive alerts** – Malicious users are redirected to decoys without seeing a “threat detected” message.

---

## Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   Landing Page  │────▶│  /analyze_request │────▶│ Behavior Engine │
│   (index.html)  │     │  (Flask app.py)   │     │ (behavior_engine)│
└─────────────────┘     └────────┬─────────┘     └────────┬─────────┘
                                 │                         │
                                 │                 ┌───────▼───────┐
                                 │                 │ Risk Scoring  │
                                 │                 │(risk_scoring) │
                                 │                 └───────┬───────┘
                                 │                         │
                                 │                 ┌───────▼───────┐
                                 │                 │   Database    │
                                 │                 │  (SQLite)     │
                                 │                 └───────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │  Redirect: normal → URL │
                    │  abnormal → decoy page  │
                    └────────────────────────┘
```

- **Frontend:** HTML/CSS/JS (landing + dashboard).
- **Backend:** Flask (Python).
- **Storage:** SQLite (`database/security_logs.db`).
- **Detection:** `behavior_engine.py` (pattern analysis) + `risk_scoring.py` (score and threshold).

---

## Prerequisites

- **Python 3.7+**
- **Flask** (`pip install flask`)

No other external services are required. SQLite is used for persistence.

---

## Installation

1. **Clone or download** the project into a folder (e.g. `cyber_defense_framework`).

2. **Create a virtual environment (recommended):**
   ```bash
   python -m venv venv
   venv\Scripts\activate    # Windows
   # or: source venv/bin/activate   # Linux/macOS
   ```

3. **Install Flask:**
   ```bash
   pip install flask
   ```

4. **Optional:** Create a `requirements.txt` with:
   ```
   flask>=2.0
   ```
   Then run: `pip install -r requirements.txt`

---

## Running the Application

From the project root:

```bash
python app.py
```

You should see:

```
  +==================================================+
  |   Intelligent Cyber Defense Framework            |
  |   Running on http://127.0.0.1:5000               |
  |   Dashboard: http://127.0.0.1:5000/dashboard     |
  +==================================================+
```

- **Landing page (user entry):** http://127.0.0.1:5000  
- **Admin dashboard:** http://127.0.0.1:5000/dashboard  

Stop the server with **Ctrl+C**.

---

## Project Structure

```
cyber_defense_framework/
├── app.py                    # Flask app, routes, site detection, redirect logic
├── behavior_engine.py        # Input analysis (SQLi, XSS, command injection, etc.)
├── risk_scoring.py           # Risk score calculation and classification
├── database.py               # SQLite schema, log_request, decoy logs, config, stats
├── README.md                 # This file
├── ATTACK_DETECTION_CHECKLIST.md
├── database/                 # Created at runtime
│   └── security_logs.db      # SQLite database
├── static/
│   ├── css/
│   │   └── style.css         # Global + decoy Google-style + dashboard styles
│   └── js/
│       ├── main.js           # Landing page: submit, loader, redirect (no toast)
│       └── dashboard.js     # Dashboard: stats, charts, logs, config
└── templates/
    ├── index.html            # Landing page with search/keyword input
    ├── dashboard.html        # Admin dashboard
    ├── decoy_generic.html    # Generic decoy (unsupported site + malicious)
    ├── decoy_amazon.html     # Amazon-style decoy
    ├── decoy_netflix.html
    ├── decoy_flipkart.html
    ├── decoy_youtube.html
    ├── decoy_bookmyshow.html
    ├── decoy_makemytrip.html
    ├── decoy_instagram.html
    ├── decoy_facebook.html
    ├── decoy_google.html
    ├── decoy_twitter.html
    ├── decoy_login.html      # Legacy decoy (login panel)
    ├── decoy_admin.html      # Legacy decoy (admin panel)
    └── decoy_files.html      # Legacy decoy (file listing)
```

---

## How It Works

1. **User** enters text in the landing page (e.g. `amazon`, `youtube <script>alert(1)</script>`, `reddit ; rm -rf /`).
2. **Frontend** sends a POST to `/analyze_request` with `{ "keyword": "<user input>" }`.
3. **Backend**:
   - Trims input, caps length at 2000 characters.
   - **Extracts site keyword:** first token (split on space, `;`, `|`, `&`), lowercased; must exactly match one of the 10 supported site names.
   - **Runs behavior analysis** (`behavior_engine.analyze_keyword_structure`) → list of findings (e.g. `sql_injection`, `xss_attempt`, `command_injection`).
   - **Checks repeated requests** from same IP in the last 60 seconds (configurable).
   - **Calculates risk score** from configurable weights; if score ≥ threshold → status `abnormal`, else `normal`.
4. **Redirect decision:**
   - **Normal**  
     - If a supported site was detected → redirect to that site’s real URL (e.g. https://www.amazon.com).  
     - Otherwise → redirect to Google search with the full query.
   - **Abnormal**  
     - If a supported site was detected → redirect to `/decoy/<site>` (brand decoy).  
     - Otherwise → redirect to `/decoy/generic` (generic decoy).
5. **Logging:** Every request is stored with timestamp, user_input, risk_score, status, ip_address, details, detected_site, redirect_destination.
6. **Frontend:** For normal requests, opens the redirect URL in a new tab. For abnormal, redirects in the same tab (no “threat detected” message).

---

## Attack Detection

The behavior engine detects the following (each can add to the risk score):

| Category | Examples / patterns |
|----------|----------------------|
| **SQL injection** | `SELECT`, `UNION`, `OR 1=1`, `--`, `;`, `DROP`, `WAITFOR DELAY`, `CHAR(`, hex `0x...` |
| **XSS** | `<script>`, `javascript:`, `onerror=`, `<iframe>`, `<img ... onerror` |
| **Command injection** | `;`, `&&`, `\|\|`, `` ` ``, `$`, and shell commands: `cat`, `ls`, `dir`, `whoami`, `pwd`, `id`, `uname` |
| **Path traversal** | `../`, `..\`, `%2e%2e` |
| **Path injection** | `/etc/passwd`, `C:\Windows\`, `/proc/self`, `/var/www`, etc. |
| **Encoded attacks** | URL-encoded payloads (e.g. `%3Cscript%3E`, `%27%20OR%201%3D1`) decoded and re-analyzed |
| **Long input** | Length &gt; 50 characters (configurable) |
| **Excessive special chars** | More than 3 special characters, or 5+ of the same character in a row |
| **Repeated requests** | Same IP sends 3+ requests within 60 seconds (configurable) |

See `ATTACK_DETECTION_CHECKLIST.md` and `RESTRICTED_INPUTS_TEST_LIST.md` (if present) for detailed test inputs.

---

## Decoy Website System

### Supported sites (10)

- amazon  
- netflix  
- flipkart  
- youtube  
- bookmyshow  
- makemytrip  
- instagram  
- facebook  
- google  
- twitter  

### Decoy pages

- **Brand decoys** (`decoy_<site>.html`): UI-only mimic of each brand (login/search/nav, brand colors). No real auth or backend. All interactions are sent to `/decoy/action` and logged with `decoy_type` = site name.
- **Generic decoy** (`decoy_generic.html`): Used when the input is malicious but the first token is not one of the 10 supported sites (e.g. `reddit ; rm -rf /`).
- **Legacy decoys** (`decoy_login`, `decoy_admin`, `decoy_files`): Still available at `/decoy`, `/decoy/admin`, `/decoy/files` for backward compatibility; not used by the main routing for the 10 sites.

### Design

- Layout, colors, and typography approximate the real site.
- Placeholder content only; no real authentication, payments, or APIs.
- Buttons/links and form submissions are logged for attacker observation.

---

## Routing Logic

| User input type | Detected site | Status | Redirect |
|-----------------|---------------|--------|----------|
| `amazon` | amazon | normal | https://www.amazon.com |
| `amazon ; cat /etc/passwd` | amazon | abnormal | `/decoy/amazon` |
| `youtube <script>alert(1)</script>` | youtube | abnormal | `/decoy/youtube` |
| `reddit ; rm -rf /` | (none) | abnormal | `/decoy/generic` |
| `hello world` | (none) | normal | Google search with query |
| `netflix` | netflix | normal | https://www.netflix.com |

Site keyword is the **first token** only (split on spaces and `;|&`). It must match one of the 10 names exactly (case-insensitive).

---

## Admin Dashboard

**URL:** http://127.0.0.1:5000/dashboard  

- **Overview:** Total requests, abnormal attempts, normal requests, active sessions, decoy interactions.
- **Charts:** Monthly activity, hourly trend, risk distribution, top IPs (Chart.js).
- **Activity feed:** Recent requests with risk badge and IP.
- **Logs table:** ID, timestamp, input, risk score, status, IP, detected site, redirect destination, details. Auto-refresh.
- **Configuration:** Edit risk threshold, score weights, long-keyword length, repeat window, repeat count limit. Changes apply immediately.
- **Export:** “Export logs” downloads `security_logs.csv`.

---

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Landing page |
| POST | `/analyze_request` | Body: `{ "keyword": "..." }`. Returns status, risk_score, threshold, details, breakdown, findings, redirect_url. |
| GET | `/dashboard` | Dashboard HTML |
| GET | `/api/stats` | Aggregate stats (total, abnormal, normal, active sessions, decoy interactions) |
| GET | `/api/logs?limit=N` | Recent security logs (default 50, max 500) |
| GET | `/api/monthly_data` | Monthly activity for charts |
| GET | `/api/hourly_trend` | Last 24h hourly trend |
| GET | `/api/risk_distribution` | Risk score buckets |
| GET | `/api/top_ips` | Top IPs by request count |
| GET/POST | `/api/config` | Get or update risk config (see Configuration) |
| GET | `/export_logs` | CSV download of all security logs |
| GET | `/decoy/<site>` | Brand decoy page for `site` (e.g. amazon, youtube) |
| GET | `/decoy/generic` | Generic decoy |
| POST | `/decoy/action` | Log decoy interaction (type, action, details) |
| POST | `/decoy/login_attempt` | Log decoy login attempt (used by some decoys) |

---

## Logging

### Security logs (`security_logs`)

- **timestamp** – Request time (ISO).
- **user_input** – Raw input (trimmed, max 2000 chars).
- **risk_score** – Calculated score.
- **status** – `normal` or `abnormal`.
- **ip_address** – Client IP.
- **details** – Human-readable summary of findings.
- **detected_site** – Extracted site keyword or empty.
- **redirect_destination** – Final URL or path user was sent to.

### Decoy interactions (`decoy_interactions`)

- **timestamp**, **ip_address**, **decoy_type** (e.g. site name or `generic`), **action** (e.g. page_view, login_attempt), **data** (optional details).

---

## Configuration

Stored in `risk_config` (SQLite). Adjust via Dashboard **Configuration** or `POST /api/config` with JSON, e.g.:

```json
{
  "risk_threshold": 5,
  "long_keyword_score": 2,
  "special_chars_score": 3,
  "repeated_requests_score": 4,
  "sql_injection_score": 5,
  "long_keyword_length": 50,
  "repeat_window_seconds": 60,
  "repeat_count_limit": 3
}
```

- **risk_threshold** – Score ≥ this → abnormal.
- **long_keyword_length** – Input length above this adds long_keyword finding.
- **repeat_window_seconds** / **repeat_count_limit** – Same IP with this many requests in this many seconds adds repeated_requests.

---

## Testing

1. **Normal + supported site:** e.g. `amazon` → real Amazon.
2. **Normal + no site:** e.g. `weather today` → Google search.
3. **Malicious + supported site:** e.g. `amazon ; whoami` → Amazon decoy.
4. **Malicious + unsupported site:** e.g. `reddit ; cat /etc/passwd` → generic decoy.

Use the dashboard **Logs** tab to verify detected_site, status, and redirect_destination. See `ATTACK_DETECTION_CHECKLIST.md` and any restricted-input test list in the repo for more examples.

---

## Security Notes

- **Development server:** Flask’s built-in server is not suitable for production. Use a production WSGI server (e.g. Gunicorn, uWSGI) and HTTPS in production.
- **Secret key:** The app uses `os.urandom(32)`. For production, set a stable `app.secret_key` via environment or config.
- **Database:** SQLite file is under `database/`. Restrict file permissions and backups as per your policy.
- **Decoys:** Decoy pages do not implement real authentication or sensitive operations; they are for observation and logging only.

---

## License and Author

Part of the **Intelligent Cyber Defense Framework** project. Use and modify as needed for your environment. For detailed attack coverage and test cases, see `ATTACK_DETECTION_CHECKLIST.md` in the repository.
"# Cyber-Defense-Framework" 
