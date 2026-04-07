# 🛡️ CyberGuard v2 — Business Website Security Review Platform

A professional, portfolio-ready cybersecurity SaaS tool built with Python & Streamlit.

---

## Features

- **Authentication** — Signup/login with bcrypt-hashed passwords stored in SQLite
- **HTTPS & Protocol checks** — Detects HTTP→HTTPS redirects
- **SSL/TLS inspection** — Issuer, expiry date, days remaining
- **Security Headers analysis** — CSP, HSTS, X-Frame-Options, and more
- **Cookie security** — Checks for Secure, HttpOnly, SameSite flags
- **Information Disclosure** — Server/X-Powered-By header detection
- **Safe endpoint checks** — robots.txt, security.txt, sitemap.xml
- **Risk scoring** — 0–100 score with Strong / Moderate / Needs Improvement / High Risk
- **PDF report generator** — Client-ready A4 PDF via ReportLab
- **Premium dark SaaS UI** — Syne + DM Sans fonts, glassmorphism cards

---

## Quick Start

```bash
cd cyberguard
pip install -r requirements.txt
streamlit run app.py
```

Open http://localhost:8501 in your browser.

---

## Project Structure

```
cyberguard/
├── app.py              # Main Streamlit application
├── requirements.txt    # Python dependencies
├── cyberguard.db       # SQLite database (auto-created)
└── utils/
    ├── auth.py         # Authentication & user management
    ├── scanner.py      # Website security checks
    └── report.py       # PDF report generator
```

---

## Deploy to Streamlit Cloud

1. Push this folder to a GitHub repository
2. Visit https://share.streamlit.io
3. Connect your repo and set **Main file path** to `app.py`
4. Deploy — no extra config needed

---

## ⚠ Disclaimer

CyberGuard performs **passive, defensive checks only**.  
Only scan websites you own or have explicit written permission to assess.  
This tool does not perform any offensive, intrusive, or exploitative testing.

---

*Built by Pamupro Cyber — for authorized security reviews, portfolio demonstrations, and client deliverables.*
