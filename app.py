"""
CyberGuard — Website Security Review Platform
Single-file Streamlit app. Streamlit Cloud compatible.
"""

import hashlib, io, os, socket, sqlite3, ssl
from contextlib import closing
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

import requests
import streamlit as st
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    BaseDocTemplate, Frame, HRFlowable,
    PageTemplate, Paragraph, Spacer, Table, TableStyle,
)

# ── Page config (must be first) ──────────────────────────────
st.set_page_config(
    page_title="CyberGuard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ── CSS ───────────────────────────────────────────────────────
st.markdown("""
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:ital,opsz,wght@0,14..32,300;0,14..32,400;0,14..32,500;0,14..32,600;1,14..32,400&display=swap" rel="stylesheet">

<style>
/* ── Design tokens ─────────────────────────────── */
:root {
  --bg:       #09090b;
  --bg1:      #18181b;
  --bg2:      #27272a;
  --bg3:      #3f3f46;
  --border:   rgba(255,255,255,0.08);
  --border2:  rgba(255,255,255,0.12);
  --text:     #fafafa;
  --text2:    #a1a1aa;
  --text3:    #71717a;
  --blue:     #3b82f6;
  --blue2:    #2563eb;
  --green:    #22c55e;
  --amber:    #f59e0b;
  --red:      #ef4444;
  --font:     'Inter', ui-sans-serif, system-ui, sans-serif;
  --radius:   8px;
  --radius-lg:12px;
  --radius-xl:16px;
}

/* ── Global reset ──────────────────────────────── */
*, *::before, *::after { box-sizing: border-box; }
html, body { margin: 0; padding: 0; }
html, body, [class*="css"] {
  font-family: var(--font) !important;
  -webkit-font-smoothing: antialiased;
  text-rendering: optimizeLegibility;
}
.stApp {
  background: var(--bg) !important;
  color: var(--text) !important;
}
#MainMenu, footer, header { visibility: hidden; }
.block-container {
  padding: 0 !important;
  max-width: 100% !important;
}
[data-testid="stSidebar"] {
  background: var(--bg1) !important;
  border-right: 1px solid var(--border) !important;
}
[data-testid="stSidebar"] * { color: var(--text2) !important; }

/* ── Typography overrides ──────────────────────── */
p, span, div, label, li, td, th {
  color: var(--text) !important;
  font-family: var(--font) !important;
}

/* ── Streamlit input overrides ─────────────────── */
[data-testid="stTextInput"] label {
  font-size: 11px !important;
  font-weight: 500 !important;
  letter-spacing: 0.05em !important;
  text-transform: uppercase !important;
  color: var(--text3) !important;
  margin-bottom: 6px !important;
}
[data-testid="stTextInput"] > div > div {
  background: var(--bg1) !important;
  border: 1px solid var(--border2) !important;
  border-radius: var(--radius) !important;
  transition: border-color 0.15s !important;
}
[data-testid="stTextInput"] > div > div:focus-within {
  border-color: var(--blue) !important;
  box-shadow: 0 0 0 2px rgba(59,130,246,0.15) !important;
}
[data-testid="stTextInput"] input {
  background: transparent !important;
  border: none !important;
  outline: none !important;
  color: var(--text) !important;
  font-family: var(--font) !important;
  font-size: 14px !important;
  padding: 9px 12px !important;
}
[data-testid="stTextInput"] input::placeholder { color: var(--text3) !important; }

/* ── Buttons ───────────────────────────────────── */
.stButton > button,
button[kind="primary"],
button[kind="secondary"] {
  background: var(--blue2) !important;
  color: #fff !important;
  border: none !important;
  border-radius: var(--radius) !important;
  font-family: var(--font) !important;
  font-size: 13px !important;
  font-weight: 500 !important;
  letter-spacing: -0.01em !important;
  padding: 8px 16px !important;
  line-height: 1.5 !important;
  cursor: pointer !important;
  transition: background 0.15s, opacity 0.15s !important;
  white-space: nowrap !important;
}
.stButton > button:hover { background: #1d4ed8 !important; }
.stButton > button:active { opacity: 0.85 !important; }
[data-testid="stDownloadButton"] > button {
  background: var(--bg2) !important;
  color: var(--text) !important;
  border: 1px solid var(--border2) !important;
}
[data-testid="stDownloadButton"] > button:hover {
  background: var(--bg3) !important;
  border-color: var(--blue) !important;
}

/* ── Tabs ──────────────────────────────────────── */
[data-testid="stTabs"] [role="tablist"] {
  border-bottom: 1px solid var(--border) !important;
  background: transparent !important;
  gap: 0 !important;
  padding: 0 !important;
}
[data-testid="stTabs"] button[role="tab"] {
  background: transparent !important;
  border: none !important;
  border-bottom: 2px solid transparent !important;
  border-radius: 0 !important;
  color: var(--text3) !important;
  font-family: var(--font) !important;
  font-size: 13px !important;
  font-weight: 500 !important;
  padding: 10px 16px !important;
  margin: 0 !important;
  transition: color 0.15s !important;
}
[data-testid="stTabs"] button[role="tab"][aria-selected="true"] {
  color: var(--text) !important;
  border-bottom: 2px solid var(--blue) !important;
}
[data-testid="stTabs"] button[role="tab"]:hover { color: var(--text2) !important; }
[data-testid="stTabs"] > div > div:last-child {
  padding: 20px 0 0 !important;
}

/* ── Expander ──────────────────────────────────── */
[data-testid="stExpander"] {
  background: var(--bg1) !important;
  border: 1px solid var(--border) !important;
  border-radius: var(--radius-lg) !important;
  overflow: hidden !important;
  margin-bottom: 6px !important;
}
[data-testid="stExpander"] > div:first-child {
  padding: 12px 16px !important;
  border-bottom: none !important;
}
[data-testid="stExpander"] summary {
  font-family: var(--font) !important;
  font-size: 13px !important;
  font-weight: 500 !important;
  color: var(--text) !important;
}
[data-testid="stExpander"] > div:last-child {
  padding: 0 16px 16px !important;
  background: var(--bg1) !important;
}
[data-testid="stExpander"] details[open] > div:first-child {
  border-bottom: 1px solid var(--border) !important;
}

/* ── Alert messages ────────────────────────────── */
[data-testid="stAlert"] {
  background: var(--bg1) !important;
  border-radius: var(--radius) !important;
}
[data-testid="stNotification"] {
  background: var(--bg1) !important;
  border: 1px solid var(--border) !important;
  border-radius: var(--radius) !important;
}

/* ── Spinner ───────────────────────────────────── */
[data-testid="stSpinner"] svg { color: var(--blue) !important; }

/* ── Scrollbar ─────────────────────────────────── */
::-webkit-scrollbar { width: 4px; height: 4px; background: var(--bg); }
::-webkit-scrollbar-thumb { background: var(--bg3); border-radius: 2px; }

/* ════════════════════════════════════════════════
   LAYOUT COMPONENTS
   ════════════════════════════════════════════════ */

/* Top navigation */
.cg-nav {
  height: 52px;
  padding: 0 24px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  border-bottom: 1px solid var(--border);
  background: var(--bg);
  position: sticky;
  top: 0;
  z-index: 100;
}
.cg-nav-logo {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 14px;
  font-weight: 600;
  letter-spacing: -0.02em;
  color: var(--text);
}
.cg-nav-dot {
  width: 7px;
  height: 7px;
  border-radius: 50%;
  background: var(--blue);
  flex-shrink: 0;
}
.cg-nav-user {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 12px;
  color: var(--text3);
  background: var(--bg1);
  border: 1px solid var(--border);
  border-radius: 20px;
  padding: 4px 12px 4px 8px;
}
.cg-online-dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: var(--green);
  flex-shrink: 0;
}

/* Page wrapper */
.cg-page {
  max-width: 1040px;
  margin: 0 auto;
  padding: 0 24px 64px;
}

/* Hero */
.cg-hero {
  padding: 52px 0 36px;
  border-bottom: 1px solid var(--border);
  margin-bottom: 36px;
}
.cg-eyebrow {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-size: 11px;
  font-weight: 500;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: var(--text3);
  margin-bottom: 18px;
}
.cg-eyebrow-line {
  width: 16px;
  height: 1px;
  background: var(--text3);
  display: inline-block;
}
.cg-h1 {
  font-size: 32px;
  font-weight: 600;
  letter-spacing: -0.03em;
  line-height: 1.15;
  color: var(--text);
  margin: 0 0 14px;
}
.cg-tagline {
  font-size: 14px;
  line-height: 1.6;
  color: var(--text3);
  max-width: 480px;
}

/* Scan panel */
.cg-scan-row {
  background: var(--bg1);
  border: 1px solid var(--border);
  border-radius: var(--radius-xl);
  padding: 20px;
  margin-bottom: 28px;
}
.cg-field-label {
  font-size: 11px;
  font-weight: 500;
  letter-spacing: 0.05em;
  text-transform: uppercase;
  color: var(--text3);
  margin-bottom: 6px;
}

/* Stat cards */
.cg-stats-grid {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 10px;
  margin-bottom: 24px;
}
.cg-stat {
  background: var(--bg1);
  border: 1px solid var(--border);
  border-radius: var(--radius-lg);
  padding: 18px 18px 16px;
}
.cg-stat-label {
  font-size: 11px;
  font-weight: 500;
  letter-spacing: 0.05em;
  text-transform: uppercase;
  color: var(--text3);
  margin-bottom: 10px;
}
.cg-stat-value {
  font-size: 28px;
  font-weight: 600;
  letter-spacing: -0.04em;
  line-height: 1;
  color: var(--text);
}
.cg-stat-sub {
  font-size: 12px;
  color: var(--text3);
  margin-top: 5px;
  font-weight: 400;
}
.cg-stat-value.green { color: #4ade80; }
.cg-stat-value.amber { color: #fbbf24; }
.cg-stat-value.red   { color: #f87171; }

/* Cards */
.cg-card {
  background: var(--bg1);
  border: 1px solid var(--border);
  border-radius: var(--radius-lg);
  padding: 20px;
  height: 100%;
}
.cg-card-label {
  font-size: 11px;
  font-weight: 600;
  letter-spacing: 0.06em;
  text-transform: uppercase;
  color: var(--text3);
  margin-bottom: 18px;
}

/* Key-value rows */
.cg-kv-row {
  display: flex;
  gap: 12px;
  padding: 8px 0;
  border-bottom: 1px solid var(--border);
  align-items: baseline;
}
.cg-kv-row:last-child { border-bottom: none; padding-bottom: 0; }
.cg-kv-key {
  font-size: 11px;
  font-weight: 500;
  color: var(--text3);
  min-width: 88px;
  flex-shrink: 0;
  padding-top: 1px;
}
.cg-kv-val {
  font-size: 13px;
  color: var(--text2);
  word-break: break-all;
  line-height: 1.45;
}
.cg-kv-val.mono {
  font-family: 'Fira Code', 'Cascadia Code', 'Consolas', monospace;
  font-size: 12px;
}

/* Summary bullets */
.cg-summary-item {
  display: flex;
  gap: 10px;
  padding: 10px 0;
  border-bottom: 1px solid var(--border);
  align-items: flex-start;
}
.cg-summary-item:last-child { border-bottom: none; padding-bottom: 4px; }
.cg-summary-bullet {
  width: 4px;
  height: 4px;
  border-radius: 50%;
  background: var(--blue);
  margin-top: 7px;
  flex-shrink: 0;
}
.cg-summary-text {
  font-size: 13px;
  color: var(--text2);
  line-height: 1.55;
}

/* TLS big number */
.cg-tls-days {
  font-size: 40px;
  font-weight: 600;
  letter-spacing: -0.04em;
  line-height: 1;
  margin-bottom: 4px;
}
.cg-tls-days-label {
  font-size: 12px;
  color: var(--text3);
  margin-bottom: 20px;
}

/* Section divider */
.cg-section {
  margin: 28px 0 12px;
  padding-bottom: 10px;
  border-bottom: 1px solid var(--border);
  display: flex;
  align-items: center;
  gap: 8px;
}
.cg-section-title {
  font-size: 13px;
  font-weight: 600;
  color: var(--text);
  letter-spacing: -0.01em;
}
.cg-section-meta {
  font-size: 12px;
  color: var(--text3);
}

/* Finding rows */
.cg-finding {
  padding: 12px 0;
  border-bottom: 1px solid var(--border);
}
.cg-finding:last-child { border-bottom: none; padding-bottom: 4px; }
.cg-finding-header {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 6px;
}
.cg-finding-dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  flex-shrink: 0;
}
.cg-finding-name {
  font-size: 13px;
  font-weight: 500;
  color: var(--text);
  flex: 1;
  line-height: 1.3;
}
.cg-badge {
  font-size: 10px;
  font-weight: 600;
  letter-spacing: 0.04em;
  text-transform: uppercase;
  padding: 2px 7px;
  border-radius: 4px;
  flex-shrink: 0;
}
.cg-badge-H { background:rgba(239,68,68,0.1);  color:#f87171; border:1px solid rgba(239,68,68,0.2);  }
.cg-badge-M { background:rgba(245,158,11,0.1); color:#fbbf24; border:1px solid rgba(245,158,11,0.2); }
.cg-badge-L { background:rgba(59,130,246,0.1); color:#93c5fd; border:1px solid rgba(59,130,246,0.2); }
.cg-badge-I { background:rgba(34,197,94,0.1);  color:#86efac; border:1px solid rgba(34,197,94,0.2);  }
.cg-finding-desc {
  font-size: 12px;
  color: var(--text3);
  margin: 0 0 6px 14px;
  line-height: 1.5;
}
.cg-finding-footer {
  display: flex;
  align-items: flex-start;
  gap: 8px;
  margin-left: 14px;
  flex-wrap: wrap;
}
.cg-code {
  font-family: 'Fira Code','Cascadia Code','Consolas',monospace;
  font-size: 11px;
  color: var(--text3);
  background: var(--bg2);
  border: 1px solid var(--border);
  padding: 1px 7px 2px;
  border-radius: 4px;
  max-width: 380px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.cg-rec-text {
  font-size: 12px;
  color: var(--text3);
  line-height: 1.45;
}

/* Export card */
.cg-export-info {
  font-size: 13px;
  color: var(--text3);
  line-height: 1.65;
}

/* Auth page */
.cg-auth-wrap {
  display: flex;
  align-items: center;
  justify-content: center;
  min-height: 100vh;
  padding: 24px;
  background: var(--bg);
}
.cg-auth-inner {
  width: 100%;
  max-width: 380px;
}
.cg-auth-brand {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 6px;
}
.cg-auth-brand-name {
  font-size: 15px;
  font-weight: 600;
  letter-spacing: -0.02em;
  color: var(--text);
}
.cg-auth-tagline {
  font-size: 12px;
  color: var(--text3);
  margin-bottom: 28px;
}
.cg-auth-card {
  background: var(--bg1);
  border: 1px solid var(--border);
  border-radius: var(--radius-xl);
  padding: 24px;
}
.cg-auth-title {
  font-size: 16px;
  font-weight: 600;
  letter-spacing: -0.02em;
  color: var(--text);
  margin-bottom: 20px;
}

/* Footer */
.cg-footer {
  border-top: 1px solid var(--border);
  padding: 16px 24px;
  display: flex;
  align-items: center;
  justify-content: space-between;
}
.cg-footer-text {
  font-size: 11px;
  color: var(--text3);
}
</style>
""", unsafe_allow_html=True)

# ── Auth helpers ──────────────────────────────────────────────
DB_FILE = "cyberguard.db"

def _db_init():
    with closing(sqlite3.connect(DB_FILE)) as c:
        c.execute("""CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL, email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL, created_at TEXT NOT NULL)""")
        c.commit()

def _pw_hash(p):
    s = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", p.encode(), s, 260_000)
    return f"pbkdf2${s.hex()}${dk.hex()}"

def _pw_verify(p, stored):
    try:
        _, sh, dh = stored.split("$")
        dk = hashlib.pbkdf2_hmac("sha256", p.encode(), bytes.fromhex(sh), 260_000)
        return dk.hex() == dh
    except Exception:
        return False

def create_user(name, email, password):
    try:
        with closing(sqlite3.connect(DB_FILE)) as c:
            c.execute("INSERT INTO users (name,email,password_hash,created_at) VALUES (?,?,?,?)",
                (name.strip(), email.strip().lower(), _pw_hash(password), datetime.utcnow().isoformat()))
            c.commit()
        return True, "Account created."
    except sqlite3.IntegrityError:
        return False, "That email is already registered."
    except Exception as e:
        return False, str(e)

def authenticate_user(email, password):
    with closing(sqlite3.connect(DB_FILE)) as c:
        row = c.execute("SELECT id,name,email,password_hash FROM users WHERE email=?",
            (email.strip().lower(),)).fetchone()
    if row and _pw_verify(password, row[3]):
        return True, {"id": row[0], "name": row[1], "email": row[2]}
    return False, None

# ── Scanner ───────────────────────────────────────────────────
_UA = "CyberGuard/2.0 (authorized defensive review)"

_HDR_CHECKS = {
    "Strict-Transport-Security": {"w":14,"sev":"High",
        "desc":"Forces browsers to use HTTPS for all future requests, preventing protocol downgrade attacks.",
        "fix":"Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"},
    "Content-Security-Policy": {"w":16,"sev":"High",
        "desc":"Controls which resources the browser may load, significantly reducing XSS attack surface.",
        "fix":"Define a restrictive CSP tailored to your application's resource needs."},
    "X-Frame-Options": {"w":8,"sev":"Medium",
        "desc":"Prevents the page from being embedded in iframes, blocking clickjacking attacks.",
        "fix":"Add: X-Frame-Options: DENY"},
    "X-Content-Type-Options": {"w":8,"sev":"Medium",
        "desc":"Instructs browsers not to MIME-sniff responses, preventing content-type confusion attacks.",
        "fix":"Add: X-Content-Type-Options: nosniff"},
    "Referrer-Policy": {"w":6,"sev":"Low",
        "desc":"Controls how much referrer information is included when navigating away from the page.",
        "fix":"Add: Referrer-Policy: strict-origin-when-cross-origin"},
    "Permissions-Policy": {"w":6,"sev":"Low",
        "desc":"Restricts which browser APIs and features this page may use.",
        "fix":"Define a Permissions-Policy based on your application's actual requirements."},
}
_OPT_HDRS = [
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
    "Cross-Origin-Embedder-Policy",
]
_PATHS = ["/robots.txt", "/security.txt", "/.well-known/security.txt", "/sitemap.xml"]

def _norm_url(u):
    u = u.strip()
    return ("https://" + u) if u and not u.startswith(("http://","https://")) else u

def _hostname(u): return urlparse(u).hostname or ""

def _fetch(u):
    return requests.get(u, timeout=10, headers={"User-Agent":_UA}, allow_redirects=True)

def _scan_ssl(host, port=443):
    r = {"enabled":False,"issuer":None,"subject":None,"valid_to":None,"days_remaining":None,"error":None}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                cert = ss.getpeercert()
        r["enabled"] = True
        issuer  = dict(x[0] for x in cert.get("issuer", []))
        subject = dict(x[0] for x in cert.get("subject", []))
        r["issuer"]  = issuer.get("organizationName") or str(issuer)
        r["subject"] = subject.get("commonName") or str(subject)
        vt = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        r["valid_to"] = vt.strftime("%d %b %Y")
        r["days_remaining"] = (vt.replace(tzinfo=timezone.utc) - datetime.now(timezone.utc)).days
    except Exception as e:
        r["error"] = str(e)
    return r

def _scan_protocol(in_url, fin_url):
    return [
        {"cat":"Protocol","name":"HTTPS on input URL",
         "ok":in_url.startswith("https://"),"sev":"High","w":14,"val":in_url,
         "desc":"Confirms the target URL uses an encrypted HTTPS connection.",
         "fix":"Ensure all traffic starts on https://."},
        {"cat":"Protocol","name":"HTTPS on final URL",
         "ok":fin_url.startswith("https://"),"sev":"High","w":14,"val":fin_url,
         "desc":"Confirms the final landing page after any redirects uses HTTPS.",
         "fix":"Permanently redirect all HTTP requests to HTTPS."},
    ]

def _scan_headers(resp):
    out = []
    for h, m in _HDR_CHECKS.items():
        present = h in resp.headers
        out.append({"cat":"Security Headers","name":h,"ok":present,
            "sev":"Info" if present else m["sev"],"w":m["w"],
            "val":resp.headers.get(h,"Not set"),
            "desc":m["desc"],"fix":"Configured correctly." if present else m["fix"]})
    for h in _OPT_HDRS:
        present = h in resp.headers
        out.append({"cat":"Security Headers","name":h,"ok":present,
            "sev":"Info" if present else "Low","w":3,
            "val":resp.headers.get(h,"Not set"),
            "desc":"Additional cross-origin isolation header for defence-in-depth hardening.",
            "fix":"Configured." if present else f"Consider adding {h}."})
    return out

def _scan_cookies(resp):
    raw = resp.raw.headers.get_all("Set-Cookie") if hasattr(resp.raw.headers,"get_all") else []
    if not raw:
        return [{"cat":"Cookies","name":"Set-Cookie headers","ok":True,"sev":"Info","w":0,
                 "val":"None observed","desc":"No cookies were issued in this response.","fix":"No action needed."}]
    out = []
    for i, c in enumerate(raw, 1):
        low = c.lower()
        missing = [f for f,k in [("Secure","secure"),("HttpOnly","httponly"),("SameSite","samesite")] if k not in low]
        out.append({"cat":"Cookies","name":f"Cookie #{i}","ok":not missing,
            "sev":"Info" if not missing else "Medium","w":8,
            "val":c[:80]+("…" if len(c)>80 else ""),
            "desc":"Cookie security attributes protect against theft and cross-site request forgery.",
            "fix":"All security flags present." if not missing else f"Missing flags: {', '.join(missing)}."})
    return out

def _scan_disclosure(resp):
    out = []
    for h, label in [("Server","Server header"),("X-Powered-By","X-Powered-By header")]:
        val = resp.headers.get(h)
        out.append({"cat":"Information Disclosure","name":label,"ok":not bool(val),
            "sev":"Info" if not val else "Low","w":5,"val":val or "Not exposed",
            "desc":"Exposing server/technology versions aids attackers in targeting known vulnerabilities.",
            "fix":"Not exposed." if not val else f"Remove or suppress the {h} response header."})
    return out

def _scan_paths(base_url):
    sess = requests.Session()
    out = []
    for p in _PATHS:
        url = urljoin(base_url, p)
        try:
            r = sess.get(url, timeout=5, headers={"User-Agent":_UA}, allow_redirects=True)
            ok = r.status_code == 200
            out.append({"cat":"Security Files","name":p,"ok":ok,
                "sev":"Info" if ok else "Low","w":3,
                "val":f"HTTP {r.status_code}",
                "desc":"Standard file that aids security researchers and automated scanning tools.",
                "fix":"Present and accessible." if ok else f"Consider publishing {p}."})
        except Exception:
            out.append({"cat":"Security Files","name":p,"ok":False,"sev":"Low","w":3,
                "val":"Unreachable","desc":"Standard security disclosure file.",
                "fix":f"Consider publishing {p}."})
    return out

def _calc_score(findings, ssl_info):
    mp = sum(f["w"] for f in findings if f["w"] > 0) + 10
    ea = sum(f["w"] for f in findings if f["ok"] and f["w"] > 0)
    if ssl_info.get("enabled"):
        d = ssl_info.get("days_remaining")
        ea += 10 if (d is None or d >= 45) else 6 if d >= 15 else 3 if d >= 0 else 0
    s = round(ea / mp * 100) if mp else 0
    if s >= 85: return s, "Strong"
    if s >= 70: return s, "Moderate"
    if s >= 50: return s, "Needs Improvement"
    return s, "High Risk"

def _make_summary(findings, ssl_info):
    pts = []
    hi = [f["name"] for f in findings if not f["ok"] and f["sev"] == "High"]
    md = [f["name"] for f in findings if not f["ok"] and f["sev"] == "Medium"]
    if hi: pts.append(f"Critical gaps found: {', '.join(hi[:3])}.")
    if md: pts.append(f"Medium-severity issues: {', '.join(md[:3])}.")
    d = ssl_info.get("days_remaining")
    if ssl_info.get("enabled") and d is not None and d < 30:
        pts.append(f"TLS certificate expires in {d} days — renewal required urgently.")
    if not pts:
        pts.append("No critical security configuration issues were identified in this review.")
    return pts

def run_scan(url):
    target = _norm_url(url)
    resp   = _fetch(target)
    host   = _hostname(target)
    ssl_info = _scan_ssl(host) if host else {"enabled":False,"error":"No hostname"}
    findings = (_scan_protocol(target, resp.url) + _scan_headers(resp) +
                _scan_cookies(resp) + _scan_disclosure(resp) + _scan_paths(resp.url))
    score, rating = _calc_score(findings, ssl_info)
    return {"input_url":target,"final_url":resp.url,"hostname":host,
            "status_code":resp.status_code,"ssl_info":ssl_info,
            "findings":findings,"score":score,"rating":rating,
            "summary":_make_summary(findings, ssl_info),
            "scanned_at":datetime.utcnow().strftime("%d %b %Y, %H:%M UTC")}

# ── PDF builder ───────────────────────────────────────────────
_PDF_NAVY  = colors.HexColor("#0f172a")
_PDF_BLUE  = colors.HexColor("#2563eb")
_PDF_TEXT  = colors.HexColor("#1e293b")
_PDF_MUTED = colors.HexColor("#64748b")
_PDF_SUB   = colors.HexColor("#94a3b8")
_PDF_BDR   = colors.HexColor("#e2e8f0")
_PDF_BG    = colors.HexColor("#ffffff")
_PDF_BG1   = colors.HexColor("#f8fafc")
_PDF_BG2   = colors.HexColor("#f1f5f9")
_PDF_GREEN = colors.HexColor("#16a34a")
_PDF_AMBER = colors.HexColor("#d97706")
_PDF_RED   = colors.HexColor("#dc2626")
_PDF_WHITE = colors.HexColor("#ffffff")

def _S(name, size, color, bold=False, leading=None, sb=0, sa=4):
    return ParagraphStyle(name, fontSize=size, textColor=color,
        fontName="Helvetica-Bold" if bold else "Helvetica",
        leading=leading or round(size * 1.5),
        spaceBefore=sb, spaceAfter=sa)

def _sev_color(s):
    return {"High":_PDF_RED,"Medium":_PDF_AMBER,"Low":_PDF_BLUE,"Info":_PDF_GREEN}.get(s, _PDF_MUTED)

def _rating_color(r):
    return {"Strong":_PDF_GREEN,"Moderate":_PDF_AMBER,
            "Needs Improvement":_PDF_AMBER,"High Risk":_PDF_RED}.get(r, _PDF_MUTED)

class _PDFHeaderFooter:
    def __init__(self, company, analyst, date):
        self.company = company
        self.analyst = analyst
        self.date = date

    def __call__(self, canvas, doc):
        W, H = A4
        c = canvas
        c.saveState()

        # Header bar
        c.setFillColor(_PDF_NAVY)
        c.rect(0, H - 46, W, 46, fill=1, stroke=0)

        # Blue left accent
        c.setFillColor(_PDF_BLUE)
        c.rect(0, H - 46, 3, 46, fill=1, stroke=0)

        # Logo
        c.setFont("Helvetica-Bold", 12)
        c.setFillColor(_PDF_WHITE)
        c.drawString(13*mm, H - 19, "CyberGuard")

        c.setFont("Helvetica", 8)
        c.setFillColor(colors.HexColor("#94a3b8"))
        c.drawString(13*mm, H - 32, "Security Review Platform")

        # Right meta
        c.setFont("Helvetica", 8)
        c.setFillColor(colors.HexColor("#94a3b8"))
        c.drawRightString(W - 13*mm, H - 19, self.company)
        c.drawRightString(W - 13*mm, H - 32, self.date)

        # Footer
        c.setFillColor(_PDF_BG2)
        c.rect(0, 0, W, 24, fill=1, stroke=0)
        c.setStrokeColor(_PDF_BDR)
        c.setLineWidth(0.5)
        c.line(0, 24, W, 24)

        c.setFont("Helvetica", 7)
        c.setFillColor(_PDF_SUB)
        c.drawString(13*mm, 8, f"Prepared by {self.analyst}  ·  Confidential — Authorised Review Only")
        c.drawRightString(W - 13*mm, 8, f"Page {doc.page}")

        c.restoreState()

def build_pdf(scan, company, analyst):
    buf = io.BytesIO()
    W, H = A4
    LM, RM, TM, BM = 14*mm, 14*mm, 54, 32
    CW = W - LM - RM  # content width

    doc = BaseDocTemplate(buf, pagesize=A4,
        leftMargin=LM, rightMargin=RM, topMargin=TM, bottomMargin=BM)
    frame = Frame(LM, BM, CW, H - TM - BM, id="body")
    cb = _PDFHeaderFooter(company, analyst, scan["scanned_at"])
    doc.addPageTemplates([PageTemplate(id="main", frames=[frame], onPage=cb)])

    # Style set
    S = {
        "title":   _S("t",   20, _PDF_NAVY,  bold=True,  leading=24, sa=4),
        "h2":      _S("h2",  11, _PDF_NAVY,  bold=True,  leading=15, sb=16, sa=8),
        "label":   _S("lb",   8, _PDF_MUTED, bold=True,  leading=11, sa=3),
        "body":    _S("bd",   9, _PDF_TEXT,              leading=14, sa=3),
        "small":   _S("sm",  8.5,_PDF_TEXT,              leading=13, sa=2),
        "tiny":    _S("ti",   8, _PDF_MUTED,             leading=12, sa=2),
        "code":    _S("cd",   8, _PDF_MUTED,             leading=12, sa=2),
        "bullet":  _S("bu",   9, _PDF_TEXT,              leading=14, sa=3, sb=0),
        "disc":    _S("dc",   8, _PDF_MUTED,             leading=12, sa=0),
    }

    def hline(space_after=10, space_before=0):
        return HRFlowable(width="100%", thickness=0.5, color=_PDF_BDR,
                          spaceBefore=space_before, spaceAfter=space_after)

    def kv_table(rows, col1=38*mm):
        """Two-column key-value table."""
        data = [[Paragraph(f"<b>{k}</b>", S["tiny"]), Paragraph(v, S["small"])] for k, v in rows]
        t = Table(data, colWidths=[col1, CW - col1])
        t.setStyle(TableStyle([
            ("FONTSIZE",    (0,0),(-1,-1), 8.5),
            ("LEADING",     (0,0),(-1,-1), 12),
            ("TOPPADDING",  (0,0),(-1,-1), 5),
            ("BOTTOMPADDING",(0,0),(-1,-1), 5),
            ("LEFTPADDING", (0,0),(-1,-1), 8),
            ("RIGHTPADDING",(0,0),(-1,-1), 8),
            ("LINEBELOW",   (0,0),(-1,-1), 0.5, _PDF_BDR),
            ("BACKGROUND",  (0,0),(0,-1),  _PDF_BG2),
            ("BACKGROUND",  (1,0),(1,-1),  _PDF_BG),
            ("TEXTCOLOR",   (0,0),(0,-1),  _PDF_MUTED),
            ("TEXTCOLOR",   (1,0),(1,-1),  _PDF_TEXT),
            ("FONTNAME",    (0,0),(0,-1),  "Helvetica-Bold"),
        ]))
        return t

    story = []

    # ── Title row ────────────────────────────────────────────────
    rc = _rating_color(scan["rating"])
    title_row = Table([
        [
            Paragraph("Website Security<br/>Review Report", S["title"]),
            Table([
                [Paragraph(
                    f'<font size="26" color="{rc.hexval()}"><b>{scan["score"]}</b></font>'
                    f'<font size="10" color="#94a3b8"> / 100</font>', S["body"])],
                [Paragraph(
                    f'<font color="{rc.hexval()}"><b>{scan["rating"]}</b></font>', S["tiny"])],
            ], colWidths=[52*mm],
            style=TableStyle([
                ("ALIGN",   (0,0),(-1,-1),"RIGHT"),
                ("PADDING", (0,0),(-1,-1), 0),
                ("VALIGN",  (0,0),(-1,-1),"BOTTOM"),
            ])),
        ]
    ], colWidths=[CW - 56*mm, 56*mm])
    title_row.setStyle(TableStyle([
        ("VALIGN",       (0,0),(-1,-1),"BOTTOM"),
        ("PADDING",      (0,0),(-1,-1), 0),
        ("LINEBELOW",    (0,0),(-1,0),  0.5, _PDF_BDR),
        ("BOTTOMPADDING",(0,0),(-1,0),  14),
    ]))
    story += [title_row, Spacer(1, 14)]

    # ── Engagement details ────────────────────────────────────────
    story.append(kv_table([
        ("Client",      company),
        ("Target URL",  scan["input_url"]),
        ("Final URL",   scan["final_url"]),
        ("Analyst",     analyst),
        ("Date",        scan["scanned_at"]),
        ("HTTP Status", str(scan["status_code"])),
    ]))
    story.append(Spacer(1, 4))

    # ── TLS ───────────────────────────────────────────────────────
    story += [Paragraph("TLS / SSL Certificate", S["h2"]), hline()]
    ssl = scan["ssl_info"]
    if ssl.get("enabled"):
        d = ssl.get("days_remaining", 0)
        dc = _PDF_GREEN if d > 45 else _PDF_AMBER if d > 15 else _PDF_RED
        story.append(kv_table([
            ("Issuer",        ssl.get("issuer","—")),
            ("Subject",       ssl.get("subject","—")),
            ("Valid To",      ssl.get("valid_to","—")),
            ("Days Remaining", f'<font color="{dc.hexval()}"><b>{d}</b></font>'),
        ]))
    else:
        story.append(Paragraph(f"TLS unavailable: {ssl.get('error','unknown')}", S["tiny"]))
    story.append(Spacer(1, 4))

    # ── Executive Summary ─────────────────────────────────────────
    story += [Paragraph("Executive Summary", S["h2"]), hline()]
    for pt in scan["summary"]:
        story.append(Paragraph(f"<bullet>•</bullet> {pt}", S["bullet"]))
    story.append(Spacer(1, 4))

    # ── Findings table ────────────────────────────────────────────
    story += [Paragraph("Detailed Findings", S["h2"]), hline()]

    hdr = [Paragraph(f"<b>{t}</b>", S["tiny"]) for t in
           ["Check", "Category", "Severity", "Status", "Recommendation"]]
    rows = [hdr]

    for f in scan["findings"]:
        sc = _sev_color(f["sev"])
        rows.append([
            Paragraph(f["name"],  S["small"]),
            Paragraph(f["cat"],   S["small"]),
            Paragraph(f'<font color="{sc.hexval()}"><b>{f["sev"]}</b></font>', S["small"]),
            Paragraph(
                f'<font color="{"#16a34a" if f["ok"] else "#dc2626"}"><b>{"Pass" if f["ok"] else "Fail"}</b></font>',
                S["small"]),
            Paragraph(f["fix"],   S["small"]),
        ])

    cws = [40*mm, 30*mm, 18*mm, 12*mm, CW - 40*mm - 30*mm - 18*mm - 12*mm]
    ft = Table(rows, colWidths=cws, repeatRows=1)
    ft.setStyle(TableStyle([
        ("FONTSIZE",        (0,0),(-1,-1), 8),
        ("LEADING",         (0,0),(-1,-1), 12),
        ("TOPPADDING",      (0,0),(-1,-1), 6),
        ("BOTTOMPADDING",   (0,0),(-1,-1), 6),
        ("LEFTPADDING",     (0,0),(-1,-1), 7),
        ("RIGHTPADDING",    (0,0),(-1,-1), 7),
        ("VALIGN",          (0,0),(-1,-1), "TOP"),
        ("BACKGROUND",      (0,0),(-1, 0), _PDF_NAVY),
        ("TEXTCOLOR",       (0,0),(-1, 0), _PDF_WHITE),
        ("FONTNAME",        (0,0),(-1, 0), "Helvetica-Bold"),
        ("ROWBACKGROUNDS",  (0,1),(-1,-1), [_PDF_BG, _PDF_BG1]),
        ("LINEBELOW",       (0,0),(-1,-1), 0.4, _PDF_BDR),
    ]))
    story.append(ft)
    story.append(Spacer(1, 18))

    # ── Disclaimer ────────────────────────────────────────────────
    disc_data = [[Paragraph(
        "Scope Notice — This report covers passive, defensive web configuration analysis only. "
        "No offensive, intrusive, or exploitative testing was performed. "
        "Intended for authorised assessment, portfolio demonstration, and security awareness.",
        S["disc"])]]
    disc = Table(disc_data, colWidths=[CW])
    disc.setStyle(TableStyle([
        ("BACKGROUND",    (0,0),(-1,-1), _PDF_BG2),
        ("LINEABOVE",     (0,0),(-1, 0), 2,   _PDF_BLUE),
        ("TOPPADDING",    (0,0),(-1,-1), 10),
        ("BOTTOMPADDING", (0,0),(-1,-1), 10),
        ("LEFTPADDING",   (0,0),(-1,-1), 12),
        ("RIGHTPADDING",  (0,0),(-1,-1), 12),
    ]))
    story.append(disc)

    doc.build(story)
    pdf = buf.getvalue()
    buf.close()
    return pdf

# ── App state ─────────────────────────────────────────────────
_db_init()
if "user"      not in st.session_state: st.session_state.user      = None
if "last_scan" not in st.session_state: st.session_state.last_scan = None

# ══════════════════════════════════════════════════════════════
# AUTH SCREEN
# ══════════════════════════════════════════════════════════════
if st.session_state.user is None:

    # Force centre using columns — this is the reliable Streamlit way
    _, mid, _ = st.columns([1, 1.2, 1])

    with mid:
        st.markdown('<div style="height:80px"></div>', unsafe_allow_html=True)

        # Brand
        st.markdown("""
        <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">
          <div style="width:8px;height:8px;border-radius:50%;background:#3b82f6;flex-shrink:0"></div>
          <span style="font-size:15px;font-weight:600;letter-spacing:-0.02em;color:#fafafa">CyberGuard</span>
        </div>
        <p style="font-size:12px;color:#71717a;margin:0 0 28px">Website security review platform</p>
        """, unsafe_allow_html=True)

        # Card wrapper
        st.markdown("""
        <div style="background:#18181b;border:1px solid rgba(255,255,255,0.08);
                    border-radius:16px;padding:24px 24px 8px">
        """, unsafe_allow_html=True)

        tab_in, tab_up = st.tabs(["Sign in", "Create account"])

        with tab_in:
            st.markdown('<p style="font-size:15px;font-weight:600;letter-spacing:-0.02em;color:#fafafa;margin:4px 0 18px">Sign in to your account</p>', unsafe_allow_html=True)
            em = st.text_input("Email address", key="li_em", placeholder="you@company.com")
            pw = st.text_input("Password", type="password", key="li_pw", placeholder="Enter your password")
            st.markdown('<div style="height:4px"></div>', unsafe_allow_html=True)
            if st.button("Sign in", use_container_width=True, key="btn_li"):
                if not em or not pw:
                    st.error("Please enter your email and password.")
                else:
                    ok, user = authenticate_user(em, pw)
                    if ok:
                        st.session_state.user = user
                        st.rerun()
                    else:
                        st.error("Incorrect email or password.")

        with tab_up:
            st.markdown('<p style="font-size:15px;font-weight:600;letter-spacing:-0.02em;color:#fafafa;margin:4px 0 18px">Create a new account</p>', unsafe_allow_html=True)
            nm  = st.text_input("Full name",  key="su_nm", placeholder="Alex Johnson")
            em2 = st.text_input("Email",      key="su_em", placeholder="alex@company.com")
            pw2 = st.text_input("Password",   key="su_pw", placeholder="Minimum 8 characters", type="password")
            st.markdown('<div style="height:4px"></div>', unsafe_allow_html=True)
            if st.button("Create account", use_container_width=True, key="btn_su"):
                if not nm or not em2 or not pw2:
                    st.error("All fields are required.")
                elif len(pw2) < 8:
                    st.error("Password must be at least 8 characters.")
                else:
                    ok, msg = create_user(nm, em2, pw2)
                    if ok: st.success(msg + " You can now sign in.")
                    else:  st.error(msg)

        st.markdown('</div>', unsafe_allow_html=True)
        st.markdown('<p style="font-size:11px;color:#52525b;text-align:center;margin-top:16px">Authorised use only. Do not scan without permission.</p>', unsafe_allow_html=True)

    st.stop()

# ══════════════════════════════════════════════════════════════
# MAIN APP
# ══════════════════════════════════════════════════════════════
user = st.session_state.user

# Sidebar
with st.sidebar:
    st.markdown(f"<p style='font-size:13px;font-weight:600;color:#fafafa;margin-bottom:2px'>{user['name']}</p>", unsafe_allow_html=True)
    st.markdown(f"<p style='font-size:11px;color:#71717a;margin-top:0'>{user['email']}</p>", unsafe_allow_html=True)
    st.divider()
    st.caption("Only scan websites you own or have explicit written permission to assess.")
    st.write("")
    if st.button("Sign out", use_container_width=True):
        st.session_state.user = None
        st.session_state.last_scan = None
        st.rerun()

# Navigation bar
st.markdown(f"""
<div class="cg-nav">
  <div class="cg-nav-logo">
    <div class="cg-nav-dot"></div>
    CyberGuard
  </div>
  <div class="cg-nav-user">
    <div class="cg-online-dot"></div>
    {user['name']}
  </div>
</div>
""", unsafe_allow_html=True)

# Page content
st.markdown('<div class="cg-page">', unsafe_allow_html=True)

# Hero section
st.markdown("""
<div class="cg-hero">
  <div class="cg-eyebrow">
    <span class="cg-eyebrow-line"></span>
    Security Review Platform
  </div>
  <h1 class="cg-h1">Website security,<br>reviewed in seconds.</h1>
  <p class="cg-tagline">
    Run a passive defensive assessment across TLS, security headers, cookies,
    and information disclosure. Export a polished PDF report ready for client delivery.
  </p>
</div>
""", unsafe_allow_html=True)

# Scan input row
st.markdown('<div class="cg-scan-row">', unsafe_allow_html=True)
c1, c2, c3 = st.columns([5, 3, 1.3], gap="medium")
with c1:
    target_url = st.text_input("Target URL", placeholder="https://example.com", key="k_url")
with c2:
    client_name = st.text_input("Client name", placeholder="Acme Corporation", key="k_client")
with c3:
    st.markdown('<div style="height:26px"></div>', unsafe_allow_html=True)
    scan_btn = st.button("Run scan", use_container_width=True, key="k_scan")
st.markdown('</div>', unsafe_allow_html=True)

# Run
if scan_btn:
    if not target_url.strip():
        st.error("Enter a target URL to continue.")
    else:
        try:
            with st.spinner("Running security checks…"):
                st.session_state.last_scan = run_scan(target_url)
        except requests.exceptions.SSLError:
            st.error("SSL handshake failed. Verify the target supports HTTPS correctly.")
        except requests.exceptions.ConnectionError:
            st.error("Could not connect to target. Check the URL and try again.")
        except requests.exceptions.Timeout:
            st.error("Request timed out. The target may be unreachable or blocking requests.")
        except Exception as e:
            st.error(f"Unexpected error: {e}")

# ── Results ───────────────────────────────────────────────────
scan = st.session_state.last_scan

if scan:
    ssl_info = scan["ssl_info"]
    ssl_days = ssl_info.get("days_remaining")
    issues   = sum(1 for f in scan["findings"] if not f["ok"])
    total    = len(scan["findings"])

    def _score_class(r):
        return {"Strong":"green","Moderate":"amber","Needs Improvement":"amber","High Risk":"red"}.get(r,"")

    sc = _score_class(scan["rating"])
    ssl_col = "green" if ssl_info.get("enabled") else "red"
    iss_col = "red" if issues > 3 else "amber" if issues > 0 else "green"

    # Stat row
    st.markdown(f"""
    <div class="cg-stats-grid">
      <div class="cg-stat">
        <div class="cg-stat-label">Security Score</div>
        <div class="cg-stat-value {sc}">{scan['score']}<span style="font-size:16px;font-weight:400;color:#52525b"> / 100</span></div>
        <div class="cg-stat-sub">{scan['rating']}</div>
      </div>
      <div class="cg-stat">
        <div class="cg-stat-label">TLS / SSL</div>
        <div class="cg-stat-value {ssl_col}">{'Active' if ssl_info.get('enabled') else 'None'}</div>
        <div class="cg-stat-sub">{f"{ssl_days} days remaining" if ssl_days is not None and ssl_info.get('enabled') else 'Certificate status'}</div>
      </div>
      <div class="cg-stat">
        <div class="cg-stat-label">HTTP Status</div>
        <div class="cg-stat-value">{scan['status_code']}</div>
        <div class="cg-stat-sub">Final response code</div>
      </div>
      <div class="cg-stat">
        <div class="cg-stat-label">Issues Found</div>
        <div class="cg-stat-value {iss_col}">{issues}</div>
        <div class="cg-stat-sub">of {total} checks</div>
      </div>
    </div>
    """, unsafe_allow_html=True)

    # Summary + TLS cards
    lc, rc2 = st.columns([3, 2], gap="medium")

    with lc:
        st.markdown('<div class="cg-card"><div class="cg-card-label">Executive Summary</div>', unsafe_allow_html=True)
        for pt in scan["summary"]:
            st.markdown(f"""
            <div class="cg-summary-item">
              <div class="cg-summary-bullet"></div>
              <span class="cg-summary-text">{pt}</span>
            </div>""", unsafe_allow_html=True)
        st.markdown(f"""
        <div style="margin-top:18px">
          <div class="cg-kv-row">
            <span class="cg-kv-key">Input URL</span>
            <span class="cg-kv-val mono">{scan['input_url']}</span>
          </div>
          <div class="cg-kv-row">
            <span class="cg-kv-key">Final URL</span>
            <span class="cg-kv-val mono">{scan['final_url']}</span>
          </div>
          <div class="cg-kv-row" style="border-bottom:none">
            <span class="cg-kv-key">Reviewed</span>
            <span class="cg-kv-val">{scan['scanned_at']}</span>
          </div>
        </div>
        </div>""", unsafe_allow_html=True)

    with rc2:
        st.markdown('<div class="cg-card"><div class="cg-card-label">TLS Certificate</div>', unsafe_allow_html=True)
        if ssl_info.get("enabled"):
            d = ssl_info.get("days_remaining", 0)
            day_color = "#4ade80" if d > 45 else "#fbbf24" if d > 15 else "#f87171"
            st.markdown(f"""
            <div class="cg-tls-days" style="color:{day_color}">{d}</div>
            <div class="cg-tls-days-label">days until expiry</div>
            <div class="cg-kv-row">
              <span class="cg-kv-key">Issuer</span>
              <span class="cg-kv-val">{ssl_info.get('issuer','—')}</span>
            </div>
            <div class="cg-kv-row">
              <span class="cg-kv-key">Subject</span>
              <span class="cg-kv-val">{ssl_info.get('subject','—')}</span>
            </div>
            <div class="cg-kv-row" style="border-bottom:none">
              <span class="cg-kv-key">Valid to</span>
              <span class="cg-kv-val">{ssl_info.get('valid_to','—')}</span>
            </div>
            </div>""", unsafe_allow_html=True)
        else:
            st.markdown(f"""
            <div style="font-size:26px;font-weight:600;color:#f87171;margin-bottom:8px">Unavailable</div>
            <div style="font-size:12px;color:#71717a">{ssl_info.get('error','TLS not detected.')}</div>
            </div>""", unsafe_allow_html=True)

    # Findings
    st.markdown(f"""
    <div class="cg-section">
      <span class="cg-section-title">Findings</span>
      <span class="cg-section-meta">— {issues} issue{'s' if issues != 1 else ''} across {total} checks</span>
    </div>""", unsafe_allow_html=True)

    cats = {}
    for f in scan["findings"]: cats.setdefault(f["cat"], []).append(f)

    badge_cls = {"High":"H","Medium":"M","Low":"L","Info":"I"}

    for cat, items in cats.items():
        passed = sum(1 for f in items if f["ok"])
        label = f"**{cat}**  —  {passed} / {len(items)} passed"
        with st.expander(label):
            for item in items:
                dot = "#4ade80" if item["ok"] else (
                    "#f87171" if item["sev"]=="High" else
                    "#fbbf24" if item["sev"]=="Medium" else "#93c5fd")
                bc = badge_cls.get(item["sev"], "I")
                st.markdown(f"""
                <div class="cg-finding">
                  <div class="cg-finding-header">
                    <div class="cg-finding-dot" style="background:{dot}"></div>
                    <div class="cg-finding-name">{item['name']}</div>
                    <span class="cg-badge cg-badge-{bc}">{item['sev']}</span>
                  </div>
                  <div class="cg-finding-desc">{item['desc']}</div>
                  <div class="cg-finding-footer">
                    <span class="cg-code">{item['val']}</span>
                    <span class="cg-rec-text">&#8594; {item['fix']}</span>
                  </div>
                </div>""", unsafe_allow_html=True)

    # Export
    st.markdown("""
    <div class="cg-section" style="margin-top:28px">
      <span class="cg-section-title">Export</span>
    </div>""", unsafe_allow_html=True)

    ex1, ex2 = st.columns([3, 1], gap="medium")
    with ex1:
        st.markdown("""
        <div class="cg-card">
          <div class="cg-card-label">PDF Report</div>
          <p class="cg-export-info">
            A clean A4 report including engagement details, TLS certificate summary,
            executive summary, full findings table with pass/fail status and remediation
            guidance, and a scope disclaimer. Ready for client delivery.
          </p>
        </div>""", unsafe_allow_html=True)
    with ex2:
        st.markdown('<div style="height:8px"></div>', unsafe_allow_html=True)
        pdf_bytes = build_pdf(scan, client_name or "—", user["name"])
        st.download_button(
            "Download PDF",
            data=pdf_bytes,
            file_name=f"cyberguard-{scan['hostname']}.pdf",
            mime="application/pdf",
            use_container_width=True,
        )
        st.caption("Suitable for portfolio, client, and internal review.")

st.markdown('</div>', unsafe_allow_html=True)  # close cg-page

# Footer
st.markdown("""
<div class="cg-footer">
  <span class="cg-footer-text">CyberGuard &nbsp;·&nbsp; Pamupro Cyber</span>
  <span class="cg-footer-text">Authorised defensive reviews only</span>
</div>
""", unsafe_allow_html=True)
