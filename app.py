"""
CyberGuard — Website Security Review Platform
Single-file Streamlit app. No utils/ package needed.
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
    BaseDocTemplate, Frame, HRFlowable, NextPageTemplate,
    PageBreak, PageTemplate, Paragraph, Spacer, Table, TableStyle,
)

# ─────────────────────────────────────────────
# PAGE CONFIG
# ─────────────────────────────────────────────
st.set_page_config(
    page_title="CyberGuard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ─────────────────────────────────────────────
# CSS  — Geist + Inter from Google Fonts
# Design language: Linear / Vercel-inspired
# Strict spacing system, no AI gimmicks
# ─────────────────────────────────────────────
st.markdown("""
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600&family=Geist+Mono:wght@400;500&display=swap" rel="stylesheet">

<style>
/* ── Tokens ── */
:root {
  --c-bg:       #0a0a0a;
  --c-bg1:      #111111;
  --c-bg2:      #1a1a1a;
  --c-bg3:      #222222;
  --c-border:   #2a2a2a;
  --c-border2:  #333333;
  --c-text:     #ededed;
  --c-muted:    #888888;
  --c-subtle:   #555555;
  --c-blue:     #2563eb;
  --c-blue-d:   #1d4ed8;
  --c-blue-bg:  rgba(37,99,235,0.08);
  --c-blue-br:  rgba(37,99,235,0.20);
  --c-green:    #16a34a;
  --c-green-bg: rgba(22,163,74,0.08);
  --c-green-br: rgba(22,163,74,0.20);
  --c-amber:    #d97706;
  --c-amber-bg: rgba(217,119,6,0.08);
  --c-amber-br: rgba(217,119,6,0.20);
  --c-red:      #dc2626;
  --c-red-bg:   rgba(220,38,38,0.08);
  --c-red-br:   rgba(220,38,38,0.20);
  --r-sm:       6px;
  --r-md:       10px;
  --r-lg:       14px;
  --r-xl:       18px;
  --font:       'Inter', -apple-system, sans-serif;
  --mono:       'Geist Mono', 'Fira Code', monospace;
}

/* ── Base reset ── */
html, body, [class*="css"], [class*="st-"] {
  font-family: var(--font) !important;
  color: var(--c-text) !important;
  -webkit-font-smoothing: antialiased !important;
}
.stApp {
  background: var(--c-bg) !important;
  min-height: 100vh;
}
#MainMenu, footer, header { visibility: hidden; }
.block-container { padding: 0 !important; max-width: 100% !important; }
section[data-testid="stSidebar"] {
  background: var(--c-bg1) !important;
  border-right: 1px solid var(--c-border) !important;
}

/* ── Inputs ── */
[data-testid="stTextInput"] > div > div {
  background: var(--c-bg1) !important;
  border: 1px solid var(--c-border2) !important;
  border-radius: var(--r-md) !important;
}
[data-testid="stTextInput"] input {
  background: transparent !important;
  border: none !important;
  color: var(--c-text) !important;
  font-family: var(--font) !important;
  font-size: 0.9rem !important;
  padding: 0.6rem 0.875rem !important;
}
[data-testid="stTextInput"] > div > div:focus-within {
  border-color: var(--c-blue) !important;
  box-shadow: 0 0 0 3px rgba(37,99,235,0.12) !important;
}
[data-testid="stTextInput"] label {
  font-size: 0.75rem !important;
  font-weight: 500 !important;
  color: var(--c-muted) !important;
  letter-spacing: 0.01em !important;
  margin-bottom: 6px !important;
}

/* ── Buttons ── */
.stButton > button {
  background: var(--c-blue) !important;
  color: #fff !important;
  border: none !important;
  border-radius: var(--r-md) !important;
  font-family: var(--font) !important;
  font-size: 0.875rem !important;
  font-weight: 500 !important;
  padding: 0.6rem 1.25rem !important;
  cursor: pointer !important;
  transition: background 0.15s, box-shadow 0.15s !important;
  letter-spacing: -0.01em !important;
  height: auto !important;
}
.stButton > button:hover {
  background: var(--c-blue-d) !important;
  box-shadow: 0 0 0 3px rgba(37,99,235,0.15) !important;
}
[data-testid="stDownloadButton"] > button {
  background: var(--c-bg2) !important;
  border: 1px solid var(--c-border2) !important;
  color: var(--c-text) !important;
  font-size: 0.875rem !important;
  font-weight: 500 !important;
}
[data-testid="stDownloadButton"] > button:hover {
  background: var(--c-bg3) !important;
  border-color: var(--c-blue) !important;
}

/* ── Expanders ── */
[data-testid="stExpander"] {
  background: var(--c-bg1) !important;
  border: 1px solid var(--c-border) !important;
  border-radius: var(--r-lg) !important;
  margin-bottom: 6px !important;
  overflow: hidden !important;
}
[data-testid="stExpander"] > div:first-child {
  padding: 0.875rem 1rem !important;
}
[data-testid="stExpander"] summary {
  color: var(--c-text) !important;
  font-size: 0.875rem !important;
  font-weight: 500 !important;
}
[data-testid="stExpander"] > div:last-child {
  padding: 0 1rem 1rem !important;
}

/* ── Tabs ── */
[data-testid="stTabs"] [role="tablist"] {
  gap: 0 !important;
  border-bottom: 1px solid var(--c-border) !important;
  background: transparent !important;
}
[data-testid="stTabs"] button {
  font-family: var(--font) !important;
  font-size: 0.875rem !important;
  font-weight: 500 !important;
  color: var(--c-muted) !important;
  border: none !important;
  background: transparent !important;
  padding: 0.75rem 1.25rem !important;
  border-bottom: 2px solid transparent !important;
  border-radius: 0 !important;
  transition: color 0.15s !important;
}
[data-testid="stTabs"] button[aria-selected="true"] {
  color: var(--c-text) !important;
  border-bottom: 2px solid var(--c-blue) !important;
}

/* ── Alert boxes ── */
[data-testid="stAlert"] {
  background: var(--c-bg1) !important;
  border: 1px solid var(--c-border) !important;
  border-radius: var(--r-lg) !important;
}
.stSuccess { border-left: 3px solid var(--c-green) !important; }
.stError   { border-left: 3px solid var(--c-red)   !important; }

/* ── Spinner ── */
.stSpinner > div { border-top-color: var(--c-blue) !important; }

/* ── Scrollbar ── */
::-webkit-scrollbar { width: 4px; background: var(--c-bg); }
::-webkit-scrollbar-thumb { background: var(--c-border2); border-radius: 2px; }

/* ════════════════════════════════════════════
   CUSTOM LAYOUT COMPONENTS
   ════════════════════════════════════════════ */

/* Top nav */
.g-nav {
  display: flex;
  align-items: center;
  justify-content: space-between;
  height: 56px;
  padding: 0 32px;
  border-bottom: 1px solid var(--c-border);
  background: var(--c-bg);
  position: sticky;
  top: 0;
  z-index: 200;
}
.g-logo {
  font-size: 0.9rem;
  font-weight: 600;
  color: var(--c-text);
  letter-spacing: -0.02em;
  display: flex;
  align-items: center;
  gap: 8px;
}
.g-logo-dot {
  width: 8px; height: 8px;
  background: var(--c-blue);
  border-radius: 50%;
  display: inline-block;
}
.g-nav-right {
  display: flex;
  align-items: center;
  gap: 12px;
}
.g-status-dot {
  width: 6px; height: 6px;
  background: var(--c-green);
  border-radius: 50%;
  display: inline-block;
  box-shadow: 0 0 6px rgba(22,163,74,0.6);
}
.g-user {
  font-size: 0.8rem;
  color: var(--c-muted);
  padding: 5px 12px;
  border: 1px solid var(--c-border);
  border-radius: 999px;
  display: flex;
  align-items: center;
  gap: 6px;
}

/* Page wrapper */
.g-page {
  max-width: 1100px;
  margin: 0 auto;
  padding: 48px 32px 80px;
}
.g-page-wide {
  max-width: 1100px;
  margin: 0 auto;
  padding: 0 32px 80px;
}

/* Hero */
.g-hero {
  padding: 56px 0 40px;
  border-bottom: 1px solid var(--c-border);
  margin-bottom: 40px;
}
.g-label {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-size: 0.72rem;
  font-weight: 500;
  letter-spacing: 0.06em;
  text-transform: uppercase;
  color: var(--c-muted);
  margin-bottom: 20px;
}
.g-label-dot {
  width: 5px; height: 5px;
  background: var(--c-blue);
  border-radius: 50%;
}
.g-h1 {
  font-size: 2.25rem;
  font-weight: 600;
  letter-spacing: -0.04em;
  line-height: 1.1;
  color: var(--c-text);
  margin: 0 0 16px;
}
.g-h1 span { color: var(--c-blue); }
.g-body {
  font-size: 0.9rem;
  line-height: 1.65;
  color: var(--c-muted);
  max-width: 520px;
  margin: 0;
}

/* Scan panel */
.g-scan-panel {
  background: var(--c-bg1);
  border: 1px solid var(--c-border);
  border-radius: var(--r-xl);
  padding: 24px;
  margin-bottom: 32px;
}
.g-field-label {
  font-size: 0.72rem;
  font-weight: 500;
  letter-spacing: 0.04em;
  text-transform: uppercase;
  color: var(--c-muted);
  margin-bottom: 8px;
}

/* Stat grid */
.g-stats {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 12px;
  margin-bottom: 32px;
}
.g-stat {
  background: var(--c-bg1);
  border: 1px solid var(--c-border);
  border-radius: var(--r-lg);
  padding: 20px 20px 18px;
}
.g-stat-label {
  font-size: 0.72rem;
  font-weight: 500;
  letter-spacing: 0.04em;
  text-transform: uppercase;
  color: var(--c-muted);
  margin-bottom: 12px;
}
.g-stat-val {
  font-size: 1.75rem;
  font-weight: 600;
  letter-spacing: -0.04em;
  line-height: 1;
  color: var(--c-text);
}
.g-stat-sub {
  font-size: 0.75rem;
  color: var(--c-subtle);
  margin-top: 6px;
}

/* Two-col */
.g-two {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 12px;
  margin-bottom: 12px;
}

/* Cards */
.g-card {
  background: var(--c-bg1);
  border: 1px solid var(--c-border);
  border-radius: var(--r-lg);
  padding: 24px;
}
.g-card-title {
  font-size: 0.8rem;
  font-weight: 600;
  letter-spacing: 0.03em;
  text-transform: uppercase;
  color: var(--c-muted);
  margin-bottom: 20px;
}

/* Section header */
.g-section-header {
  display: flex;
  align-items: baseline;
  gap: 10px;
  margin: 32px 0 12px;
  padding-bottom: 12px;
  border-bottom: 1px solid var(--c-border);
}
.g-section-title {
  font-size: 0.875rem;
  font-weight: 600;
  color: var(--c-text);
  letter-spacing: -0.01em;
}
.g-section-count {
  font-size: 0.75rem;
  color: var(--c-subtle);
}

/* KV rows */
.g-kv { display: flex; align-items: baseline; gap: 0; margin-bottom: 12px; }
.g-kv:last-child { margin-bottom: 0; }
.g-kv-k {
  font-size: 0.75rem;
  font-weight: 500;
  color: var(--c-muted);
  min-width: 100px;
  flex-shrink: 0;
}
.g-kv-v {
  font-size: 0.82rem;
  color: var(--c-text);
  font-family: var(--mono);
  word-break: break-all;
}

/* Summary list */
.g-bullet {
  display: flex;
  align-items: flex-start;
  gap: 10px;
  padding: 12px 0;
  border-bottom: 1px solid var(--c-border);
  font-size: 0.85rem;
  color: var(--c-muted);
  line-height: 1.55;
}
.g-bullet:last-child { border-bottom: none; padding-bottom: 0; }
.g-bullet-icon {
  width: 18px; height: 18px;
  border-radius: 50%;
  background: var(--c-blue-bg);
  border: 1px solid var(--c-blue-br);
  display: flex; align-items: center; justify-content: center;
  flex-shrink: 0;
  margin-top: 1px;
  font-size: 0.6rem;
  color: var(--c-blue);
}

/* Finding rows */
.g-finding {
  padding: 14px 0;
  border-bottom: 1px solid var(--c-border);
}
.g-finding:last-child { border-bottom: none; padding-bottom: 0; }
.g-finding-row {
  display: flex;
  align-items: flex-start;
  gap: 10px;
}
.g-finding-status {
  width: 7px; height: 7px;
  border-radius: 50%;
  flex-shrink: 0;
  margin-top: 6px;
}
.g-finding-name {
  font-size: 0.85rem;
  font-weight: 500;
  color: var(--c-text);
  line-height: 1.4;
  flex: 1;
}
.g-finding-desc {
  font-size: 0.78rem;
  color: var(--c-muted);
  margin: 5px 0 6px 17px;
  line-height: 1.5;
}
.g-finding-meta {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-left: 17px;
  flex-wrap: wrap;
}
.g-code {
  font-family: var(--mono);
  font-size: 0.72rem;
  color: var(--c-muted);
  background: var(--c-bg2);
  border: 1px solid var(--c-border);
  padding: 2px 8px;
  border-radius: 4px;
  max-width: 400px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.g-rec {
  font-size: 0.75rem;
  color: var(--c-muted);
  max-width: 500px;
}

/* Badge / pill */
.g-badge {
  display: inline-flex;
  align-items: center;
  font-size: 0.68rem;
  font-weight: 600;
  letter-spacing: 0.04em;
  text-transform: uppercase;
  padding: 2px 8px;
  border-radius: 4px;
  flex-shrink: 0;
}
.g-badge-high   { background: var(--c-red-bg);   color: var(--c-red);   border: 1px solid var(--c-red-br);   }
.g-badge-medium { background: var(--c-amber-bg); color: var(--c-amber); border: 1px solid var(--c-amber-br); }
.g-badge-low    { background: var(--c-blue-bg);  color: #60a5fa;        border: 1px solid var(--c-blue-br);  }
.g-badge-info   { background: var(--c-green-bg); color: #4ade80;        border: 1px solid var(--c-green-br); }

/* Auth */
.g-auth-shell {
  min-height: 100vh;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  background: var(--c-bg);
  padding: 32px;
}
.g-auth-logo {
  font-size: 1rem;
  font-weight: 600;
  letter-spacing: -0.03em;
  color: var(--c-text);
  margin-bottom: 8px;
  display: flex;
  align-items: center;
  gap: 8px;
}
.g-auth-sub {
  font-size: 0.82rem;
  color: var(--c-muted);
  margin-bottom: 32px;
}
.g-auth-box {
  width: 100%;
  max-width: 400px;
  background: var(--c-bg1);
  border: 1px solid var(--c-border);
  border-radius: var(--r-xl);
  padding: 28px;
}
.g-auth-heading {
  font-size: 1.1rem;
  font-weight: 600;
  letter-spacing: -0.02em;
  color: var(--c-text);
  margin-bottom: 24px;
}

/* Score colour helpers */
.col-green { color: #4ade80 !important; }
.col-amber { color: #fbbf24 !important; }
.col-red   { color: #f87171 !important; }
.col-text  { color: var(--c-text) !important; }

/* Footer */
.g-footer {
  border-top: 1px solid var(--c-border);
  padding: 20px 32px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  max-width: 100%;
}
.g-footer span {
  font-size: 0.75rem;
  color: var(--c-subtle);
}
</style>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────────
# AUTH (inline, stdlib only)
# ─────────────────────────────────────────────
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

# ─────────────────────────────────────────────
# SCANNER (inline)
# ─────────────────────────────────────────────
_UA = "CyberGuard/2.0 (authorized defensive review)"
_T  = 10

_HEADERS = {
    "Strict-Transport-Security": {"w":14,"sev":"High",
        "desc":"Forces browsers to use HTTPS for all future requests, preventing protocol downgrade attacks.",
        "fix":"Strict-Transport-Security: max-age=31536000; includeSubDomains"},
    "Content-Security-Policy": {"w":16,"sev":"High",
        "desc":"Controls which resources the browser may load, significantly reducing XSS attack surface.",
        "fix":"Define a restrictive CSP tailored to your application's resource requirements."},
    "X-Frame-Options": {"w":8,"sev":"Medium",
        "desc":"Prevents the page from being embedded in iframes, blocking clickjacking attacks.",
        "fix":"X-Frame-Options: DENY"},
    "X-Content-Type-Options": {"w":8,"sev":"Medium",
        "desc":"Instructs browsers not to MIME-sniff responses away from the declared content type.",
        "fix":"X-Content-Type-Options: nosniff"},
    "Referrer-Policy": {"w":6,"sev":"Low",
        "desc":"Controls how much referrer information is included when navigating away from the page.",
        "fix":"Referrer-Policy: strict-origin-when-cross-origin"},
    "Permissions-Policy": {"w":6,"sev":"Low",
        "desc":"Restricts which browser features and APIs this page may use.",
        "fix":"Define a Permissions-Policy based on your application's actual feature requirements."},
}
_OPT = ["Cross-Origin-Opener-Policy","Cross-Origin-Resource-Policy","Cross-Origin-Embedder-Policy"]
_PATHS = ["/robots.txt","/security.txt","/.well-known/security.txt","/sitemap.xml"]

def _norm(u):
    u = u.strip()
    return ("https://" + u) if u and not u.startswith(("http://","https://")) else u

def _host(u): return urlparse(u).hostname or ""

def _get(u):
    return requests.get(u, timeout=_T, headers={"User-Agent":_UA}, allow_redirects=True)

def _ssl(host, port=443):
    r = {"enabled":False,"issuer":None,"subject":None,"valid_to":None,"days_remaining":None,"error":None}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                cert = ss.getpeercert()
        r["enabled"] = True
        issuer  = dict(x[0] for x in cert.get("issuer",[]))
        subject = dict(x[0] for x in cert.get("subject",[]))
        r["issuer"]  = issuer.get("organizationName") or str(issuer)
        r["subject"] = subject.get("commonName") or str(subject)
        vt = datetime.strptime(cert["notAfter"],"%b %d %H:%M:%S %Y %Z")
        r["valid_to"] = vt.strftime("%d %b %Y")
        r["days_remaining"] = (vt.replace(tzinfo=timezone.utc) - datetime.now(timezone.utc)).days
    except Exception as e:
        r["error"] = str(e)
    return r

def _proto(in_url, fin_url):
    return [
        {"cat":"Protocol","name":"HTTPS on input URL","ok":in_url.startswith("https://"),
         "sev":"High","w":14,"val":in_url,
         "desc":"Confirms the initial URL uses an encrypted HTTPS connection.",
         "fix":"Ensure all traffic starts on https://."},
        {"cat":"Protocol","name":"HTTPS on final URL","ok":fin_url.startswith("https://"),
         "sev":"High","w":14,"val":fin_url,
         "desc":"Confirms the final landing page is served over HTTPS after any redirects.",
         "fix":"Permanently redirect (301) all HTTP requests to HTTPS."},
    ]

def _headers(resp):
    out = []
    for h, m in _HEADERS.items():
        present = h in resp.headers
        out.append({"cat":"Security Headers","name":h,"ok":present,
            "sev":"Info" if present else m["sev"],"w":m["w"],
            "val":resp.headers.get(h,"Not set"),
            "desc":m["desc"],"fix":"Header is configured." if present else m["fix"]})
    for h in _OPT:
        present = h in resp.headers
        out.append({"cat":"Security Headers","name":h,"ok":present,
            "sev":"Info" if present else "Low","w":3,
            "val":resp.headers.get(h,"Not set"),
            "desc":"Additional cross-origin isolation header for defence-in-depth hardening.",
            "fix":"Header is configured." if present else f"Consider adding {h}."})
    return out

def _cookies(resp):
    raw = resp.raw.headers.get_all("Set-Cookie") if hasattr(resp.raw.headers,"get_all") else []
    if not raw:
        return [{"cat":"Cookies","name":"Set-Cookie headers","ok":True,"sev":"Info","w":0,
                 "val":"None observed","desc":"No cookies were issued in this response.","fix":"No action needed."}]
    out = []
    for i, c in enumerate(raw, 1):
        low = c.lower()
        missing = [f for f,k in[("Secure","secure"),("HttpOnly","httponly"),("SameSite","samesite")]if k not in low]
        out.append({"cat":"Cookies","name":f"Cookie #{i}","ok":not missing,
            "sev":"Info" if not missing else "Medium","w":8,
            "val":c[:80]+("…" if len(c)>80 else ""),
            "desc":"Cookie attributes control whether it can be accessed or transmitted insecurely.",
            "fix":"All security flags present." if not missing else f"Missing flags: {', '.join(missing)}."})
    return out

def _disclosure(resp):
    out = []
    for h, label in [("Server","Server header"),("X-Powered-By","X-Powered-By header")]:
        val = resp.headers.get(h)
        out.append({"cat":"Information Disclosure","name":label,"ok":not bool(val),
            "sev":"Info" if not val else "Low","w":5,"val":val or "Not present",
            "desc":"Exposing server technology versions assists attackers in identifying known vulnerabilities.",
            "fix":"Not exposed — good." if not val else f"Suppress or redact the {h} response header."})
    return out

def _paths(base):
    session = requests.Session()
    out = []
    for p in _PATHS:
        url = urljoin(base, p)
        try:
            r = session.get(url, timeout=5, headers={"User-Agent":_UA}, allow_redirects=True)
            ok = r.status_code == 200
            out.append({"cat":"Security Files","name":p,"ok":ok,"sev":"Info" if ok else "Low","w":3,
                "val":f"HTTP {r.status_code}",
                "desc":"Standard file that assists security researchers and automated scanning tools.",
                "fix":"File is accessible." if ok else f"Consider publishing {p}."})
        except Exception:
            out.append({"cat":"Security Files","name":p,"ok":False,"sev":"Low","w":3,
                "val":"Unreachable","desc":"Standard security disclosure / discovery file.",
                "fix":f"Consider publishing {p}."})
    return out

def _score(findings, ssl_info):
    mp = sum(f["w"] for f in findings if f["w"]>0) + 10
    ea = sum(f["w"] for f in findings if f["ok"] and f["w"]>0)
    if ssl_info.get("enabled"):
        d = ssl_info.get("days_remaining")
        ea += 10 if (d is None or d>=45) else 6 if d>=15 else 3 if d>=0 else 0
    s = round(ea/mp*100) if mp else 0
    if s>=85: return s,"Strong"
    if s>=70: return s,"Moderate"
    if s>=50: return s,"Needs Improvement"
    return s,"High Risk"

def _summary(findings, ssl_info):
    pts = []
    hi = [f["name"] for f in findings if not f["ok"] and f["sev"]=="High"]
    md = [f["name"] for f in findings if not f["ok"] and f["sev"]=="Medium"]
    if hi: pts.append(f"Critical gaps requiring immediate attention: {', '.join(hi[:3])}.")
    if md: pts.append(f"Medium-severity issues identified: {', '.join(md[:3])}.")
    d = ssl_info.get("days_remaining")
    if ssl_info.get("enabled") and d is not None and d < 30:
        pts.append(f"TLS certificate expires in {d} days — renewal required.")
    if not pts:
        pts.append("No critical security configuration issues were identified in this review.")
    return pts

def run_scan(url):
    t = _norm(url)
    resp = _get(t)
    host = _host(t)
    ssl_info = _ssl(host) if host else {"enabled":False,"error":"No hostname"}
    findings = _proto(t,resp.url)+_headers(resp)+_cookies(resp)+_disclosure(resp)+_paths(resp.url)
    score, rating = _score(findings, ssl_info)
    return {"input_url":t,"final_url":resp.url,"hostname":host,
            "status_code":resp.status_code,"ssl_info":ssl_info,
            "findings":findings,"score":score,"rating":rating,
            "summary":_summary(findings,ssl_info),
            "scanned_at":datetime.utcnow().strftime("%d %b %Y, %H:%M UTC")}

# ─────────────────────────────────────────────
# PDF REPORT (inline) — clean A4 layout
# ─────────────────────────────────────────────
_C = {
    "bg":    colors.HexColor("#ffffff"),
    "bg1":   colors.HexColor("#f8fafc"),
    "bg2":   colors.HexColor("#f1f5f9"),
    "navy":  colors.HexColor("#0f172a"),
    "blue":  colors.HexColor("#2563eb"),
    "text":  colors.HexColor("#0f172a"),
    "muted": colors.HexColor("#64748b"),
    "sub":   colors.HexColor("#94a3b8"),
    "bdr":   colors.HexColor("#e2e8f0"),
    "green": colors.HexColor("#16a34a"),
    "amber": colors.HexColor("#d97706"),
    "red":   colors.HexColor("#dc2626"),
    "white": colors.HexColor("#ffffff"),
}

def _ps(name, size, color, font="Helvetica", leading=None, space_before=0, space_after=4, indent=0):
    return ParagraphStyle(name, fontSize=size, textColor=color, fontName=font,
        leading=leading or round(size*1.45), spaceBefore=space_before,
        spaceAfter=space_after, leftIndent=indent)

def _sev_col(s):
    return {"High":_C["red"],"Medium":_C["amber"],"Low":_C["blue"],"Info":_C["green"]}.get(s, _C["muted"])

def _rating_col(r):
    return {"Strong":_C["green"],"Moderate":_C["amber"],"Needs Improvement":_C["amber"],"High Risk":_C["red"]}.get(r, _C["muted"])

def _hline(): return HRFlowable(width="100%", thickness=0.5, color=_C["bdr"], spaceAfter=12, spaceBefore=0)

def _tbl_style(extra=None):
    base = [
        ("FONTSIZE",  (0,0), (-1,-1), 8.5),
        ("LEADING",   (0,0), (-1,-1), 12),
        ("PADDING",   (0,0), (-1,-1), 8),
        ("VALIGN",    (0,0), (-1,-1), "TOP"),
        ("LINEBELOW", (0,0), (-1,-1), 0.5, _C["bdr"]),
        ("BACKGROUND",(0,0), (-1, 0), _C["bg2"]),
        ("FONTNAME",  (0,0), (-1, 0), "Helvetica-Bold"),
        ("TEXTCOLOR", (0,0), (-1,-1), _C["text"]),
    ]
    if extra: base += extra
    return TableStyle(base)

class _PageCB:
    def __init__(self, company, analyst, date):
        self.company=company; self.analyst=analyst; self.date=date
        self._S = {
            "nav":  _ps("nav",  7.5, _C["muted"]),
            "foot": _ps("foot", 7,   _C["sub"]),
        }
    def header(self, canvas, doc):
        W, H = A4; c = canvas; c.saveState()
        # Top bar
        c.setFillColor(_C["navy"]); c.rect(0, H-44, W, 44, fill=1, stroke=0)
        # Blue accent strip
        c.setFillColor(_C["blue"]); c.rect(0, H-44, 4, 44, fill=1, stroke=0)
        # Logo
        c.setFont("Helvetica-Bold", 11); c.setFillColor(_C["white"])
        c.drawString(14*mm, H-16, "CyberGuard")
        c.setFont("Helvetica", 7.5); c.setFillColor(colors.HexColor("#94a3b8"))
        c.drawString(14*mm, H-28, "Security Review Platform")
        # Right side
        c.setFont("Helvetica", 7.5); c.setFillColor(colors.HexColor("#94a3b8"))
        c.drawRightString(W-14*mm, H-16, self.company)
        c.drawRightString(W-14*mm, H-28, self.date)
        # Bottom footer bar
        c.setFillColor(_C["bg2"]); c.rect(0, 0, W, 26, fill=1, stroke=0)
        c.setStrokeColor(_C["bdr"]); c.setLineWidth(0.5); c.line(0, 26, W, 26)
        c.setFont("Helvetica", 7); c.setFillColor(_C["sub"])
        c.drawString(14*mm, 9, f"Prepared by {self.analyst}  ·  Confidential — Authorised Review Only")
        c.drawRightString(W-14*mm, 9, f"Page {doc.page}")
        c.restoreState()
    def __call__(self, c, doc): self.header(c, doc)

def build_pdf(scan, company, analyst):
    buf = io.BytesIO()
    W, H = A4
    L, R, TB, BB = 14*mm, 14*mm, 52, 34

    doc = BaseDocTemplate(buf, pagesize=A4, leftMargin=L, rightMargin=R,
                          topMargin=TB, bottomMargin=BB)
    frame = Frame(L, BB, W-L-R, H-TB-BB, id="body")
    cb = _PageCB(company, analyst, scan["scanned_at"])
    doc.addPageTemplates([PageTemplate(id="main", frames=[frame], onPage=cb)])

    # ── Styles ──────────────────────────────────────────────────────────
    S = {
        "h1":    _ps("h1",    18, _C["navy"],  "Helvetica-Bold", leading=22, space_before=0, space_after=6),
        "h2":    _ps("h2",    11, _C["navy"],  "Helvetica-Bold", leading=15, space_before=18, space_after=8),
        "h3":    _ps("h3",    9,  _C["muted"], "Helvetica-Bold", leading=13, space_before=0,  space_after=4),
        "body":  _ps("body",  9,  _C["text"],  leading=14, space_after=4),
        "small": _ps("small", 8,  _C["text"],  leading=12, space_after=3),
        "muted": _ps("muted", 8,  _C["muted"], leading=12, space_after=3),
        "code":  _ps("code",  7.5,_C["muted"],"Helvetica", leading=11, space_after=2),
        "disc":  _ps("disc",  7.5,_C["muted"], leading=11, space_after=2),
    }

    story = []

    # ── Title block ──────────────────────────────────────────────────────
    rc = _rating_col(scan["rating"])
    title_data = [[
        Paragraph("Website Security<br/>Review Report", S["h1"]),
        Table([
            [Paragraph(f'<font color="{rc.hexval()}" size="22"><b>{scan["score"]}</b></font>'
                       f'<font color="#94a3b8" size="10"> / 100</font>', S["body"])],
            [Paragraph(f'<font color="{rc.hexval()}"><b>{scan["rating"]}</b></font>', S["h3"])],
        ], colWidths=[55*mm]),
    ]]
    title_tbl = Table(title_data, colWidths=[W-L-R-70*mm, 55*mm])
    title_tbl.setStyle(TableStyle([
        ("VALIGN",      (0,0),(-1,-1),"BOTTOM"),
        ("PADDING",     (0,0),(-1,-1), 0),
        ("ALIGN",       (1,0),(1,0),  "RIGHT"),
        ("LINEBELOW",   (0,0),(-1,0), 0.5, _C["bdr"]),
        ("BOTTOMPADDING",(0,0),(-1,0), 16),
    ]))
    story += [title_tbl, Spacer(1, 16)]

    # ── Meta table ──────────────────────────────────────────────────────
    meta = [
        [Paragraph("<b>Client</b>",     S["muted"]), Paragraph(company, S["small"])],
        [Paragraph("<b>Target</b>",     S["muted"]), Paragraph(scan["input_url"], S["small"])],
        [Paragraph("<b>Final URL</b>",  S["muted"]), Paragraph(scan["final_url"], S["small"])],
        [Paragraph("<b>Analyst</b>",    S["muted"]), Paragraph(analyst, S["small"])],
        [Paragraph("<b>Date</b>",       S["muted"]), Paragraph(scan["scanned_at"], S["small"])],
        [Paragraph("<b>HTTP Status</b>",S["muted"]), Paragraph(str(scan["status_code"]), S["small"])],
    ]
    meta_tbl = Table(meta, colWidths=[32*mm, W-L-R-32*mm])
    meta_tbl.setStyle(TableStyle([
        ("FONTSIZE",    (0,0),(-1,-1), 8.5),
        ("LEADING",     (0,0),(-1,-1), 12),
        ("PADDING",     (0,0),(-1,-1), 6),
        ("TOPPADDING",  (0,0),(-1,-1), 6),
        ("LINEBELOW",   (0,0),(-1,-1), 0.5, _C["bdr"]),
        ("BACKGROUND",  (0,0),(0,-1),  _C["bg2"]),
        ("BACKGROUND",  (1,0),(1,-1),  _C["bg"]),
        ("FONTNAME",    (0,0),(0,-1),  "Helvetica-Bold"),
        ("TEXTCOLOR",   (0,0),(0,-1),  _C["muted"]),
        ("TEXTCOLOR",   (1,0),(1,-1),  _C["text"]),
    ]))
    story += [meta_tbl, Spacer(1, 2)]

    # ── TLS block ───────────────────────────────────────────────────────
    story += [Paragraph("TLS / SSL Certificate", S["h2"]), _hline()]
    ssl = scan["ssl_info"]
    if ssl.get("enabled"):
        d = ssl.get("days_remaining", 0)
        dc = _C["green"] if d > 45 else _C["amber"] if d > 15 else _C["red"]
        ssl_rows = [
            [Paragraph("<b>Issuer</b>",         S["muted"]), Paragraph(ssl.get("issuer","—"),   S["small"])],
            [Paragraph("<b>Subject</b>",        S["muted"]), Paragraph(ssl.get("subject","—"),  S["small"])],
            [Paragraph("<b>Valid To</b>",       S["muted"]), Paragraph(ssl.get("valid_to","—"), S["small"])],
            [Paragraph("<b>Days Remaining</b>", S["muted"]),
             Paragraph(f'<font color="{dc.hexval()}"><b>{d}</b></font>', S["small"])],
        ]
        ssl_tbl = Table(ssl_rows, colWidths=[36*mm, W-L-R-36*mm])
        ssl_tbl.setStyle(TableStyle([
            ("FONTSIZE",   (0,0),(-1,-1), 8.5),
            ("LEADING",    (0,0),(-1,-1), 12),
            ("PADDING",    (0,0),(-1,-1), 6),
            ("LINEBELOW",  (0,0),(-1,-1), 0.5, _C["bdr"]),
            ("BACKGROUND", (0,0),(0,-1),  _C["bg2"]),
            ("BACKGROUND", (1,0),(1,-1),  _C["bg"]),
            ("FONTNAME",   (0,0),(0,-1),  "Helvetica-Bold"),
            ("TEXTCOLOR",  (0,0),(0,-1),  _C["muted"]),
            ("TEXTCOLOR",  (1,0),(1,-1),  _C["text"]),
        ]))
        story.append(ssl_tbl)
    else:
        story.append(Paragraph(f"TLS not available: {ssl.get('error','unknown error')}", S["muted"]))

    # ── Executive Summary ────────────────────────────────────────────────
    story += [Paragraph("Executive Summary", S["h2"]), _hline()]
    for pt in scan["summary"]:
        story.append(Paragraph(f"— {pt}", S["body"]))
    story.append(Spacer(1, 4))

    # ── Findings ─────────────────────────────────────────────────────────
    story += [Paragraph("Detailed Findings", S["h2"]), _hline()]

    header_row = [
        Paragraph("<b>Check</b>",          S["h3"]),
        Paragraph("<b>Category</b>",       S["h3"]),
        Paragraph("<b>Severity</b>",       S["h3"]),
        Paragraph("<b>Status</b>",         S["h3"]),
        Paragraph("<b>Recommendation</b>", S["h3"]),
    ]
    rows = [header_row]

    for f in scan["findings"]:
        sc = _sev_col(f["sev"])
        ok_txt = Paragraph(
            f'<font color="{"#16a34a" if f["ok"] else "#dc2626"}">{"Pass" if f["ok"] else "Fail"}</font>',
            S["small"])
        rows.append([
            Paragraph(f["name"],   S["small"]),
            Paragraph(f["cat"],    S["small"]),
            Paragraph(f'<font color="{sc.hexval()}"><b>{f["sev"]}</b></font>', S["small"]),
            ok_txt,
            Paragraph(f["fix"],    S["small"]),
        ])

    col_w = [40*mm, 30*mm, 18*mm, 12*mm, W-L-R-40*mm-30*mm-18*mm-12*mm]
    ft = Table(rows, colWidths=col_w, repeatRows=1)
    ft.setStyle(_tbl_style([
        ("ROWBACKGROUNDS",(0,1),(-1,-1),[_C["bg"],_C["bg1"]]),
    ]))
    story.append(ft)

    # ── Scope notice ─────────────────────────────────────────────────────
    story += [Spacer(1, 20)]
    disc_data = [[Paragraph(
        "Scope Notice: This report covers passive, defensive web configuration analysis only. "
        "No offensive, intrusive, or exploitative testing was performed. "
        "This document is intended for authorized assessment, portfolio demonstration, "
        "and client security awareness purposes.", S["disc"])]]
    disc_tbl = Table(disc_data, colWidths=[W-L-R])
    disc_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0,0),(-1,-1), _C["bg2"]),
        ("LINEABOVE",  (0,0),(-1, 0), 1.5, _C["blue"]),
        ("PADDING",    (0,0),(-1,-1), 10),
    ]))
    story.append(disc_tbl)

    doc.build(story)
    pdf = buf.getvalue(); buf.close(); return pdf

# ─────────────────────────────────────────────
# APP STATE
# ─────────────────────────────────────────────
_db_init()
if "user"      not in st.session_state: st.session_state.user      = None
if "last_scan" not in st.session_state: st.session_state.last_scan = None

# ─────────────────────────────────────────────
# AUTH SCREEN
# ─────────────────────────────────────────────
if st.session_state.user is None:
    st.markdown('<div class="g-auth-shell">', unsafe_allow_html=True)
    st.markdown("""
        <div class="g-auth-logo">
            <span class="g-logo-dot"></span> CyberGuard
        </div>
        <div class="g-auth-sub">Website security review platform</div>
    """, unsafe_allow_html=True)

    tab_in, tab_up = st.tabs(["Sign in", "Create account"])

    with tab_in:
        st.markdown('<div class="g-auth-box"><div class="g-auth-heading">Sign in</div>', unsafe_allow_html=True)
        em = st.text_input("Email", key="li_em", placeholder="you@company.com", label_visibility="collapsed")
        st.markdown('<div style="height:4px"></div>', unsafe_allow_html=True)
        pw = st.text_input("Password", type="password", key="li_pw", placeholder="Password", label_visibility="collapsed")
        st.markdown('<div style="height:12px"></div>', unsafe_allow_html=True)
        if st.button("Sign in", use_container_width=True, key="btn_li"):
            if not em or not pw:
                st.error("Enter email and password.")
            else:
                ok, user = authenticate_user(em, pw)
                if ok: st.session_state.user = user; st.rerun()
                else: st.error("Incorrect email or password.")
        st.markdown('</div>', unsafe_allow_html=True)

    with tab_up:
        st.markdown('<div class="g-auth-box"><div class="g-auth-heading">Create account</div>', unsafe_allow_html=True)
        nm  = st.text_input("Full name",   key="su_nm",  placeholder="Alex Johnson",      label_visibility="collapsed")
        em2 = st.text_input("Work email",  key="su_em",  placeholder="alex@company.com",  label_visibility="collapsed")
        pw2 = st.text_input("Password",    key="su_pw",  placeholder="Min. 8 characters", type="password", label_visibility="collapsed")
        st.markdown('<div style="height:12px"></div>', unsafe_allow_html=True)
        if st.button("Create account", use_container_width=True, key="btn_su"):
            if not nm or not em2 or not pw2: st.error("All fields required.")
            elif len(pw2) < 8:               st.error("Password must be at least 8 characters.")
            else:
                ok, msg = create_user(nm, em2, pw2)
                if ok: st.success(msg + " Sign in above.")
                else:  st.error(msg)
        st.markdown('</div>', unsafe_allow_html=True)

    st.markdown('</div>', unsafe_allow_html=True)
    st.stop()

# ─────────────────────────────────────────────
# MAIN APP
# ─────────────────────────────────────────────
user = st.session_state.user

# Sidebar
with st.sidebar:
    st.markdown(f"**{user['name']}**")
    st.caption(user["email"])
    st.divider()
    st.caption("Only scan websites you own or have explicit permission to assess.")
    st.write("")
    if st.button("Sign out", use_container_width=True):
        st.session_state.user = None; st.session_state.last_scan = None; st.rerun()

# Top nav
st.markdown(f"""
<div class="g-nav">
  <div class="g-logo">
    <span class="g-logo-dot"></span> CyberGuard
  </div>
  <div class="g-nav-right">
    <span class="g-status-dot"></span>
    <span class="g-user">{user['name']}</span>
  </div>
</div>
""", unsafe_allow_html=True)

# Page wrapper
st.markdown('<div class="g-page-wide">', unsafe_allow_html=True)

# Hero
st.markdown("""
<div class="g-hero">
  <div class="g-label"><span class="g-label-dot"></span> Security Review Platform</div>
  <h1 class="g-h1">Website security,<br><span>reviewed in seconds.</span></h1>
  <p class="g-body">Passive defensive analysis across TLS, security headers, cookies, and information
  disclosure. Generate a polished PDF report ready for client delivery.</p>
</div>
""", unsafe_allow_html=True)

# Scan panel
st.markdown('<div class="g-scan-panel">', unsafe_allow_html=True)
col1, col2, col3 = st.columns([3, 2, 1], gap="medium")
with col1:
    st.markdown('<div class="g-field-label">Target URL</div>', unsafe_allow_html=True)
    target_url = st.text_input("url", label_visibility="collapsed",
                                placeholder="https://example.com", key="k_url")
with col2:
    st.markdown('<div class="g-field-label">Client name</div>', unsafe_allow_html=True)
    client_name = st.text_input("client", label_visibility="collapsed",
                                 placeholder="Acme Corporation", key="k_client")
with col3:
    st.markdown('<div style="height:26px"></div>', unsafe_allow_html=True)
    scan_btn = st.button("Run scan", use_container_width=True, key="k_scan")
st.markdown('</div>', unsafe_allow_html=True)

# Execute scan
if scan_btn:
    if not target_url.strip():
        st.error("Please enter a target URL.")
    else:
        try:
            with st.spinner("Running security checks…"):
                st.session_state.last_scan = run_scan(target_url)
        except requests.exceptions.SSLError:
            st.error("SSL handshake failed. Verify the target supports HTTPS.")
        except requests.exceptions.ConnectionError:
            st.error("Could not connect to target. Check the URL and try again.")
        except requests.exceptions.Timeout:
            st.error("Request timed out.")
        except Exception as e:
            st.error(f"Unexpected error: {e}")

# ─────────────────────────────────────────────
# RESULTS
# ─────────────────────────────────────────────
scan = st.session_state.last_scan

if scan:
    ssl_info = scan["ssl_info"]

    def _rcol(r):
        return {"Strong":"col-green","Moderate":"col-amber","Needs Improvement":"col-amber","High Risk":"col-red"}.get(r,"col-text")

    ssl_days = ssl_info.get("days_remaining")

    # Stat row
    ssl_display = "Active" if ssl_info.get("enabled") else "None"
    ssl_col     = "col-green" if ssl_info.get("enabled") else "col-red"
    issues      = sum(1 for f in scan["findings"] if not f["ok"])

    st.markdown(f"""
    <div class="g-stats">
      <div class="g-stat">
        <div class="g-stat-label">Security score</div>
        <div class="g-stat-val {_rcol(scan['rating'])}">{scan['score']}<span style="font-size:1rem;color:var(--c-subtle);font-weight:400"> /100</span></div>
        <div class="g-stat-sub">{scan['rating']}</div>
      </div>
      <div class="g-stat">
        <div class="g-stat-label">TLS / SSL</div>
        <div class="g-stat-val {ssl_col}">{ssl_display}</div>
        <div class="g-stat-sub">{f"{ssl_days} days remaining" if ssl_days is not None and ssl_info.get("enabled") else "Certificate status"}</div>
      </div>
      <div class="g-stat">
        <div class="g-stat-label">HTTP status</div>
        <div class="g-stat-val">{scan['status_code']}</div>
        <div class="g-stat-sub">Final response code</div>
      </div>
      <div class="g-stat">
        <div class="g-stat-label">Issues found</div>
        <div class="g-stat-val {'col-red' if issues > 3 else 'col-amber' if issues > 0 else 'col-green'}">{issues}</div>
        <div class="g-stat-sub">of {len(scan['findings'])} checks</div>
      </div>
    </div>
    """, unsafe_allow_html=True)

    # Summary + TLS
    col_l, col_r = st.columns([3, 2], gap="medium")

    with col_l:
        st.markdown("""
        <div class="g-card">
          <div class="g-card-title">Executive Summary</div>
        """, unsafe_allow_html=True)
        for pt in scan["summary"]:
            st.markdown(f"""
            <div class="g-bullet">
              <div class="g-bullet-icon">›</div>
              <div>{pt}</div>
            </div>
            """, unsafe_allow_html=True)
        st.markdown(f"""
          <div style="margin-top:20px">
            <div class="g-kv"><span class="g-kv-k">Input URL</span><span class="g-kv-v">{scan['input_url']}</span></div>
            <div class="g-kv"><span class="g-kv-k">Final URL</span><span class="g-kv-v">{scan['final_url']}</span></div>
            <div class="g-kv"><span class="g-kv-k">Reviewed</span><span class="g-kv-v">{scan['scanned_at']}</span></div>
          </div>
        </div>
        """, unsafe_allow_html=True)

    with col_r:
        st.markdown("""
        <div class="g-card">
          <div class="g-card-title">TLS Certificate</div>
        """, unsafe_allow_html=True)
        if ssl_info.get("enabled"):
            d = ssl_info.get("days_remaining", 0)
            dc = "col-green" if d > 45 else "col-amber" if d > 15 else "col-red"
            st.markdown(f"""
              <div style="margin-bottom:20px">
                <span class="g-stat-val {dc}" style="font-size:2.25rem">{d}</span>
                <span style="font-size:0.8rem;color:var(--c-muted);margin-left:6px">days remaining</span>
              </div>
              <div class="g-kv"><span class="g-kv-k">Issuer</span><span class="g-kv-v">{ssl_info.get('issuer','—')}</span></div>
              <div class="g-kv"><span class="g-kv-k">Subject</span><span class="g-kv-v">{ssl_info.get('subject','—')}</span></div>
              <div class="g-kv"><span class="g-kv-k">Valid to</span><span class="g-kv-v">{ssl_info.get('valid_to','—')}</span></div>
            """, unsafe_allow_html=True)
        else:
            st.markdown(f"""
              <div style="color:var(--c-red);font-size:1.5rem;font-weight:600;margin-bottom:8px">Not available</div>
              <div style="font-size:0.8rem;color:var(--c-muted)">{ssl_info.get('error','TLS not detected.')}</div>
            """, unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)

    # Findings
    st.markdown("""
    <div class="g-section-header">
      <span class="g-section-title">Findings</span>
      <span class="g-section-count">Expand each category to review details and remediation guidance</span>
    </div>
    """, unsafe_allow_html=True)

    cats = {}
    for f in scan["findings"]: cats.setdefault(f["cat"], []).append(f)

    bdg = {"High":"g-badge-high","Medium":"g-badge-medium","Low":"g-badge-low","Info":"g-badge-info"}

    for cat, items in cats.items():
        passed = sum(1 for f in items if f["ok"])
        with st.expander(f"**{cat}** — {passed} / {len(items)} passed"):
            for item in items:
                dot_col = "#16a34a" if item["ok"] else ("#dc2626" if item["sev"]=="High" else "#d97706" if item["sev"]=="Medium" else "#60a5fa")
                st.markdown(f"""
                <div class="g-finding">
                  <div class="g-finding-row">
                    <div class="g-finding-status" style="background:{dot_col}"></div>
                    <div class="g-finding-name">{item['name']}</div>
                    <span class="g-badge {bdg.get(item['sev'],'g-badge-info')}">{item['sev']}</span>
                  </div>
                  <div class="g-finding-desc">{item['desc']}</div>
                  <div class="g-finding-meta">
                    <span class="g-code">{item['val']}</span>
                    <span class="g-rec">→ {item['fix']}</span>
                  </div>
                </div>
                """, unsafe_allow_html=True)

    # Export
    st.markdown("""
    <div class="g-section-header" style="margin-top:32px">
      <span class="g-section-title">Export</span>
    </div>
    """, unsafe_allow_html=True)

    ec1, ec2 = st.columns([2, 1], gap="medium")
    with ec1:
        st.markdown("""
        <div class="g-card">
          <div class="g-card-title">PDF Report</div>
          <div style="font-size:0.82rem;color:var(--c-muted);line-height:1.7">
            A clean A4 PDF including the score summary, TLS certificate details,
            executive summary, full findings table with recommendations,
            and a scope disclaimer — ready for client delivery.
          </div>
        </div>
        """, unsafe_allow_html=True)
    with ec2:
        st.markdown('<div style="height:10px"></div>', unsafe_allow_html=True)
        pdf_bytes = build_pdf(scan, client_name or "—", user["name"])
        st.download_button(
            "Download PDF report",
            data=pdf_bytes,
            file_name=f"cyberguard-{scan['hostname']}.pdf",
            mime="application/pdf",
            use_container_width=True,
        )
        st.caption("Suitable for portfolio, client delivery, and internal review.")

st.markdown('</div>', unsafe_allow_html=True)  # close g-page-wide

# Footer
st.markdown("""
<div class="g-footer">
  <span>CyberGuard · Pamupro Cyber</span>
  <span>Authorised defensive reviews only. Do not scan without permission.</span>
</div>
""", unsafe_allow_html=True)
