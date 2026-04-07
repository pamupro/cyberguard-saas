"""
CyberGuard v2 – Business Website Security Review Platform
Single-file Streamlit app (Streamlit Cloud compatible).
"""

# ============================================================
# STDLIB / THIRD-PARTY IMPORTS
# ============================================================
import hashlib
import io
import os
import socket
import sqlite3
import ssl
from contextlib import closing
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

import requests
import streamlit as st
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    HRFlowable,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

# ============================================================
# PAGE CONFIG  (must be first Streamlit call)
# ============================================================
st.set_page_config(
    page_title="CyberGuard — Security Review Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ============================================================
# GLOBAL CSS
# ============================================================
st.markdown("""
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Syne:wght@600;700;800&family=DM+Sans:wght@300;400;500;600&display=swap" rel="stylesheet">

<style>
:root {
    --bg:        #060c18;
    --surface:   #0d1525;
    --surface2:  #111d30;
    --border:    rgba(255,255,255,0.06);
    --border2:   rgba(255,255,255,0.10);
    --blue:      #2B5BFF;
    --blue-glow: rgba(43,91,255,0.25);
    --cyan:      #38bdf8;
    --green:     #22c55e;
    --amber:     #f59e0b;
    --red:       #ef4444;
    --text:      #e2eaf6;
    --muted:     #64748b;
    --subtle:    #94a3b8;
    --font-head: 'Syne', sans-serif;
    --font-body: 'DM Sans', sans-serif;
}
html, body, [class*="css"] { font-family: var(--font-body) !important; color: var(--text) !important; }
.stApp {
    background:
        radial-gradient(ellipse 80% 40% at 50% -10%, rgba(43,91,255,0.14) 0%, transparent 60%),
        radial-gradient(ellipse 40% 30% at 90% 20%, rgba(56,189,248,0.07) 0%, transparent 50%),
        linear-gradient(180deg, #060c18 0%, #07101f 100%);
    min-height: 100vh;
}
#MainMenu, footer, header { visibility: hidden; }
.block-container { padding: 0 !important; max-width: 100% !important; }
[data-testid="stSidebar"] { background: var(--surface) !important; border-right: 1px solid var(--border) !important; }
input[type="text"], input[type="password"], input[type="email"], [data-testid="stTextInput"] input {
    background: var(--surface2) !important; border: 1px solid var(--border2) !important;
    border-radius: 10px !important; color: var(--text) !important;
    font-family: var(--font-body) !important; font-size: 0.95rem !important;
    padding: 0.65rem 1rem !important; transition: border-color 0.2s;
}
input:focus { border-color: var(--blue) !important; outline: none !important; }
.stButton > button {
    background: linear-gradient(135deg, #2B5BFF 0%, #1a3fa8 100%) !important;
    color: #fff !important; border: none !important; border-radius: 10px !important;
    font-family: var(--font-body) !important; font-weight: 600 !important;
    font-size: 0.92rem !important; padding: 0.65rem 1.4rem !important;
    cursor: pointer !important; transition: all 0.2s !important;
    box-shadow: 0 4px 20px rgba(43,91,255,0.30) !important;
}
.stButton > button:hover { transform: translateY(-1px) !important; box-shadow: 0 6px 28px rgba(43,91,255,0.45) !important; }
[data-testid="stDownloadButton"] > button { background: linear-gradient(135deg, #0ea5e9 0%, #2B5BFF 100%) !important; width: 100% !important; }
[data-testid="stExpander"] { background: var(--surface2) !important; border: 1px solid var(--border) !important; border-radius: 12px !important; margin-bottom: 0.5rem !important; }
[data-testid="stExpander"] summary { font-family: var(--font-body) !important; font-weight: 500 !important; color: var(--text) !important; }
[data-testid="stTabs"] [role="tablist"] { border-bottom: 1px solid var(--border2) !important; gap: 0.2rem !important; }
[data-testid="stTabs"] button { font-family: var(--font-body) !important; font-weight: 500 !important; color: var(--muted) !important; border-radius: 8px 8px 0 0 !important; padding: 0.55rem 1.1rem !important; border: none !important; background: transparent !important; }
[data-testid="stTabs"] button[aria-selected="true"] { color: var(--blue) !important; border-bottom: 2px solid var(--blue) !important; background: rgba(43,91,255,0.06) !important; }
::-webkit-scrollbar { width: 5px; background: var(--bg); }
::-webkit-scrollbar-thumb { background: var(--surface2); border-radius: 4px; }

.cg-navbar { display:flex; align-items:center; justify-content:space-between; padding:1rem 2.5rem; border-bottom:1px solid var(--border); background:rgba(6,12,24,0.80); backdrop-filter:blur(16px); position:sticky; top:0; z-index:100; }
.cg-logo { font-family:var(--font-head); font-size:1.35rem; font-weight:800; color:#fff; letter-spacing:-0.03em; }
.cg-logo span { color:var(--blue); }
.cg-badge { display:inline-flex; align-items:center; gap:0.35rem; font-size:0.72rem; font-weight:600; letter-spacing:0.05em; text-transform:uppercase; color:var(--cyan); background:rgba(56,189,248,0.10); border:1px solid rgba(56,189,248,0.20); border-radius:999px; padding:0.28rem 0.75rem; }
.cg-user-pill { display:inline-flex; align-items:center; gap:0.5rem; font-size:0.87rem; color:var(--subtle); background:var(--surface2); border:1px solid var(--border2); border-radius:999px; padding:0.35rem 1rem; }
.cg-hero { padding:3.5rem 2.5rem 2.5rem; max-width:900px; }
.cg-eyebrow { font-size:0.75rem; font-weight:600; letter-spacing:0.12em; text-transform:uppercase; color:var(--blue); margin-bottom:0.8rem; }
.cg-headline { font-family:var(--font-head); font-size:3rem; font-weight:800; line-height:1.05; letter-spacing:-0.04em; color:#fff; margin-bottom:1rem; }
.cg-headline em { color:var(--blue); font-style:normal; }
.cg-desc { font-size:1.05rem; color:var(--subtle); line-height:1.6; max-width:580px; margin-bottom:0; }
.cg-scan-box { background:var(--surface); border:1px solid var(--border2); border-radius:18px; padding:1.75rem 2rem; margin:0 2.5rem 2rem; box-shadow:0 8px 40px rgba(0,0,0,0.3); }
.cg-scan-label { font-size:0.75rem; font-weight:600; letter-spacing:0.08em; text-transform:uppercase; color:var(--muted); margin-bottom:0.4rem; }
.cg-metrics { display:grid; grid-template-columns:repeat(4,1fr); gap:1rem; margin:0 2.5rem 2rem; }
.cg-metric { background:var(--surface); border:1px solid var(--border); border-radius:16px; padding:1.25rem 1.35rem; position:relative; overflow:hidden; }
.cg-metric::before { content:''; position:absolute; top:0; left:0; width:100%; height:2px; background:linear-gradient(90deg,var(--blue),transparent); }
.cg-metric-label { font-size:0.76rem; font-weight:600; letter-spacing:0.06em; text-transform:uppercase; color:var(--muted); margin-bottom:0.5rem; }
.cg-metric-value { font-family:var(--font-head); font-size:2rem; font-weight:700; color:#fff; letter-spacing:-0.03em; line-height:1; }
.cg-metric-sub { font-size:0.77rem; color:var(--muted); margin-top:0.3rem; }
.cg-section { margin:0 2.5rem 2rem; }
.cg-section-head { font-family:var(--font-head); font-size:1.1rem; font-weight:700; color:#fff; margin-bottom:0.2rem; }
.cg-section-sub { font-size:0.82rem; color:var(--muted); margin-bottom:1rem; }
.cg-card { background:var(--surface); border:1px solid var(--border); border-radius:16px; padding:1.5rem; }
.cg-score-ring { display:inline-flex; align-items:baseline; gap:3px; }
.cg-score-big { font-family:var(--font-head); font-size:3.2rem; font-weight:800; letter-spacing:-0.04em; line-height:1; }
.cg-score-denom { font-size:1rem; color:var(--muted); }
.cg-auth-wrap { min-height:100vh; display:flex; flex-direction:column; align-items:center; justify-content:center; padding:2rem; background:radial-gradient(ellipse 70% 50% at 50% 0%,rgba(43,91,255,0.15),transparent 60%),var(--bg); }
.cg-auth-logo { font-family:var(--font-head); font-size:1.8rem; font-weight:800; color:#fff; letter-spacing:-0.04em; margin-bottom:0.3rem; text-align:center; }
.cg-auth-logo span { color:var(--blue); }
.cg-auth-tagline { font-size:0.9rem; color:var(--muted); text-align:center; margin-bottom:2.5rem; }
.cg-auth-card { background:var(--surface); border:1px solid var(--border2); border-radius:20px; padding:2.2rem 2rem; width:100%; max-width:460px; box-shadow:0 20px 60px rgba(0,0,0,0.4); }
.cg-auth-title { font-family:var(--font-head); font-size:1.4rem; font-weight:700; color:#fff; margin-bottom:1.5rem; }
.cg-divider { border:none; border-top:1px solid var(--border); margin:1.5rem 0; }
.cg-tag { display:inline-block; font-size:0.72rem; font-weight:600; letter-spacing:0.04em; text-transform:uppercase; padding:0.22rem 0.65rem; border-radius:6px; margin-right:0.35rem; }
.cg-tag-high   { background:rgba(239,68,68,0.12);  color:var(--red);   border:1px solid rgba(239,68,68,0.2);   }
.cg-tag-medium { background:rgba(245,158,11,0.12); color:var(--amber); border:1px solid rgba(245,158,11,0.2);  }
.cg-tag-low    { background:rgba(56,189,248,0.10); color:var(--cyan);  border:1px solid rgba(56,189,248,0.18); }
.cg-tag-info   { background:rgba(34,197,94,0.10);  color:var(--green); border:1px solid rgba(34,197,94,0.18);  }
.cg-summary-bullet { display:flex; align-items:flex-start; gap:0.6rem; padding:0.65rem 0; border-bottom:1px solid var(--border); font-size:0.9rem; color:var(--subtle); }
.cg-summary-bullet:last-child { border-bottom:none; }
.cg-footer { padding:1.5rem 2.5rem; border-top:1px solid var(--border); display:flex; align-items:center; justify-content:space-between; font-size:0.78rem; color:var(--muted); }
.rating-strong   { color:var(--green)  !important; }
.rating-moderate { color:var(--amber)  !important; }
.rating-needs    { color:var(--amber)  !important; }
.rating-high     { color:var(--red)    !important; }
</style>
""", unsafe_allow_html=True)

# ============================================================
# ── AUTH MODULE (inline) ─────────────────────────────────────
# ============================================================
DB_FILE = "cyberguard.db"

def _db_init():
    with closing(sqlite3.connect(DB_FILE)) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                name          TEXT    NOT NULL,
                email         TEXT    UNIQUE NOT NULL,
                password_hash TEXT    NOT NULL,
                created_at    TEXT    NOT NULL
            )""")
        conn.commit()

def _pw_hash(password: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 260_000)
    return f"pbkdf2${salt.hex()}${dk.hex()}"

def _pw_verify(password: str, stored: str) -> bool:
    try:
        _, salt_hex, dk_hex = stored.split("$")
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), 260_000)
        return dk.hex() == dk_hex
    except Exception:
        return False

def create_user(name, email, password):
    try:
        with closing(sqlite3.connect(DB_FILE)) as conn:
            conn.execute(
                "INSERT INTO users (name,email,password_hash,created_at) VALUES (?,?,?,?)",
                (name.strip(), email.strip().lower(), _pw_hash(password), datetime.utcnow().isoformat()),
            )
            conn.commit()
        return True, "Account created successfully."
    except sqlite3.IntegrityError:
        return False, "That email is already registered."
    except Exception as e:
        return False, str(e)

def authenticate_user(email, password):
    with closing(sqlite3.connect(DB_FILE)) as conn:
        row = conn.execute(
            "SELECT id,name,email,password_hash FROM users WHERE email=?",
            (email.strip().lower(),)
        ).fetchone()
    if row and _pw_verify(password, row[3]):
        return True, {"id": row[0], "name": row[1], "email": row[2]}
    return False, None

# ============================================================
# ── SCANNER MODULE (inline) ──────────────────────────────────
# ============================================================
SCAN_TIMEOUT = 10
UA = "CyberGuard/2.0 (authorized defensive review)"

PRIMARY_HEADERS = {
    "Strict-Transport-Security": {"weight":14,"severity":"High","desc":"Forces browsers to use HTTPS, preventing SSL stripping.","advice":"Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"},
    "Content-Security-Policy":   {"weight":16,"severity":"High","desc":"Controls which resources the browser may load, reducing XSS risk.","advice":"Define a restrictive CSP policy tailored to your application."},
    "X-Frame-Options":           {"weight":8, "severity":"Medium","desc":"Prevents iframe embedding, blocking clickjacking attacks.","advice":"Add: X-Frame-Options: DENY"},
    "X-Content-Type-Options":    {"weight":8, "severity":"Medium","desc":"Stops MIME-type sniffing in browsers.","advice":"Add: X-Content-Type-Options: nosniff"},
    "Referrer-Policy":           {"weight":6, "severity":"Low","desc":"Controls how much referrer info is shared with other sites.","advice":"Add: Referrer-Policy: strict-origin-when-cross-origin"},
    "Permissions-Policy":        {"weight":6, "severity":"Low","desc":"Restricts which browser APIs the page may use.","advice":"Define a Permissions-Policy based on your app's actual needs."},
}
OPTIONAL_HEADERS = ["Cross-Origin-Opener-Policy","Cross-Origin-Resource-Policy","Cross-Origin-Embedder-Policy"]
SAFE_PATHS = ["/robots.txt","/security.txt","/.well-known/security.txt","/sitemap.xml"]

def _fetch(url):
    return requests.get(url, timeout=SCAN_TIMEOUT, headers={"User-Agent": UA}, allow_redirects=True)

def _normalize(raw):
    raw = raw.strip()
    if raw and not raw.startswith(("http://","https://")):
        raw = "https://" + raw
    return raw

def _hostname(url):
    return urlparse(url).hostname or ""

def _check_ssl(hostname, port=443):
    r = {"enabled":False,"issuer":None,"subject":None,"valid_to":None,"days_remaining":None,"error":None}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ss:
                cert = ss.getpeercert()
        r["enabled"] = True
        issuer  = dict(x[0] for x in cert.get("issuer",[]))
        subject = dict(x[0] for x in cert.get("subject",[]))
        r["issuer"]  = issuer.get("organizationName") or str(issuer)
        r["subject"] = subject.get("commonName") or str(subject)
        vt = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        r["valid_to"] = vt.strftime("%Y-%m-%d")
        r["days_remaining"] = (vt.replace(tzinfo=timezone.utc) - datetime.now(timezone.utc)).days
    except Exception as e:
        r["error"] = str(e)
    return r

def _check_protocol(input_url, final_url):
    return [
        {"category":"Protocol","name":"HTTPS on input URL","present":input_url.startswith("https://"),"severity":"High","weight":14,"value":input_url,"description":"Checks the supplied URL uses HTTPS.","recommendation":"Use HTTPS as the canonical starting point."},
        {"category":"Protocol","name":"HTTPS on final URL","present":final_url.startswith("https://"),"severity":"High","weight":14,"value":final_url,"description":"Checks the final destination uses HTTPS.","recommendation":"Redirect all HTTP traffic permanently to HTTPS."},
    ]

def _check_headers(resp):
    findings = []
    for h, m in PRIMARY_HEADERS.items():
        present = h in resp.headers
        findings.append({"category":"Security Headers","name":h,"present":present,"severity":"Info" if present else m["severity"],"weight":m["weight"],"value":resp.headers.get(h,"—"),"description":m["desc"],"recommendation":"✓ Configured" if present else m["advice"]})
    for h in OPTIONAL_HEADERS:
        present = h in resp.headers
        findings.append({"category":"Security Headers","name":h,"present":present,"severity":"Info" if present else "Low","weight":3,"value":resp.headers.get(h,"—"),"description":"Additional cross-origin isolation header.","recommendation":"✓ Configured" if present else f"Consider adding {h}."})
    return findings

def _check_cookies(resp):
    raw = resp.raw.headers.get_all("Set-Cookie") if hasattr(resp.raw.headers,"get_all") else []
    if not raw:
        return [{"category":"Cookies","name":"Cookie presence","present":True,"severity":"Info","weight":0,"value":"No Set-Cookie headers","description":"No cookies were set in this response.","recommendation":"No action required."}]
    out = []
    for i, c in enumerate(raw, 1):
        low = c.lower()
        missing = [f for f,k in [("Secure","secure"),("HttpOnly","httponly"),("SameSite","samesite")] if k not in low]
        out.append({"category":"Cookies","name":f"Cookie #{i} flags","present":not missing,"severity":"Info" if not missing else "Medium","weight":8,"value":c[:120]+("…" if len(c)>120 else ""),"description":"Cookies without Secure/HttpOnly/SameSite can be stolen or forged.","recommendation":"✓ All flags present" if not missing else f"Add missing flags: {', '.join(missing)}"})
    return out

def _check_disclosure(resp):
    out = []
    for h, label in [("Server","Server header disclosure"),("X-Powered-By","X-Powered-By disclosure")]:
        val = resp.headers.get(h)
        out.append({"category":"Information Disclosure","name":label,"present":not bool(val),"severity":"Info" if not val else "Low","weight":5,"value":val or "Not exposed","description":"Exposing server/framework versions aids targeted attacks.","recommendation":"✓ Not exposed" if not val else f"Remove or redact the {h} header."})
    return out

def _check_paths(base_url):
    session = requests.Session()
    out = []
    for path in SAFE_PATHS:
        url = urljoin(base_url, path)
        try:
            r = session.get(url, timeout=5, headers={"User-Agent":UA}, allow_redirects=True)
            ok = r.status_code == 200
            out.append({"category":"Security Files","name":path,"present":ok,"severity":"Info" if ok else "Low","weight":3,"value":f"HTTP {r.status_code}","description":"Standard file aiding security researchers.","recommendation":"✓ Present" if ok else f"Consider publishing {path}."})
        except Exception:
            out.append({"category":"Security Files","name":path,"present":False,"severity":"Low","weight":3,"value":"Unreachable","description":"Standard file aiding security researchers.","recommendation":f"Consider publishing {path}."})
    return out

def _score(findings, ssl_info):
    max_pts = sum(f["weight"] for f in findings if f["weight"]>0) + 10
    earned  = sum(f["weight"] for f in findings if f["present"] and f["weight"]>0)
    if ssl_info.get("enabled"):
        days = ssl_info.get("days_remaining")
        earned += 10 if (days is None or days>=45) else 6 if days>=15 else 3 if days>=0 else 0
    score = round(earned/max_pts*100) if max_pts else 0
    if score>=85: return score,"Strong"
    if score>=70: return score,"Moderate"
    if score>=50: return score,"Needs Improvement"
    return score,"High Risk"

def _summary(findings, ssl_info):
    pts = []
    crit = [f["name"] for f in findings if not f["present"] and f["severity"]=="High"]
    med  = [f["name"] for f in findings if not f["present"] and f["severity"]=="Medium"]
    if crit: pts.append(f"High-severity gaps: {', '.join(crit[:3])}.")
    if med:  pts.append(f"Medium-severity issues: {', '.join(med[:3])}.")
    days = ssl_info.get("days_remaining")
    if ssl_info.get("enabled") and days is not None and days<30:
        pts.append(f"TLS certificate expires in {days} days — renew promptly.")
    if not pts: pts.append("No critical defensive configuration issues were identified.")
    return pts

def run_scan(url):
    target = _normalize(url)
    resp   = _fetch(target)
    host   = _hostname(target)
    ssl_info = _check_ssl(host) if host else {"enabled":False,"error":"No hostname"}
    findings = (_check_protocol(target,resp.url) + _check_headers(resp) +
                _check_cookies(resp) + _check_disclosure(resp) + _check_paths(resp.url))
    score, rating = _score(findings, ssl_info)
    return {"input_url":target,"final_url":resp.url,"hostname":host,"status_code":resp.status_code,
            "ssl_info":ssl_info,"findings":findings,"score":score,"rating":rating,
            "summary":_summary(findings,ssl_info),"scanned_at":datetime.utcnow().strftime("%d %b %Y, %H:%M UTC")}

# ============================================================
# ── REPORT MODULE (inline) ───────────────────────────────────
# ============================================================
_NAVY  = colors.HexColor("#0a0f1e")
_DARK  = colors.HexColor("#0d1526")
_BLUE  = colors.HexColor("#2563eb")
_LBLUE = colors.HexColor("#60a5fa")
_SLATE = colors.HexColor("#94a3b8")
_WHITE = colors.HexColor("#f8fafc")
_GREEN = colors.HexColor("#22c55e")
_AMBER = colors.HexColor("#f59e0b")
_RED   = colors.HexColor("#ef4444")
_LGRAY = colors.HexColor("#f1f5f9")
_MGRAY = colors.HexColor("#e2e8f0")
_DGRAY = colors.HexColor("#334155")

def _sev_color(s):
    return {"High":_RED,"Medium":_AMBER,"Low":_LBLUE,"Info":_GREEN}.get(s,_SLATE)

def _rating_color(r):
    return {"Strong":_GREEN,"Moderate":_AMBER,"Needs Improvement":_AMBER,"High Risk":_RED}.get(r,_SLATE)

def _pdf_styles():
    return {
        "title": ParagraphStyle("cg_t",fontSize=22,textColor=_WHITE,fontName="Helvetica-Bold",spaceAfter=2,leading=26),
        "h2":    ParagraphStyle("cg_h2",fontSize=13,textColor=_DARK,fontName="Helvetica-Bold",spaceBefore=12,spaceAfter=5,leading=17),
        "body":  ParagraphStyle("cg_b",fontSize=9,textColor=_DGRAY,fontName="Helvetica",leading=13,spaceAfter=4),
        "small": ParagraphStyle("cg_s",fontSize=8,textColor=_DGRAY,fontName="Helvetica",leading=12),
        "tiny":  ParagraphStyle("cg_ti",fontSize=7,textColor=_SLATE,fontName="Helvetica",leading=11),
        "bullet":ParagraphStyle("cg_bu",fontSize=9,textColor=_DGRAY,fontName="Helvetica",leading=13,spaceAfter=3,leftIndent=10),
    }

class _HF:
    def __init__(self, company, target, analyst, date):
        self.company=company; self.target=target; self.analyst=analyst; self.date=date
    def __call__(self, canvas, doc):
        W, H = A4; canvas.saveState()
        canvas.setFillColor(_NAVY); canvas.rect(0,H-50,W,50,fill=1,stroke=0)
        canvas.setFillColor(_BLUE); canvas.rect(0,H-50,5,50,fill=1,stroke=0)
        canvas.setFont("Helvetica-Bold",13); canvas.setFillColor(_WHITE); canvas.drawString(16*mm,H-28,"CyberGuard")
        canvas.setFont("Helvetica",8); canvas.setFillColor(_SLATE)
        canvas.drawString(16*mm,H-40,"Security Review Platform")
        canvas.drawRightString(W-14*mm,H-28,self.company)
        canvas.drawRightString(W-14*mm,H-40,self.date)
        canvas.setFillColor(_LGRAY); canvas.rect(0,0,W,20,fill=1,stroke=0)
        canvas.setFont("Helvetica",7); canvas.setFillColor(_SLATE)
        canvas.drawString(14*mm,7,f"Analyst: {self.analyst}  |  Target: {self.target}  |  Page {doc.page}")
        canvas.drawRightString(W-14*mm,7,"AUTHORIZED DEFENSIVE REVIEW ONLY")
        canvas.restoreState()

def build_pdf(scan, company, analyst):
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf,pagesize=A4,leftMargin=16*mm,rightMargin=16*mm,topMargin=56,bottomMargin=28)
    S = _pdf_styles(); cb = _HF(company,scan["input_url"],analyst,scan["scanned_at"]); story = []
    # Cover
    cover = Table([[Paragraph("Security Review Report",S["title"])]],colWidths=[doc.width])
    cover.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,-1),_NAVY),("PADDING",(0,0),(-1,-1),14)]))
    story += [cover, Spacer(1,8)]
    # Meta
    meta = Table([["Client",company],["Target",scan["input_url"]],["Final URL",scan["final_url"]],["Analyst",analyst],["Reviewed",scan["scanned_at"]]],colWidths=[40*mm,doc.width-40*mm])
    meta.setStyle(TableStyle([("BACKGROUND",(0,0),(0,-1),_LGRAY),("GRID",(0,0),(-1,-1),0.4,_MGRAY),("FONTNAME",(0,0),(0,-1),"Helvetica-Bold"),("FONTSIZE",(0,0),(-1,-1),9),("PADDING",(0,0),(-1,-1),6)]))
    story += [meta, Spacer(1,12)]
    # Score card
    rc = _rating_color(scan["rating"])
    sc_data = [[
        Paragraph(f'<font size="28" color="{rc.hexval()}"><b>{scan["score"]}</b></font><font size="11" color="#94a3b8">/100</font>',S["body"]),
        Paragraph(f'<font size="16" color="{rc.hexval()}"><b>{scan["rating"]}</b></font>',S["body"]),
        Paragraph(f'<font size="14"><b>HTTP {scan["status_code"]}</b></font>',S["body"]),
        Paragraph(f'<font size="14" color="{"#22c55e" if scan["ssl_info"].get("enabled") else "#ef4444"}"><b>{"✓ TLS Active" if scan["ssl_info"].get("enabled") else "✗ No TLS"}</b></font>',S["body"]),
    ]]
    sc_tbl = Table(sc_data,colWidths=[doc.width/4]*4)
    sc_tbl.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,-1),_NAVY),("ALIGN",(0,0),(-1,-1),"CENTER"),("VALIGN",(0,0),(-1,-1),"MIDDLE"),("PADDING",(0,0),(-1,-1),14),("LINEAFTER",(0,0),(2,0),0.5,_DGRAY)]))
    story += [sc_tbl, Spacer(1,12)]
    # SSL
    story.append(Paragraph("TLS Certificate",S["h2"])); story.append(HRFlowable(width="100%",thickness=0.5,color=_MGRAY,spaceAfter=5))
    ssl = scan["ssl_info"]
    if ssl.get("enabled"):
        st2 = Table([["Issuer",ssl.get("issuer","—")],["Subject",ssl.get("subject","—")],["Valid To",ssl.get("valid_to","—")],["Days Remaining",str(ssl.get("days_remaining","—"))]],colWidths=[38*mm,doc.width-38*mm])
        st2.setStyle(TableStyle([("BACKGROUND",(0,0),(0,-1),_LGRAY),("GRID",(0,0),(-1,-1),0.4,_MGRAY),("FONTNAME",(0,0),(0,-1),"Helvetica-Bold"),("FONTSIZE",(0,0),(-1,-1),9),("PADDING",(0,0),(-1,-1),5)]))
        story.append(st2)
    else:
        story.append(Paragraph(f"TLS unavailable: {ssl.get('error','Unknown')}",S["body"]))
    story.append(Spacer(1,10))
    # Summary
    story.append(Paragraph("Executive Summary",S["h2"])); story.append(HRFlowable(width="100%",thickness=0.5,color=_MGRAY,spaceAfter=5))
    for pt in scan["summary"]: story.append(Paragraph(f"• {pt}",S["bullet"]))
    story.append(Spacer(1,10))
    # Findings table
    story.append(Paragraph("Detailed Findings",S["h2"])); story.append(HRFlowable(width="100%",thickness=0.5,color=_MGRAY,spaceAfter=5))
    rows = [[Paragraph(f"<b>{h}</b>",S["tiny"]) for h in ["Finding","Category","Severity","Status","Recommendation"]]]
    for f in scan["findings"]:
        sc2 = _sev_color(f["severity"])
        rows.append([
            Paragraph(f["name"],S["tiny"]),
            Paragraph(f["category"],S["tiny"]),
            Paragraph(f'<font color="{sc2.hexval()}"><b>{f["severity"]}</b></font>',S["tiny"]),
            Paragraph(f'<font color="{"#22c55e" if f["present"] else "#ef4444"}">{"✓" if f["present"] else "✗"}</font>',S["tiny"]),
            Paragraph(f["recommendation"],S["tiny"]),
        ])
    ft = Table(rows,colWidths=[40*mm,28*mm,17*mm,12*mm,None])
    ft.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),_DARK),("TEXTCOLOR",(0,0),(-1,0),_WHITE),("ROWBACKGROUNDS",(0,1),(-1,-1),[_WHITE,_LGRAY]),("GRID",(0,0),(-1,-1),0.3,_MGRAY),("FONTSIZE",(0,0),(-1,-1),8),("PADDING",(0,0),(-1,-1),5),("VALIGN",(0,0),(-1,-1),"TOP")]))
    story.append(ft); story.append(Spacer(1,12))
    # Disclaimer
    disc = Table([[Paragraph("SCOPE NOTICE: Passive, defensive checks only. Authorized use only. CyberGuard performs no offensive, intrusive, or exploitative testing.",S["tiny"])]],colWidths=[doc.width])
    disc.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,-1),_LGRAY),("PADDING",(0,0),(-1,-1),10)]))
    story.append(disc)
    doc.build(story,onFirstPage=cb,onLaterPages=cb)
    pdf = buf.getvalue(); buf.close(); return pdf

# ============================================================
# APP STATE
# ============================================================
_db_init()
if "user"      not in st.session_state: st.session_state.user      = None
if "last_scan" not in st.session_state: st.session_state.last_scan = None

# ============================================================
# ── AUTH SCREEN ──────────────────────────────────────────────
# ============================================================
if st.session_state.user is None:
    st.markdown('<div class="cg-auth-wrap">', unsafe_allow_html=True)
    st.markdown('<div class="cg-auth-logo">Cyber<span>Guard</span></div><div class="cg-auth-tagline">Professional website security reviews for modern teams</div>', unsafe_allow_html=True)

    tab_login, tab_signup = st.tabs(["Sign In", "Create Account"])
    with tab_login:
        st.markdown('<div class="cg-auth-card"><div class="cg-auth-title">Welcome back</div>', unsafe_allow_html=True)
        em = st.text_input("Email address", key="li_email", placeholder="you@company.com")
        pw = st.text_input("Password", type="password", key="li_pass", placeholder="••••••••")
        st.write("")
        if st.button("Sign In →", use_container_width=True, key="btn_login"):
            if not em or not pw:
                st.error("Please enter email and password.")
            else:
                ok, user = authenticate_user(em, pw)
                if ok:
                    st.session_state.user = user; st.rerun()
                else:
                    st.error("Invalid email or password.")
        st.markdown('</div>', unsafe_allow_html=True)

    with tab_signup:
        st.markdown('<div class="cg-auth-card"><div class="cg-auth-title">Create your account</div>', unsafe_allow_html=True)
        nm = st.text_input("Full Name",    key="su_name",  placeholder="Alex Johnson")
        em2= st.text_input("Work Email",   key="su_email", placeholder="alex@company.com")
        pw2= st.text_input("Password (min 8 chars)", type="password", key="su_pass", placeholder="••••••••")
        st.write("")
        if st.button("Create Account →", use_container_width=True, key="btn_signup"):
            if not nm or not em2 or not pw2:
                st.error("Please complete all fields.")
            elif len(pw2) < 8:
                st.error("Password must be at least 8 characters.")
            else:
                ok, msg = create_user(nm, em2, pw2)
                st.success(msg + "  Switch to Sign In.") if ok else st.error(msg)
        st.markdown('</div>', unsafe_allow_html=True)

    st.markdown('</div>', unsafe_allow_html=True)
    st.stop()

# ============================================================
# ── MAIN APP ─────────────────────────────────────────────────
# ============================================================
user = st.session_state.user

# Sidebar
with st.sidebar:
    st.markdown(f"### {user['name']}")
    st.caption(user["email"])
    st.divider()
    st.info("Only scan websites you own or have explicit permission to assess.")
    if st.button("🚪  Log Out", use_container_width=True):
        st.session_state.user = None; st.session_state.last_scan = None; st.rerun()

# Navbar
st.markdown(f"""
<div class="cg-navbar">
    <div style="display:flex;align-items:center;gap:1rem;">
        <span class="cg-logo">Cyber<span>Guard</span></span>
        <span class="cg-badge">🛡 Defensive Analysis</span>
    </div>
    <div class="cg-user-pill">👤 &nbsp;{user['name']}</div>
</div>
""", unsafe_allow_html=True)

# Hero
st.markdown("""
<div class="cg-hero">
    <div class="cg-eyebrow">Security Review Platform</div>
    <div class="cg-headline">Website security<br>reviewed in <em>seconds.</em></div>
    <div class="cg-desc">Run a comprehensive defensive assessment — SSL, headers, cookies, information disclosure — then export a polished client-ready PDF report.</div>
</div>
""", unsafe_allow_html=True)

# Scan input
st.markdown('<div class="cg-scan-box">', unsafe_allow_html=True)
c1, c2, c3 = st.columns([3, 2, 1])
with c1:
    st.markdown('<div class="cg-scan-label">Target website URL</div>', unsafe_allow_html=True)
    target_url = st.text_input("URL", label_visibility="collapsed", placeholder="https://example.com", key="url_input")
with c2:
    st.markdown('<div class="cg-scan-label">Client / Company Name</div>', unsafe_allow_html=True)
    client_name = st.text_input("Client", label_visibility="collapsed", placeholder="Nexora Commerce Ltd", key="client_input")
with c3:
    st.markdown('<div class="cg-scan-label">&nbsp;</div>', unsafe_allow_html=True)
    scan_clicked = st.button("Run Scan →", use_container_width=True, key="btn_scan")
st.markdown('</div>', unsafe_allow_html=True)

# Run scan
if scan_clicked:
    if not target_url:
        st.error("Please enter a website URL.")
    else:
        try:
            with st.spinner("🔍  Running defensive security checks…"):
                st.session_state.last_scan = run_scan(target_url)
            st.success("✅  Scan completed successfully.")
        except requests.exceptions.SSLError:
            st.error("SSL error. Verify the target supports HTTPS.")
        except requests.exceptions.ConnectionError:
            st.error("Cannot reach target. Check the URL and try again.")
        except requests.exceptions.Timeout:
            st.error("Target timed out.")
        except Exception as exc:
            st.error(f"Error: {exc}")

# ── Results ───────────────────────────────────────────────────
scan = st.session_state.last_scan
if scan:
    ssl_info = scan["ssl_info"]
    rc_map = {"Strong":"rating-strong","Moderate":"rating-moderate","Needs Improvement":"rating-needs","High Risk":"rating-high"}
    rc = rc_map.get(scan["rating"],"")
    ssl_days = ssl_info.get("days_remaining")

    # Metrics
    st.markdown(f"""
    <div class="cg-metrics">
        <div class="cg-metric">
            <div class="cg-metric-label">Security Score</div>
            <div class="cg-score-ring">
                <span class="cg-score-big {rc}">{scan['score']}</span>
                <span class="cg-score-denom">/100</span>
            </div>
            <div class="cg-metric-sub">{scan['rating']}</div>
        </div>
        <div class="cg-metric">
            <div class="cg-metric-label">TLS / SSL</div>
            <div class="cg-metric-value" style="color:{'var(--green)' if ssl_info.get('enabled') else 'var(--red)'}">
                {"✓ Active" if ssl_info.get('enabled') else "✗ None"}
            </div>
            <div class="cg-metric-sub">{f"{ssl_days} days remaining" if ssl_days is not None else "TLS enabled"}</div>
        </div>
        <div class="cg-metric">
            <div class="cg-metric-label">HTTP Status</div>
            <div class="cg-metric-value">{scan['status_code']}</div>
            <div class="cg-metric-sub">Final response code</div>
        </div>
        <div class="cg-metric">
            <div class="cg-metric-label">Checks Run</div>
            <div class="cg-metric-value">{len(scan['findings'])}</div>
            <div class="cg-metric-sub">{sum(1 for f in scan['findings'] if not f['present'])} issues found</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # Summary + TLS
    col_l, col_r = st.columns([1.3, 0.7], gap="medium")
    with col_l:
        st.markdown('<div class="cg-section"><div class="cg-section-head">Executive Summary</div><div class="cg-section-sub">Key observations from this security review</div><div class="cg-card">', unsafe_allow_html=True)
        for pt in scan["summary"]:
            st.markdown(f'<div class="cg-summary-bullet"><span>◈</span><span>{pt}</span></div>', unsafe_allow_html=True)
        st.markdown(f'<hr class="cg-divider"><div style="font-size:0.83rem;color:var(--muted);line-height:1.8;"><b style="color:var(--subtle)">Input URL</b><br>{scan["input_url"]}<br><b style="color:var(--subtle)">Final URL</b><br>{scan["final_url"]}<br><b style="color:var(--subtle)">Scanned</b><br>{scan["scanned_at"]}</div>', unsafe_allow_html=True)
        st.markdown('</div></div>', unsafe_allow_html=True)

    with col_r:
        st.markdown('<div class="cg-section"><div class="cg-section-head">TLS Certificate</div><div class="cg-section-sub">SSL/TLS inspection results</div><div class="cg-card">', unsafe_allow_html=True)
        if ssl_info.get("enabled"):
            days = ssl_info.get("days_remaining", 0)
            dc = "var(--green)" if days > 45 else "var(--amber)" if days > 15 else "var(--red)"
            st.markdown(f'<div style="margin-bottom:1rem"><span style="font-family:var(--font-head);font-size:2rem;font-weight:700;color:{dc}">{days}</span><span style="color:var(--muted);font-size:0.85rem;"> days remaining</span></div><div style="font-size:0.85rem;color:var(--subtle);line-height:2.1;"><b style="color:var(--text)">Issuer</b><br><span style="color:var(--muted)">{ssl_info.get("issuer","—")}</span><br><b style="color:var(--text)">Subject</b><br><span style="color:var(--muted)">{ssl_info.get("subject","—")}</span><br><b style="color:var(--text)">Valid To</b><br><span style="color:var(--muted)">{ssl_info.get("valid_to","—")}</span></div>', unsafe_allow_html=True)
        else:
            st.markdown(f'<div style="color:var(--red);font-size:2rem">✗</div><div style="color:var(--muted);font-size:0.88rem">TLS unavailable<br>{ssl_info.get("error","")}</div>', unsafe_allow_html=True)
        st.markdown('</div></div>', unsafe_allow_html=True)

    # Findings
    st.markdown('<div class="cg-section"><div class="cg-section-head">Detailed Findings</div><div class="cg-section-sub">Expand each category for details and remediation guidance</div>', unsafe_allow_html=True)
    categories = {}
    for f in scan["findings"]:
        categories.setdefault(f["category"], []).append(f)

    tag_cls = {"High":"cg-tag-high","Medium":"cg-tag-medium","Low":"cg-tag-low","Info":"cg-tag-info"}
    icon_map = lambda f: "✅" if f["present"] else ("🔴" if f["severity"]=="High" else "🟡" if f["severity"]=="Medium" else "🔵")

    for cat, items in categories.items():
        ok_n = sum(1 for f in items if f["present"])
        with st.expander(f"**{cat}** — {ok_n}/{len(items)} passed"):
            for item in items:
                st.markdown(f"""
                <div style="padding:0.6rem 0;border-bottom:1px solid var(--border)">
                    <div style="display:flex;align-items:center;gap:0.5rem;margin-bottom:0.25rem">
                        <span>{icon_map(item)}</span>
                        <span style="font-weight:600;font-size:0.92rem">{item['name']}</span>
                        <span class="cg-tag {tag_cls.get(item['severity'],'cg-tag-info')}">{item['severity']}</span>
                    </div>
                    <div style="font-size:0.82rem;color:var(--muted);margin-bottom:0.25rem">{item['description']}</div>
                    <div style="font-size:0.81rem">
                        <span style="color:var(--subtle)">Value: </span>
                        <code style="background:var(--surface2);padding:2px 6px;border-radius:5px;font-size:0.78rem;color:var(--cyan)">{item['value'] or '—'}</code>
                    </div>
                    <div style="font-size:0.81rem;margin-top:0.2rem">
                        <span style="color:var(--subtle)">Fix: </span>
                        <span style="color:{'var(--green)' if item['present'] else 'var(--amber)'}">{item['recommendation']}</span>
                    </div>
                </div>
                """, unsafe_allow_html=True)
    st.markdown('</div>', unsafe_allow_html=True)

    # Export
    st.markdown('<div class="cg-section"><div class="cg-section-head">Export Report</div><div class="cg-section-sub">Download a professional client-ready PDF</div><div class="cg-card">', unsafe_allow_html=True)
    r1, r2 = st.columns([2, 1])
    with r1:
        st.markdown("""<div style="font-size:0.88rem;color:var(--subtle);line-height:1.9">
            The PDF includes: score card, TLS summary, executive summary,<br>
            full findings table with recommendations, and a scope disclaimer.
        </div>""", unsafe_allow_html=True)
    with r2:
        pdf_bytes = build_pdf(scan, client_name or "Sample Client", user["name"])
        st.download_button("⬇  Download PDF Report", data=pdf_bytes,
            file_name=f"cyberguard_{scan['hostname']}.pdf", mime="application/pdf", use_container_width=True)
        st.caption("For portfolio, internal review, or authorized client delivery.")
    st.markdown('</div></div>', unsafe_allow_html=True)

# Footer
st.markdown("""
<div class="cg-footer">
    <span>CyberGuard v2 · <b>Pamupro Cyber</b></span>
    <span>⚠ Authorized use only — do not scan without permission</span>
</div>
""", unsafe_allow_html=True)
