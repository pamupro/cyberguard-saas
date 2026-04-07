"""CyberGuard - Website Security Review Platform. Single-file Streamlit app."""

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

st.set_page_config(
    page_title="CyberGuard",
    page_icon="shield",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# NOTE: CSS stored as plain ASCII string - no special characters.
_CSS = (
    "<link rel='preconnect' href='https://fonts.googleapis.com'>"
    "<link rel='preconnect' href='https://fonts.gstatic.com' crossorigin>"
    "<link href='https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap' rel='stylesheet'>"
    "<style>"
    ":root{"
    "--bg:#f4f5f7;"
    "--white:#ffffff;"
    "--s1:#f9fafb;"
    "--s2:#f3f4f6;"
    "--s3:#e5e7eb;"
    "--b0:rgba(0,0,0,0.05);"
    "--b1:rgba(0,0,0,0.08);"
    "--b2:rgba(0,0,0,0.12);"
    "--t0:#111827;"
    "--t1:#374151;"
    "--t2:#6b7280;"
    "--t3:#9ca3af;"
    "--t4:#d1d5db;"
    "--acc:#1a56db;"
    "--acc-l:#eff6ff;"
    "--acc-b:#bfdbfe;"
    "--ok:#16a34a;"
    "--ok-l:#f0fdf4;"
    "--ok-b:#bbf7d0;"
    "--warn:#d97706;"
    "--warn-l:#fffbeb;"
    "--warn-b:#fde68a;"
    "--err:#dc2626;"
    "--err-l:#fef2f2;"
    "--err-b:#fecaca;"
    "--inf:#0284c7;"
    "--inf-l:#f0f9ff;"
    "--inf-b:#bae6fd;"
    "--font:'Inter',-apple-system,sans-serif;"
    "--r:8px;--rl:12px;--rxl:16px;"
    "}"
    "*,*::before,*::after{box-sizing:border-box}"
    "html,body,[class*='css']{font-family:var(--font)!important;-webkit-font-smoothing:antialiased}"
    ".stApp{background:var(--bg)!important;color:var(--t0)!important}"
    "#MainMenu,footer,header{visibility:hidden}"
    ".block-container{padding:0!important;max-width:100%!important}"
    "p,span,label,div,li,td,th,small{color:var(--t0)!important;font-family:var(--font)!important}"
    "[data-testid='stSidebar']{background:var(--white)!important;border-right:1px solid var(--b1)!important}"
    "[data-testid='stSidebar'] *{color:var(--t1)!important}"
    "[data-testid='stTextInput'] label{font-size:11px!important;font-weight:600!important;letter-spacing:.04em!important;text-transform:uppercase!important;color:var(--t2)!important;margin-bottom:5px!important;display:block!important}"
    "[data-testid='stTextInput']>div>div{background:var(--white)!important;border:1.5px solid var(--b2)!important;border-radius:var(--r)!important;transition:border-color .15s,box-shadow .15s!important;box-shadow:0 1px 2px rgba(0,0,0,0.04)!important}"
    "[data-testid='stTextInput']>div>div:focus-within{border-color:var(--acc)!important;box-shadow:0 0 0 3px rgba(26,86,219,0.12)!important}"
    "[data-testid='stTextInput'] input{background:transparent!important;border:none!important;outline:none!important;color:var(--t0)!important;font-family:var(--font)!important;font-size:14px!important;padding:10px 12px!important}"
    "[data-testid='stTextInput'] input::placeholder{color:var(--t3)!important}"
    ".stButton>button{background:var(--acc)!important;color:#fff!important;border:none!important;border-radius:var(--r)!important;font-family:var(--font)!important;font-size:13px!important;font-weight:600!important;letter-spacing:-.01em!important;padding:10px 18px!important;cursor:pointer!important;transition:background .15s,transform .1s,box-shadow .15s!important;white-space:nowrap!important;box-shadow:0 1px 3px rgba(26,86,219,0.3)!important}"
    ".stButton>button:hover{background:#1e429f!important;transform:translateY(-1px)!important;box-shadow:0 4px 12px rgba(26,86,219,0.25)!important}"
    "[data-testid='stDownloadButton']>button{background:var(--white)!important;color:var(--t0)!important;border:1.5px solid var(--b2)!important;box-shadow:0 1px 2px rgba(0,0,0,0.04)!important}"
    "[data-testid='stDownloadButton']>button:hover{background:var(--s1)!important;border-color:var(--acc)!important;color:var(--acc)!important}"
    "[data-testid='stTabs'] [role='tablist']{border-bottom:1.5px solid var(--b1)!important;background:transparent!important;gap:0!important}"
    "[data-testid='stTabs'] button[role='tab']{background:transparent!important;border:none!important;border-bottom:2px solid transparent!important;border-radius:0!important;color:var(--t2)!important;font-family:var(--font)!important;font-size:13px!important;font-weight:500!important;padding:10px 18px!important;transition:color .15s!important}"
    "[data-testid='stTabs'] button[role='tab'][aria-selected='true']{color:var(--acc)!important;border-bottom:2px solid var(--acc)!important}"
    "[data-testid='stTabs']>div>div:last-child{padding:20px 0 0!important}"
    "[data-testid='stExpander']{background:var(--white)!important;border:1.5px solid var(--b1)!important;border-radius:var(--rl)!important;overflow:hidden!important;margin-bottom:8px!important;box-shadow:0 1px 3px rgba(0,0,0,0.04)!important}"
    "[data-testid='stExpander']>div:first-child{padding:14px 18px!important}"
    "[data-testid='stExpander'] details[open]>div:first-child{border-bottom:1.5px solid var(--b1)!important}"
    "[data-testid='stExpander'] summary{font-family:var(--font)!important;font-size:13px!important;font-weight:600!important;color:var(--t0)!important}"
    "[data-testid='stExpander']>div:last-child{padding:0 18px 16px!important;background:var(--white)!important}"
    "[data-testid='stAlert']{background:var(--white)!important;border-radius:var(--r)!important;border:1.5px solid var(--b1)!important}"
    "::-webkit-scrollbar{width:5px;height:5px;background:var(--s2)}"
    "::-webkit-scrollbar-thumb{background:var(--s3);border-radius:3px}"

    ".cg-nav{height:58px;padding:0 24px;display:flex;align-items:center;justify-content:space-between;border-bottom:1.5px solid var(--b1);background:var(--white);position:sticky;top:0;z-index:200;box-shadow:0 1px 4px rgba(0,0,0,0.06)}"
    ".cg-brand{display:flex;align-items:center;gap:10px}"
    ".cg-logo{width:32px;height:32px;border-radius:9px;background:var(--acc);display:flex;align-items:center;justify-content:center;font-weight:700;font-size:14px;color:white;flex-shrink:0;box-shadow:0 2px 6px rgba(26,86,219,0.35)}"
    ".cg-brand-name{font-size:15px;font-weight:700;letter-spacing:-.03em;color:var(--t0)}"
    ".cg-brand-tag{font-size:10px;font-weight:600;letter-spacing:.05em;text-transform:uppercase;color:var(--acc);background:var(--acc-l);border:1px solid var(--acc-b);border-radius:5px;padding:2px 8px}"
    ".cg-nav-right{display:flex;align-items:center;gap:8px}"
    ".cg-avatar{width:32px;height:32px;border-radius:50%;background:linear-gradient(135deg,var(--acc),#7c3aed);display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:700;color:white}"
    ".cg-user-name{font-size:13px;font-weight:500;color:var(--t1)}"

    ".cg-layout{display:flex;min-height:calc(100vh - 58px)}"
    ".cg-sidebar{width:220px;flex-shrink:0;background:var(--white);border-right:1.5px solid var(--b1);padding:20px 0}"
    ".cg-main{flex:1;padding:28px 28px 60px;min-width:0}"

    ".cg-sidenav-item{display:flex;align-items:center;gap:10px;padding:9px 20px;font-size:13px;font-weight:500;color:var(--t2);cursor:pointer;transition:all .15s;border-left:3px solid transparent;margin-bottom:1px}"
    ".cg-sidenav-item:hover{background:var(--s1);color:var(--t0)}"
    ".cg-sidenav-item.active{background:var(--acc-l);color:var(--acc);border-left:3px solid var(--acc);font-weight:600}"
    ".cg-sidenav-icon{font-size:15px;opacity:.7;flex-shrink:0}"
    ".cg-sidenav-section{font-size:10px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:var(--t3);padding:16px 20px 6px}"

    ".cg-page-title{font-size:22px;font-weight:700;letter-spacing:-.03em;color:var(--t0);margin:0 0 4px}"
    ".cg-page-sub{font-size:13px;color:var(--t2);margin:0 0 24px}"

    ".cg-scan-card{background:var(--white);border:1.5px solid var(--b1);border-radius:var(--rxl);padding:22px 24px;margin-bottom:24px;box-shadow:0 1px 4px rgba(0,0,0,0.05)}"
    ".cg-scan-card-title{font-size:13px;font-weight:600;color:var(--t0);margin-bottom:16px;display:flex;align-items:center;gap:8px}"
    ".cg-scan-dot{width:8px;height:8px;border-radius:50%;background:var(--ok);box-shadow:0 0 0 2px rgba(22,163,74,.2)}"
    ".cg-field-label{font-size:11px;font-weight:600;letter-spacing:.04em;text-transform:uppercase;color:var(--t2);margin-bottom:6px}"

    ".cg-stats{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:20px}"
    ".cg-stat{background:var(--white);border:1.5px solid var(--b1);border-radius:var(--rl);padding:18px 20px;box-shadow:0 1px 3px rgba(0,0,0,0.04)}"
    ".cg-stat-label{font-size:11px;font-weight:600;letter-spacing:.04em;text-transform:uppercase;color:var(--t2);margin-bottom:10px}"
    ".cg-stat-val{font-size:28px;font-weight:700;letter-spacing:-.04em;line-height:1;color:var(--t0)}"
    ".cg-stat-val.green{color:var(--ok)}"
    ".cg-stat-val.amber{color:var(--warn)}"
    ".cg-stat-val.red{color:var(--err)}"
    ".cg-stat-val.blue{color:var(--acc)}"
    ".cg-stat-sub{font-size:12px;color:var(--t3);margin-top:5px}"
    ".cg-stat-badge{display:inline-flex;align-items:center;gap:4px;font-size:11px;font-weight:600;padding:2px 8px;border-radius:20px;margin-top:6px}"
    ".cg-stat-badge.ok{background:var(--ok-l);color:var(--ok);border:1px solid var(--ok-b)}"
    ".cg-stat-badge.warn{background:var(--warn-l);color:var(--warn);border:1px solid var(--warn-b)}"
    ".cg-stat-badge.err{background:var(--err-l);color:var(--err);border:1px solid var(--err-b)}"
    ".cg-stat-badge.inf{background:var(--inf-l);color:var(--inf);border:1px solid var(--inf-b)}"

    ".cg-grid2{display:grid;grid-template-columns:3fr 2fr;gap:16px;margin-bottom:16px}"
    ".cg-card{background:var(--white);border:1.5px solid var(--b1);border-radius:var(--rl);padding:22px;box-shadow:0 1px 3px rgba(0,0,0,0.04)}"
    ".cg-card-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;padding-bottom:12px;border-bottom:1.5px solid var(--b0)}"
    ".cg-card-title{font-size:12px;font-weight:700;letter-spacing:.04em;text-transform:uppercase;color:var(--t2)}"
    ".cg-card-meta{font-size:11px;color:var(--t3)}"

    ".cg-kv{display:flex;gap:12px;padding:8px 0;border-bottom:1px solid var(--b0);align-items:baseline}"
    ".cg-kv:last-child{border-bottom:none;padding-bottom:0}"
    ".cg-kv-k{font-size:11px;font-weight:600;color:var(--t2);min-width:80px;flex-shrink:0}"
    ".cg-kv-v{font-size:12px;color:var(--t1);word-break:break-all;line-height:1.5}"
    ".cg-kv-v.mono{font-family:'Fira Code','Cascadia Mono',monospace;font-size:11px}"

    ".cg-bullet{display:flex;gap:10px;padding:9px 0;border-bottom:1px solid var(--b0);align-items:flex-start}"
    ".cg-bullet:last-child{border-bottom:none;padding-bottom:2px}"
    ".cg-bullet-icon{width:20px;height:20px;border-radius:6px;background:var(--acc-l);border:1px solid var(--acc-b);display:flex;align-items:center;justify-content:center;flex-shrink:0;font-size:10px;color:var(--acc);margin-top:1px}"
    ".cg-bullet-txt{font-size:13px;color:var(--t1);line-height:1.55}"

    ".cg-tls-days{font-size:42px;font-weight:700;letter-spacing:-.05em;line-height:1;margin-bottom:2px}"
    ".cg-tls-label{font-size:12px;color:var(--t3);margin-bottom:18px}"

    ".cg-section-row{display:flex;align-items:center;justify-content:space-between;margin:24px 0 10px;padding-bottom:10px;border-bottom:1.5px solid var(--b1)}"
    ".cg-section-title{font-size:14px;font-weight:700;color:var(--t0);letter-spacing:-.015em}"
    ".cg-section-meta{font-size:12px;color:var(--t3)}"

    ".cg-finding{padding:12px 0;border-bottom:1px solid var(--b0)}"
    ".cg-finding:last-child{border-bottom:none;padding-bottom:2px}"
    ".cg-finding-top{display:flex;align-items:center;gap:8px;margin-bottom:4px}"
    ".cg-finding-dot{width:7px;height:7px;border-radius:50%;flex-shrink:0}"
    ".cg-finding-name{font-size:13px;font-weight:600;color:var(--t0);flex:1;line-height:1.3}"
    ".cg-finding-desc{font-size:12px;color:var(--t2);margin:0 0 6px 15px;line-height:1.55}"
    ".cg-finding-foot{display:flex;align-items:center;gap:8px;margin-left:15px;flex-wrap:wrap}"
    ".cg-chip{font-family:'Fira Code','Cascadia Mono',monospace;font-size:11px;color:var(--t2);background:var(--s2);border:1px solid var(--b1);padding:2px 8px;border-radius:5px;max-width:320px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}"
    ".cg-rec{font-size:12px;color:var(--t2);line-height:1.4}"

    ".cg-badge{font-size:10px;font-weight:700;letter-spacing:.04em;text-transform:uppercase;padding:2px 8px;border-radius:5px;flex-shrink:0}"
    ".badge-H{background:var(--err-l);color:var(--err);border:1px solid var(--err-b)}"
    ".badge-M{background:var(--warn-l);color:var(--warn);border:1px solid var(--warn-b)}"
    ".badge-L{background:var(--inf-l);color:var(--inf);border:1px solid var(--inf-b)}"
    ".badge-I{background:var(--ok-l);color:var(--ok);border:1px solid var(--ok-b)}"
    ".badge-pass{background:var(--ok-l);color:var(--ok);border:1px solid var(--ok-b)}"
    ".badge-fail{background:var(--err-l);color:var(--err);border:1px solid var(--err-b)}"

    ".cg-score-ring{position:relative;display:inline-flex;align-items:center;justify-content:center;width:80px;height:80px}"
    ".cg-score-num{font-size:22px;font-weight:700;letter-spacing:-.03em;color:var(--t0)}"
    ".cg-progress-wrap{background:var(--s2);border-radius:999px;height:6px;overflow:hidden;margin:8px 0 4px}"
    ".cg-progress-bar{height:100%;border-radius:999px;transition:width .5s ease}"

    ".cg-table{width:100%;border-collapse:collapse;font-size:12px}"
    ".cg-table th{text-align:left;font-size:11px;font-weight:700;letter-spacing:.04em;text-transform:uppercase;color:var(--t2);padding:10px 12px;border-bottom:1.5px solid var(--b1);background:var(--s1)}"
    ".cg-table td{padding:10px 12px;border-bottom:1px solid var(--b0);color:var(--t1);vertical-align:top}"
    ".cg-table tr:last-child td{border-bottom:none}"
    ".cg-table tr:hover td{background:var(--s1)}"

    ".cg-auth-bg{min-height:100vh;background:var(--bg);display:flex;flex-direction:column;align-items:center;justify-content:center;padding:24px}"
    ".cg-auth-card{background:var(--white);border:1.5px solid var(--b1);border-radius:var(--rxl);padding:28px;width:100%;max-width:400px;box-shadow:0 4px 24px rgba(0,0,0,0.08)}"

    ".cg-footer{border-top:1.5px solid var(--b1);padding:14px 24px;display:flex;align-items:center;justify-content:space-between;background:var(--white)}"
    ".cg-footer-txt{font-size:11px;color:var(--t3)}"
    "</style>"
)
st.markdown(_CSS, unsafe_allow_html=True)

# =============================================================
# AUTH (stdlib only)
# =============================================================
DB_FILE = "cyberguard.db"

def _db_init():
    with closing(sqlite3.connect(DB_FILE)) as c:
        c.execute("""CREATE TABLE IF NOT EXISTS users(
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
            c.execute("INSERT INTO users(name,email,password_hash,created_at)VALUES(?,?,?,?)",
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

# =============================================================
# SCANNER
# =============================================================
_UA = "CyberGuard/2.0 (authorized defensive review)"
_HDRS = {
    "Strict-Transport-Security": {"w":14,"sev":"High",
        "desc":"Forces browsers to use HTTPS for all future requests, preventing protocol downgrade attacks.",
        "fix":"Strict-Transport-Security: max-age=31536000; includeSubDomains"},
    "Content-Security-Policy": {"w":16,"sev":"High",
        "desc":"Controls which resources the browser may load, significantly reducing XSS attack surface.",
        "fix":"Define a restrictive CSP policy tailored to your application requirements."},
    "X-Frame-Options": {"w":8,"sev":"Medium",
        "desc":"Prevents the page from being embedded in iframes, blocking clickjacking attacks.",
        "fix":"X-Frame-Options: DENY"},
    "X-Content-Type-Options": {"w":8,"sev":"Medium",
        "desc":"Prevents MIME-sniffing attacks by locking down content-type handling.",
        "fix":"X-Content-Type-Options: nosniff"},
    "Referrer-Policy": {"w":6,"sev":"Low",
        "desc":"Controls how much referrer information is passed to other origins when navigating.",
        "fix":"Referrer-Policy: strict-origin-when-cross-origin"},
    "Permissions-Policy": {"w":6,"sev":"Low",
        "desc":"Restricts which browser APIs and device features this page is permitted to access.",
        "fix":"Define a Permissions-Policy covering camera, microphone, geolocation, etc."},
}
_OPT = ["Cross-Origin-Opener-Policy","Cross-Origin-Resource-Policy","Cross-Origin-Embedder-Policy"]
_PATHS = ["/robots.txt","/security.txt","/.well-known/security.txt","/sitemap.xml"]

def _norm(u):
    u = u.strip()
    return ("https://"+u) if u and not u.startswith(("http://","https://")) else u

def _host(u): return urlparse(u).hostname or ""

def _fetch(u):
    return requests.get(u, timeout=10, headers={"User-Agent":_UA}, allow_redirects=True)

def _ssl_check(host, port=443):
    r = {"enabled":False,"issuer":None,"subject":None,"valid_to":None,"days_remaining":None,"error":None}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host,port),timeout=6) as sock:
            with ctx.wrap_socket(sock,server_hostname=host) as ss:
                cert = ss.getpeercert()
        r["enabled"] = True
        iss = dict(x[0] for x in cert.get("issuer",[]))
        sub = dict(x[0] for x in cert.get("subject",[]))
        r["issuer"] = iss.get("organizationName") or str(iss)
        r["subject"] = sub.get("commonName") or str(sub)
        vt = datetime.strptime(cert["notAfter"],"%b %d %H:%M:%S %Y %Z")
        r["valid_to"] = vt.strftime("%d %b %Y")
        r["days_remaining"] = (vt.replace(tzinfo=timezone.utc)-datetime.now(timezone.utc)).days
    except Exception as e:
        r["error"] = str(e)
    return r

def _proto(iu, fu):
    return [
        {"cat":"Protocol","name":"HTTPS on input URL","ok":iu.startswith("https://"),
         "sev":"High","w":14,"val":iu,"desc":"Verifies the target URL uses HTTPS from the start.","fix":"Ensure all traffic begins on https://."},
        {"cat":"Protocol","name":"HTTPS on final URL","ok":fu.startswith("https://"),
         "sev":"High","w":14,"val":fu,"desc":"Verifies the final page after redirects uses HTTPS.","fix":"Issue a 301 redirect from HTTP to HTTPS."},
    ]

def _headers(resp):
    out = []
    for h, m in _HDRS.items():
        p = h in resp.headers
        out.append({"cat":"Security Headers","name":h,"ok":p,"sev":"Info" if p else m["sev"],"w":m["w"],
            "val":resp.headers.get(h,"Not set"),"desc":m["desc"],"fix":"Configured correctly." if p else m["fix"]})
    for h in _OPT:
        p = h in resp.headers
        out.append({"cat":"Security Headers","name":h,"ok":p,"sev":"Info" if p else "Low","w":3,
            "val":resp.headers.get(h,"Not set"),"desc":"Cross-origin isolation header for defence-in-depth.","fix":"Configured." if p else f"Consider adding {h}."})
    return out

def _cookies(resp):
    raw = resp.raw.headers.get_all("Set-Cookie") if hasattr(resp.raw.headers,"get_all") else []
    if not raw:
        return [{"cat":"Cookies","name":"Set-Cookie presence","ok":True,"sev":"Info","w":0,
                 "val":"None observed","desc":"No cookies were issued in this response.","fix":"No action required."}]
    out = []
    for i, c in enumerate(raw, 1):
        low = c.lower()
        miss = [f for f,k in [("Secure","secure"),("HttpOnly","httponly"),("SameSite","samesite")] if k not in low]
        out.append({"cat":"Cookies","name":f"Cookie #{i}","ok":not miss,"sev":"Info" if not miss else "Medium","w":8,
            "val":c[:90]+("..." if len(c)>90 else ""),"desc":"Cookie security attributes protect against interception and forgery.",
            "fix":"All attributes present." if not miss else f"Missing: {', '.join(miss)}."})
    return out

def _disclosure(resp):
    out = []
    for h, lbl in [("Server","Server header"),("X-Powered-By","X-Powered-By header")]:
        val = resp.headers.get(h)
        out.append({"cat":"Info Disclosure","name":lbl,"ok":not bool(val),"sev":"Info" if not val else "Low","w":5,
            "val":val or "Not present","desc":"Exposing server/framework versions helps attackers find CVEs.",
            "fix":"Not exposed." if not val else f"Remove the {h} response header."})
    return out

def _paths(base):
    sess = requests.Session()
    out = []
    for p in _PATHS:
        url = urljoin(base,p)
        try:
            r = sess.get(url,timeout=5,headers={"User-Agent":_UA},allow_redirects=True)
            ok = r.status_code == 200
            out.append({"cat":"Security Files","name":p,"ok":ok,"sev":"Info" if ok else "Low","w":3,
                "val":f"HTTP {r.status_code}","desc":"Standard file that aids security researchers.","fix":"Accessible." if ok else f"Consider publishing {p}."})
        except Exception:
            out.append({"cat":"Security Files","name":p,"ok":False,"sev":"Low","w":3,
                "val":"Unreachable","desc":"Standard security disclosure file.","fix":f"Consider publishing {p}."})
    return out

def _score(findings, ssl_info):
    mp = sum(f["w"] for f in findings if f["w"]>0)+10
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
    if hi: pts.append(f"Critical gaps found: {', '.join(hi[:3])}.")
    if md: pts.append(f"Medium-severity issues: {', '.join(md[:3])}.")
    d = ssl_info.get("days_remaining")
    if ssl_info.get("enabled") and d is not None and d<30:
        pts.append(f"TLS certificate expires in {d} days - renewal required.")
    if not pts: pts.append("No critical security configuration issues were identified.")
    return pts

def run_scan(url):
    t = _norm(url); resp = _fetch(t); h = _host(t)
    ssl_info = _ssl_check(h) if h else {"enabled":False,"error":"No hostname"}
    findings = _proto(t,resp.url)+_headers(resp)+_cookies(resp)+_disclosure(resp)+_paths(resp.url)
    score, rating = _score(findings,ssl_info)
    return {"input_url":t,"final_url":resp.url,"hostname":h,"status_code":resp.status_code,
            "ssl_info":ssl_info,"findings":findings,"score":score,"rating":rating,
            "summary":_summary(findings,ssl_info),"scanned_at":datetime.utcnow().strftime("%d %b %Y, %H:%M UTC")}

# =============================================================
# PDF
# =============================================================
PC = {
    "navy":  colors.HexColor("#0f172a"), "blue":  colors.HexColor("#1a56db"),
    "text":  colors.HexColor("#1f2937"), "muted": colors.HexColor("#6b7280"),
    "sub":   colors.HexColor("#9ca3af"), "bdr":   colors.HexColor("#e5e7eb"),
    "bg":    colors.HexColor("#ffffff"), "bg1":   colors.HexColor("#f9fafb"),
    "bg2":   colors.HexColor("#f3f4f6"), "green": colors.HexColor("#16a34a"),
    "amber": colors.HexColor("#d97706"), "red":   colors.HexColor("#dc2626"),
    "white": colors.HexColor("#ffffff"),
}

def _ps(n, sz, col, bold=False, lead=None, sb=0, sa=4, indent=0):
    return ParagraphStyle(n, fontSize=sz, textColor=col,
        fontName="Helvetica-Bold" if bold else "Helvetica",
        leading=lead or round(sz*1.5), spaceBefore=sb, spaceAfter=sa, leftIndent=indent)

def _sev_c(s): return {"High":PC["red"],"Medium":PC["amber"],"Low":PC["blue"],"Info":PC["green"]}.get(s,PC["muted"])
def _rat_c(r): return {"Strong":PC["green"],"Moderate":PC["amber"],"Needs Improvement":PC["amber"],"High Risk":PC["red"]}.get(r,PC["muted"])

class _HF:
    def __init__(self, co, an, dt): self.co=co; self.an=an; self.dt=dt
    def __call__(self, cv, doc):
        W,H = A4; cv.saveState()
        cv.setFillColor(PC["navy"]); cv.rect(0,H-50,W,50,fill=1,stroke=0)
        cv.setFillColor(PC["blue"]); cv.rect(0,H-50,4,50,fill=1,stroke=0)
        cv.setFont("Helvetica-Bold",13); cv.setFillColor(PC["white"]); cv.drawString(12*mm,H-22,"CyberGuard")
        cv.setFont("Helvetica",8); cv.setFillColor(colors.HexColor("#9ca3af"))
        cv.drawString(12*mm,H-35,"Security Review Platform")
        cv.drawRightString(W-12*mm,H-22,self.co); cv.drawRightString(W-12*mm,H-35,self.dt)
        cv.setFillColor(PC["bg2"]); cv.rect(0,0,W,26,fill=1,stroke=0)
        cv.setStrokeColor(PC["bdr"]); cv.setLineWidth(0.5); cv.line(0,26,W,26)
        cv.setFont("Helvetica",7); cv.setFillColor(PC["sub"])
        cv.drawString(12*mm,9,f"Analyst: {self.an}  |  Confidential - Authorised Review Only")
        cv.drawRightString(W-12*mm,9,f"Page {doc.page}")
        cv.restoreState()

def build_pdf(scan, company, analyst):
    buf = io.BytesIO()
    W,H = A4; LM=RM=13*mm; TM=58; BM=34; CW=W-LM-RM
    doc = BaseDocTemplate(buf,pagesize=A4,leftMargin=LM,rightMargin=RM,topMargin=TM,bottomMargin=BM)
    frame = Frame(LM,BM,CW,H-TM-BM,id="body")
    doc.addPageTemplates([PageTemplate(id="main",frames=[frame],onPage=_HF(company,analyst,scan["scanned_at"]))])
    S = {
        "h1":  _ps("h1",20,PC["navy"],bold=True,lead=24,sa=6),
        "h2":  _ps("h2",11,PC["navy"],bold=True,lead=15,sb=18,sa=6),
        "h3":  _ps("h3", 9,PC["muted"],bold=True,lead=13,sa=3),
        "body":_ps("b",  9,PC["text"],lead=14,sa=3),
        "sm":  _ps("sm",8.5,PC["text"],lead=13,sa=2),
        "mu":  _ps("mu", 8,PC["muted"],lead=12,sa=2),
        "disc":_ps("dc",7.5,PC["muted"],lead=11,sa=0),
    }
    def hline(): return HRFlowable(width="100%",thickness=0.5,color=PC["bdr"],spaceAfter=8)
    def kv(rows, kw=36*mm):
        data = [[Paragraph(k,S["h3"]),Paragraph(v,S["sm"])] for k,v in rows]
        t = Table(data,colWidths=[kw,CW-kw])
        t.setStyle(TableStyle([
            ("FONTSIZE",(0,0),(-1,-1),8.5),("LEADING",(0,0),(-1,-1),12),
            ("TOPPADDING",(0,0),(-1,-1),6),("BOTTOMPADDING",(0,0),(-1,-1),6),
            ("LEFTPADDING",(0,0),(-1,-1),8),("RIGHTPADDING",(0,0),(-1,-1),8),
            ("BACKGROUND",(0,0),(0,-1),PC["bg2"]),("BACKGROUND",(1,0),(1,-1),PC["bg"]),
            ("TEXTCOLOR",(0,0),(0,-1),PC["muted"]),("TEXTCOLOR",(1,0),(1,-1),PC["text"]),
            ("FONTNAME",(0,0),(0,-1),"Helvetica-Bold"),("LINEBELOW",(0,0),(-1,-1),0.5,PC["bdr"]),
        ]))
        return t
    story = []
    rc = _rat_c(scan["rating"])
    sc_badge = Table([[Paragraph(f'<font size="26" color="{rc.hexval()}"><b>{scan["score"]}</b></font><font size="10" color="#9ca3af"> / 100</font>',S["body"])],
        [Paragraph(f'<font color="{rc.hexval()}"><b>{scan["rating"]}</b></font>',S["mu"])]],colWidths=[52*mm])
    sc_badge.setStyle(TableStyle([("ALIGN",(0,0),(-1,-1),"RIGHT"),("PADDING",(0,0),(-1,-1),0),("VALIGN",(0,0),(-1,-1),"BOTTOM")]))
    title = Table([[Paragraph("Website Security Review Report",S["h1"]),sc_badge]],colWidths=[CW-56*mm,56*mm])
    title.setStyle(TableStyle([("VALIGN",(0,0),(-1,-1),"BOTTOM"),("PADDING",(0,0),(-1,-1),0),
        ("LINEBELOW",(0,0),(-1,0),1,PC["navy"]),("BOTTOMPADDING",(0,0),(-1,0),14)]))
    story += [title,Spacer(1,14)]
    story.append(kv([("Client",company),("Target",scan["input_url"]),("Final URL",scan["final_url"]),
        ("Analyst",analyst),("Reviewed",scan["scanned_at"]),("HTTP Status",str(scan["status_code"]))]))
    story.append(Spacer(1,4))
    ssl = scan["ssl_info"]; d = ssl.get("days_remaining",0) or 0
    dc = PC["green"] if d>45 else PC["amber"] if d>15 else PC["red"]
    story += [Paragraph("Assessment Overview",S["h2"]),hline()]
    def ov_cell(lbl,val,col,sub=""):
        rows = [[Paragraph(f'<font size="7" color="#6b7280"><b>{lbl}</b></font>',S["mu"])],
                [Paragraph(f'<font size="16" color="{col.hexval()}"><b>{val}</b></font>',S["body"])]]
        if sub: rows.append([Paragraph(f'<font size="7" color="#9ca3af">{sub}</font>',S["mu"])])
        t = Table(rows,colWidths=[(CW-3*mm)/4])
        t.setStyle(TableStyle([("ALIGN",(0,0),(-1,-1),"CENTER"),("PADDING",(0,0),(-1,-1),10),("VALIGN",(0,0),(-1,-1),"MIDDLE")]))
        return t
    ssl_val = "Active" if ssl.get("enabled") else "None"
    ssl_col = PC["green"] if ssl.get("enabled") else PC["red"]
    issues = sum(1 for f in scan["findings"] if not f["ok"])
    ov = Table([[ov_cell("SCORE",f'{scan["score"]}/100',rc,scan["rating"]),
        ov_cell("TLS",ssl_val,ssl_col,f'{d} days' if ssl.get("enabled") else ""),
        ov_cell("HTTP",str(scan["status_code"]),PC["blue"],"Response code"),
        ov_cell("ISSUES",str(issues),PC["amber"] if issues>0 else PC["green"],f'of {len(scan["findings"])} checks')]],
        colWidths=[(CW-3*mm)/4]*4)
    ov.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,-1),PC["bg1"]),("BOX",(0,0),(-1,-1),0.5,PC["bdr"]),
        ("LINEBEFORE",(1,0),(3,0),0.5,PC["bdr"]),("PADDING",(0,0),(-1,-1),0),("VALIGN",(0,0),(-1,-1),"MIDDLE")]))
    story += [ov,Spacer(1,4)]
    story += [Paragraph("TLS / SSL Certificate",S["h2"]),hline()]
    if ssl.get("enabled"):
        story.append(kv([("Issuer",ssl.get("issuer","-")),("Subject",ssl.get("subject","-")),
            ("Valid To",ssl.get("valid_to","-")),("Days Left",f'<font color="{dc.hexval()}"><b>{d}</b></font>')]))
    else:
        story.append(Paragraph(f"TLS unavailable: {ssl.get('error','unknown')}",S["mu"]))
    story.append(Spacer(1,4))
    story += [Paragraph("Executive Summary",S["h2"]),hline()]
    for pt in scan["summary"]:
        story.append(Paragraph(f"- {pt}",_ps("bp",9,PC["text"],lead=14,sa=3,indent=8)))
    story.append(Spacer(1,4))
    story += [Paragraph("Detailed Findings",S["h2"]),hline()]
    cws = [38*mm,26*mm,16*mm,13*mm,CW-38*mm-26*mm-16*mm-13*mm]
    hdr = [Paragraph(f"<b>{t}</b>",S["h3"]) for t in ["Finding","Category","Severity","Result","Recommendation"]]
    rows = [hdr]
    for f in scan["findings"]:
        sc2 = _sev_c(f["sev"]); pc = PC["green"] if f["ok"] else PC["red"]
        rows.append([Paragraph(f["name"],S["sm"]),Paragraph(f["cat"],S["sm"]),
            Paragraph(f'<font color="{sc2.hexval()}"><b>{f["sev"]}</b></font>',S["sm"]),
            Paragraph(f'<font color="{pc.hexval()}"><b>{"Pass" if f["ok"] else "Fail"}</b></font>',S["sm"]),
            Paragraph(f["fix"],S["sm"])])
    ft = Table(rows,colWidths=cws,repeatRows=1)
    ft.setStyle(TableStyle([
        ("FONTSIZE",(0,0),(-1,-1),8),("LEADING",(0,0),(-1,-1),12),
        ("TOPPADDING",(0,0),(-1,-1),6),("BOTTOMPADDING",(0,0),(-1,-1),6),
        ("LEFTPADDING",(0,0),(-1,-1),7),("RIGHTPADDING",(0,0),(-1,-1),7),
        ("VALIGN",(0,0),(-1,-1),"TOP"),
        ("BACKGROUND",(0,0),(-1,0),PC["navy"]),("TEXTCOLOR",(0,0),(-1,0),PC["white"]),
        ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),
        ("ROWBACKGROUNDS",(0,1),(-1,-1),[PC["bg"],PC["bg1"]]),
        ("LINEBELOW",(0,0),(-1,-1),0.4,PC["bdr"]),("BOX",(0,0),(-1,-1),0.5,PC["bdr"]),
    ]))
    story.append(ft); story.append(Spacer(1,18))
    disc = Table([[Paragraph("<b>Scope Notice</b> - Passive, defensive analysis only. No offensive testing performed. For authorised assessment and security awareness.",_ps("di",8,PC["muted"],lead=12))]],colWidths=[CW])
    disc.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,-1),PC["bg2"]),("LINEABOVE",(0,0),(-1,0),2,PC["blue"]),
        ("TOPPADDING",(0,0),(-1,-1),10),("BOTTOMPADDING",(0,0),(-1,-1),10),
        ("LEFTPADDING",(0,0),(-1,-1),12),("RIGHTPADDING",(0,0),(-1,-1),12)]))
    story.append(disc)
    doc.build(story); pdf = buf.getvalue(); buf.close(); return pdf

# =============================================================
# STATE
# =============================================================
_db_init()
if "user"      not in st.session_state: st.session_state.user      = None
if "last_scan" not in st.session_state: st.session_state.last_scan = None
if "active_tab" not in st.session_state: st.session_state.active_tab = "scanner"

# =============================================================
# AUTH
# =============================================================
if st.session_state.user is None:
    _, col, _ = st.columns([1, 1.1, 1])
    with col:
        st.markdown('<div style="height:60px"></div>', unsafe_allow_html=True)
        # Brand
        st.markdown("""
        <div style="text-align:center;margin-bottom:28px">
          <div style="display:inline-flex;align-items:center;justify-content:center;width:44px;height:44px;border-radius:12px;background:#1a56db;margin-bottom:12px;box-shadow:0 4px 12px rgba(26,86,219,0.3)">
            <span style="color:white;font-size:20px;font-weight:700">C</span>
          </div>
          <div style="font-size:20px;font-weight:700;letter-spacing:-.03em;color:#111827;margin-bottom:4px">CyberGuard</div>
          <div style="font-size:13px;color:#6b7280">Professional website security reviews</div>
        </div>
        """, unsafe_allow_html=True)

        st.markdown('<div class="cg-auth-card">', unsafe_allow_html=True)
        tab_in, tab_up = st.tabs(["Sign in", "Create account"])
        with tab_in:
            st.markdown('<div style="height:4px"></div>', unsafe_allow_html=True)
            em  = st.text_input("Email address", key="li_em", placeholder="you@company.com")
            pw  = st.text_input("Password", type="password", key="li_pw", placeholder="Enter password")
            st.markdown('<div style="height:4px"></div>', unsafe_allow_html=True)
            if st.button("Sign in", use_container_width=True, key="btn_li"):
                if not em or not pw: st.error("Please enter email and password.")
                else:
                    ok, user = authenticate_user(em, pw)
                    if ok: st.session_state.user = user; st.rerun()
                    else: st.error("Incorrect email or password.")
        with tab_up:
            st.markdown('<div style="height:4px"></div>', unsafe_allow_html=True)
            nm  = st.text_input("Full name",  key="su_nm", placeholder="Alex Johnson")
            em2 = st.text_input("Work email", key="su_em", placeholder="alex@company.com")
            pw2 = st.text_input("Password",   key="su_pw", placeholder="Minimum 8 characters", type="password")
            st.markdown('<div style="height:4px"></div>', unsafe_allow_html=True)
            if st.button("Create account", use_container_width=True, key="btn_su"):
                if not nm or not em2 or not pw2: st.error("All fields required.")
                elif len(pw2) < 8: st.error("Password must be at least 8 characters.")
                else:
                    ok, msg = create_user(nm, em2, pw2)
                    if ok: st.success(msg + " You can now sign in.")
                    else: st.error(msg)
        st.markdown('</div>', unsafe_allow_html=True)
        st.markdown('<p style="text-align:center;font-size:11px;color:#9ca3af;margin-top:14px">Authorised use only. Do not scan without permission.</p>', unsafe_allow_html=True)
    st.stop()

# =============================================================
# MAIN APP
# =============================================================
user = st.session_state.user
initials = "".join(w[0].upper() for w in user["name"].split()[:2])

# TOP NAV
st.markdown(f"""
<div class="cg-nav">
  <div class="cg-brand">
    <div class="cg-logo">C</div>
    <span class="cg-brand-name">CyberGuard</span>
    <span class="cg-brand-tag">Defensive Platform</span>
  </div>
  <div class="cg-nav-right">
    <span class="cg-user-name">{user['name']}</span>
    <div class="cg-avatar">{initials}</div>
  </div>
</div>
""", unsafe_allow_html=True)

# LAYOUT: sidebar + main
st.markdown('<div class="cg-layout">', unsafe_allow_html=True)

# Left sidebar nav
st.markdown("""
<div class="cg-sidebar">
  <div class="cg-sidenav-section">Main</div>
  <div class="cg-sidenav-item active">
    <span class="cg-sidenav-icon">&#9670;</span> Scanner
  </div>
  <div class="cg-sidenav-item">
    <span class="cg-sidenav-icon">&#9632;</span> History
  </div>
  <div class="cg-sidenav-section">Account</div>
  <div class="cg-sidenav-item">
    <span class="cg-sidenav-icon">&#9675;</span> Settings
  </div>
</div>
""", unsafe_allow_html=True)

# Main content
st.markdown('<div class="cg-main">', unsafe_allow_html=True)

# Sign out in Streamlit sidebar (hidden but functional)
with st.sidebar:
    st.write("")
    if st.button("Sign out", use_container_width=True, key="signout_btn"):
        st.session_state.user = None; st.session_state.last_scan = None; st.rerun()

# Page header
st.markdown("""
<div style="margin-bottom:24px">
  <h1 class="cg-page-title">Security Scanner</h1>
  <p class="cg-page-sub">Run a passive defensive assessment and export a client-ready report</p>
</div>
""", unsafe_allow_html=True)

# Scan card
st.markdown("""
<div class="cg-scan-card">
  <div class="cg-scan-card-title">
    <div class="cg-scan-dot"></div>
    New Scan
  </div>
</div>
""", unsafe_allow_html=True)

sc1, sc2, sc3 = st.columns([4, 3, 1.2], gap="medium")
with sc1:
    target_url = st.text_input("Target URL", placeholder="https://example.com", key="k_url")
with sc2:
    client_name = st.text_input("Client name", placeholder="Acme Corporation", key="k_cl")
with sc3:
    st.markdown('<div style="height:27px"></div>', unsafe_allow_html=True)
    scan_btn = st.button("Run scan", use_container_width=True, key="k_scan")

if scan_btn:
    if not target_url.strip():
        st.error("Please enter a target URL.")
    else:
        try:
            with st.spinner("Running security checks..."):
                st.session_state.last_scan = run_scan(target_url)
        except requests.exceptions.SSLError:
            st.error("SSL handshake failed. Verify the target supports HTTPS.")
        except requests.exceptions.ConnectionError:
            st.error("Could not connect to target. Check the URL and try again.")
        except requests.exceptions.Timeout:
            st.error("Request timed out.")
        except Exception as e:
            st.error(f"Error: {e}")

scan = st.session_state.last_scan

if scan:
    ssl_info = scan["ssl_info"]
    ssl_days = ssl_info.get("days_remaining")
    issues   = sum(1 for f in scan["findings"] if not f["ok"])
    total    = len(scan["findings"])
    passed   = total - issues

    def sc_cls(r): return {"Strong":"green","Moderate":"amber","Needs Improvement":"amber","High Risk":"red"}.get(r,"blue")
    def sc_badge_cls(r): return {"Strong":"ok","Moderate":"warn","Needs Improvement":"warn","High Risk":"err"}.get(r,"inf")
    ssl_col = "green" if ssl_info.get("enabled") else "red"
    ssl_badge = "ok" if ssl_info.get("enabled") else "err"
    iss_col = "red" if issues > 4 else "amber" if issues > 0 else "green"
    iss_badge = "err" if issues > 4 else "warn" if issues > 0 else "ok"
    score_pct = scan["score"]
    bar_color = "#16a34a" if score_pct >= 70 else "#d97706" if score_pct >= 50 else "#dc2626"

    # STAT CARDS
    st.markdown(f"""
    <div class="cg-stats">
      <div class="cg-stat">
        <div class="cg-stat-label">Security Score</div>
        <div class="cg-stat-val {sc_cls(scan['rating'])}">{scan['score']}</div>
        <div class="cg-progress-wrap" style="margin-top:10px">
          <div class="cg-progress-bar" style="width:{scan['score']}%;background:{bar_color}"></div>
        </div>
        <span class="cg-stat-badge {sc_badge_cls(scan['rating'])}">{scan['rating']}</span>
      </div>
      <div class="cg-stat">
        <div class="cg-stat-label">TLS / SSL</div>
        <div class="cg-stat-val {ssl_col}">{'Active' if ssl_info.get('enabled') else 'None'}</div>
        <div class="cg-stat-sub" style="margin-top:10px">{f"{ssl_days} days remaining" if ssl_days is not None and ssl_info.get('enabled') else 'Not detected'}</div>
        <span class="cg-stat-badge {ssl_badge}">{'Secure' if ssl_info.get('enabled') else 'Not secure'}</span>
      </div>
      <div class="cg-stat">
        <div class="cg-stat-label">HTTP Status</div>
        <div class="cg-stat-val blue">{scan['status_code']}</div>
        <div class="cg-stat-sub" style="margin-top:10px">Final response code</div>
        <span class="cg-stat-badge inf">Response OK</span>
      </div>
      <div class="cg-stat">
        <div class="cg-stat-label">Issues Found</div>
        <div class="cg-stat-val {iss_col}">{issues}</div>
        <div class="cg-stat-sub" style="margin-top:10px">{passed} of {total} checks passed</div>
        <span class="cg-stat-badge {iss_badge}">{issues} issue{'s' if issues != 1 else ''}</span>
      </div>
    </div>
    """, unsafe_allow_html=True)

    # SUMMARY + TLS
    col_l, col_r = st.columns([3, 2], gap="medium")

    with col_l:
        st.markdown("""
        <div class="cg-card">
          <div class="cg-card-header">
            <span class="cg-card-title">Executive Summary</span>
          </div>
        """, unsafe_allow_html=True)
        for pt in scan["summary"]:
            st.markdown(f"""
            <div class="cg-bullet">
              <div class="cg-bullet-icon">i</div>
              <span class="cg-bullet-txt">{pt}</span>
            </div>""", unsafe_allow_html=True)
        st.markdown(f"""
        <div style="margin-top:16px;padding-top:14px;border-top:1px solid var(--b0)">
          <div class="cg-kv"><span class="cg-kv-k">Target</span><span class="cg-kv-v mono">{scan['input_url']}</span></div>
          <div class="cg-kv"><span class="cg-kv-k">Final URL</span><span class="cg-kv-v mono">{scan['final_url']}</span></div>
          <div class="cg-kv"><span class="cg-kv-k">Scanned</span><span class="cg-kv-v">{scan['scanned_at']}</span></div>
          <div class="cg-kv" style="border-bottom:none"><span class="cg-kv-k">HTTP</span><span class="cg-kv-v">{scan['status_code']}</span></div>
        </div>
        </div>""", unsafe_allow_html=True)

    with col_r:
        st.markdown("""
        <div class="cg-card">
          <div class="cg-card-header">
            <span class="cg-card-title">TLS Certificate</span>
          </div>
        """, unsafe_allow_html=True)
        if ssl_info.get("enabled"):
            d = ssl_info.get("days_remaining", 0)
            dc = "#16a34a" if d > 45 else "#d97706" if d > 15 else "#dc2626"
            st.markdown(f"""
            <div class="cg-tls-days" style="color:{dc}">{d}</div>
            <div class="cg-tls-label">days until expiry</div>
            <div class="cg-kv"><span class="cg-kv-k">Issuer</span><span class="cg-kv-v">{ssl_info.get('issuer','--')}</span></div>
            <div class="cg-kv"><span class="cg-kv-k">Subject</span><span class="cg-kv-v">{ssl_info.get('subject','--')}</span></div>
            <div class="cg-kv" style="border-bottom:none"><span class="cg-kv-k">Valid to</span><span class="cg-kv-v">{ssl_info.get('valid_to','--')}</span></div>
            </div>""", unsafe_allow_html=True)
        else:
            st.markdown(f"""
            <div style="font-size:20px;font-weight:700;color:#dc2626;margin-bottom:8px">Not available</div>
            <div style="font-size:12px;color:#6b7280">{ssl_info.get('error','TLS not detected.')}</div>
            </div>""", unsafe_allow_html=True)

    # FINDINGS
    st.markdown(f"""
    <div class="cg-section-row">
      <span class="cg-section-title">Detailed Findings</span>
      <span class="cg-section-meta">{issues} issue{'s' if issues != 1 else ''} across {total} checks</span>
    </div>""", unsafe_allow_html=True)

    cats = {}
    for f in scan["findings"]: cats.setdefault(f["cat"], []).append(f)
    bc = {"High":"H","Medium":"M","Low":"L","Info":"I"}

    for cat, items in cats.items():
        p_count = sum(1 for f in items if f["ok"])
        f_count = len(items) - p_count
        with st.expander(f"**{cat}**  |  {p_count}/{len(items)} passed"):
            for item in items:
                dot = ("#16a34a" if item["ok"] else
                       "#dc2626" if item["sev"] == "High" else
                       "#d97706" if item["sev"] == "Medium" else
                       "#0284c7" if item["sev"] == "Low" else "#16a34a")
                cls = bc.get(item["sev"], "I")
                ok_cls = "pass" if item["ok"] else "fail"
                st.markdown(f"""
                <div class="cg-finding">
                  <div class="cg-finding-top">
                    <div class="cg-finding-dot" style="background:{dot}"></div>
                    <span class="cg-finding-name">{item['name']}</span>
                    <span class="cg-badge badge-{cls}">{item['sev']}</span>
                    <span class="cg-badge badge-{ok_cls}">{'Pass' if item['ok'] else 'Fail'}</span>
                  </div>
                  <div class="cg-finding-desc">{item['desc']}</div>
                  <div class="cg-finding-foot">
                    <span class="cg-chip">{item['val']}</span>
                    <span class="cg-rec">&#8594; {item['fix']}</span>
                  </div>
                </div>""", unsafe_allow_html=True)

    # EXPORT
    st.markdown("""
    <div class="cg-section-row" style="margin-top:28px">
      <span class="cg-section-title">Export Report</span>
    </div>""", unsafe_allow_html=True)

    ex1, ex2 = st.columns([3, 1], gap="medium")
    with ex1:
        st.markdown(f"""
        <div class="cg-card">
          <div class="cg-card-header">
            <span class="cg-card-title">PDF Report</span>
            <span class="cg-card-meta">Ready for client delivery</span>
          </div>
          <table class="cg-table">
            <thead><tr><th>Section</th><th>Contents</th></tr></thead>
            <tbody>
              <tr><td>Engagement Details</td><td>Client, target URL, analyst, date, HTTP status</td></tr>
              <tr><td>Assessment Overview</td><td>Score, TLS status, HTTP code, issue count</td></tr>
              <tr><td>TLS Certificate</td><td>Issuer, subject, expiry date, days remaining</td></tr>
              <tr><td>Executive Summary</td><td>Key findings and prioritised recommendations</td></tr>
              <tr><td>Detailed Findings</td><td>All {total} checks with severity, pass/fail, and remediation</td></tr>
              <tr><td>Scope Notice</td><td>Authorised defensive review disclaimer</td></tr>
            </tbody>
          </table>
        </div>""", unsafe_allow_html=True)
    with ex2:
        st.markdown('<div style="height:10px"></div>', unsafe_allow_html=True)
        pdf_bytes = build_pdf(scan, client_name or "--", user["name"])
        st.download_button(
            "Download PDF",
            data=pdf_bytes,
            file_name=f"cyberguard-{scan['hostname']}.pdf",
            mime="application/pdf",
            use_container_width=True,
        )
        st.caption(f"Report for {scan['hostname']}")
        st.caption(f"Generated {scan['scanned_at']}")

st.markdown('</div>', unsafe_allow_html=True)  # close cg-main
st.markdown('</div>', unsafe_allow_html=True)  # close cg-layout

st.markdown("""
<div class="cg-footer">
  <span class="cg-footer-txt">CyberGuard &nbsp;&middot;&nbsp; Pamupro Cyber &nbsp;&middot;&nbsp; Authorised defensive reviews only</span>
  <span class="cg-footer-txt">Do not scan without permission</span>
</div>
""", unsafe_allow_html=True)
