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

st.set_page_config(
    page_title="CyberGuard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ─────────────────────────────────────────────────────────────
# GLOBAL CSS
# ─────────────────────────────────────────────────────────────
st.markdown("""
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
<style>
/* ── Tokens ─────────────────────────────────────────── */
:root{
  --bg:#0c0c0f;
  --s1:#111115;
  --s2:#17171c;
  --s3:#1e1e25;
  --s4:#2a2a35;
  --b0:rgba(255,255,255,0.05);
  --b1:rgba(255,255,255,0.09);
  --b2:rgba(255,255,255,0.14);
  --t0:#f4f4f6;
  --t1:#a0a0b0;
  --t2:#60607a;
  --t3:#3a3a50;
  --acc:#5b6af0;
  --acc2:#4455e8;
  --acc-g:rgba(91,106,240,0.12);
  --acc-b:rgba(91,106,240,0.22);
  --ok:#22c55e;
  --ok-g:rgba(34,197,94,0.10);
  --ok-b:rgba(34,197,94,0.20);
  --warn:#f59e0b;
  --warn-g:rgba(245,158,11,0.10);
  --warn-b:rgba(245,158,11,0.20);
  --err:#ef4444;
  --err-g:rgba(239,68,68,0.10);
  --err-b:rgba(239,68,68,0.20);
  --inf:#38bdf8;
  --inf-g:rgba(56,189,248,0.10);
  --inf-b:rgba(56,189,248,0.20);
  --font:'Inter',-apple-system,sans-serif;
  --r:8px;--rl:12px;--rxl:16px;
}
/* ── Reset ──────────────────────────────────────────── */
*,*::before,*::after{box-sizing:border-box}
html,body,[class*="css"]{font-family:var(--font)!important;-webkit-font-smoothing:antialiased}
.stApp{background:var(--bg)!important;color:var(--t0)!important}
#MainMenu,footer,header{visibility:hidden}
.block-container{padding:0!important;max-width:100%!important}
p,span,label,div,li,td,th,small,caption{color:var(--t0)!important;font-family:var(--font)!important}
/* Sidebar */
[data-testid="stSidebar"]{background:var(--s1)!important;border-right:1px solid var(--b1)!important}
[data-testid="stSidebar"] *{color:var(--t1)!important}
/* ── Input fields ───────────────────────────────────── */
[data-testid="stTextInput"] label{
  font-size:11px!important;font-weight:500!important;
  letter-spacing:.05em!important;text-transform:uppercase!important;
  color:var(--t2)!important;margin-bottom:5px!important;display:block!important
}
[data-testid="stTextInput"]>div>div{
  background:var(--s2)!important;border:1px solid var(--b1)!important;
  border-radius:var(--r)!important;transition:border-color .15s,box-shadow .15s!important
}
[data-testid="stTextInput"]>div>div:focus-within{
  border-color:var(--acc)!important;box-shadow:0 0 0 3px var(--acc-g)!important
}
[data-testid="stTextInput"] input{
  background:transparent!important;border:none!important;outline:none!important;
  color:var(--t0)!important;font-family:var(--font)!important;
  font-size:14px!important;padding:10px 12px!important
}
[data-testid="stTextInput"] input::placeholder{color:var(--t3)!important}
/* ── Buttons ────────────────────────────────────────── */
.stButton>button{
  background:var(--acc)!important;color:#fff!important;border:none!important;
  border-radius:var(--r)!important;font-family:var(--font)!important;
  font-size:13px!important;font-weight:500!important;letter-spacing:-.01em!important;
  padding:10px 18px!important;cursor:pointer!important;
  transition:background .15s,transform .1s!important;white-space:nowrap!important;
  line-height:1.4!important
}
.stButton>button:hover{background:var(--acc2)!important;transform:translateY(-1px)!important}
.stButton>button:active{transform:translateY(0)!important}
[data-testid="stDownloadButton"]>button{
  background:var(--s3)!important;color:var(--t0)!important;
  border:1px solid var(--b2)!important;font-size:13px!important;font-weight:500!important
}
[data-testid="stDownloadButton"]>button:hover{background:var(--s4)!important;border-color:var(--acc)!important}
/* ── Tabs ───────────────────────────────────────────── */
[data-testid="stTabs"] [role="tablist"]{
  border-bottom:1px solid var(--b1)!important;background:transparent!important;gap:0!important
}
[data-testid="stTabs"] button[role="tab"]{
  background:transparent!important;border:none!important;
  border-bottom:2px solid transparent!important;border-radius:0!important;
  color:var(--t2)!important;font-family:var(--font)!important;
  font-size:13px!important;font-weight:500!important;
  padding:10px 18px!important;transition:color .15s!important
}
[data-testid="stTabs"] button[role="tab"][aria-selected="true"]{
  color:var(--t0)!important;border-bottom:2px solid var(--acc)!important
}
[data-testid="stTabs"]>div>div:last-child{padding:20px 0 0!important}
/* ── Expanders ──────────────────────────────────────── */
[data-testid="stExpander"]{
  background:var(--s2)!important;border:1px solid var(--b0)!important;
  border-radius:var(--rl)!important;overflow:hidden!important;margin-bottom:6px!important
}
[data-testid="stExpander"]>div:first-child{padding:14px 18px!important}
[data-testid="stExpander"] details[open]>div:first-child{border-bottom:1px solid var(--b0)!important}
[data-testid="stExpander"] summary{
  font-family:var(--font)!important;font-size:13px!important;
  font-weight:500!important;color:var(--t0)!important
}
[data-testid="stExpander"]>div:last-child{padding:0 18px 16px!important;background:var(--s2)!important}
/* ── Alerts ─────────────────────────────────────────── */
[data-testid="stAlert"]{background:var(--s2)!important;border-radius:var(--r)!important;border:1px solid var(--b1)!important}
[data-testid="stNotification"]{background:var(--s2)!important;border:1px solid var(--b1)!important;border-radius:var(--r)!important}
/* ── Scrollbar ──────────────────────────────────────── */
::-webkit-scrollbar{width:4px;height:4px;background:var(--bg)}
::-webkit-scrollbar-thumb{background:var(--s4);border-radius:2px}

/* ════════════════════════════════════════════════════
   NAV
   ════════════════════════════════════════════════════ */
.cg-nav{
  height:54px;padding:0 28px;display:flex;align-items:center;
  justify-content:space-between;border-bottom:1px solid var(--b1);
  background:rgba(12,12,15,.9);backdrop-filter:blur(12px);
  position:sticky;top:0;z-index:200
}
.cg-nav-left{display:flex;align-items:center;gap:20px}
.cg-brand{display:flex;align-items:center;gap:9px;text-decoration:none}
.cg-brand-icon{
  width:28px;height:28px;border-radius:7px;
  background:linear-gradient(135deg,var(--acc),#8b5cf6);
  display:flex;align-items:center;justify-content:center;
  font-size:13px;flex-shrink:0
}
.cg-brand-name{font-size:14px;font-weight:600;letter-spacing:-.025em;color:var(--t0)}
.cg-nav-tag{
  font-size:10px;font-weight:600;letter-spacing:.05em;text-transform:uppercase;
  color:var(--acc);background:var(--acc-g);border:1px solid var(--acc-b);
  border-radius:4px;padding:2px 8px
}
.cg-nav-right{display:flex;align-items:center;gap:10px}
.cg-nav-user{
  display:flex;align-items:center;gap:7px;font-size:12px;color:var(--t1);
  background:var(--s2);border:1px solid var(--b1);border-radius:20px;
  padding:5px 12px 5px 8px;cursor:pointer
}
.cg-online{width:7px;height:7px;border-radius:50%;background:var(--ok);
  box-shadow:0 0 6px rgba(34,197,94,.5)}

/* ════════════════════════════════════════════════════
   PAGE SHELL
   ════════════════════════════════════════════════════ */
.cg-wrap{max-width:1100px;margin:0 auto;padding:0 28px 80px}

/* ── Hero ──────────────────────────────────────────── */
.cg-hero{padding:52px 0 40px;margin-bottom:0}
.cg-hero-eyebrow{
  display:inline-flex;align-items:center;gap:7px;
  font-size:11px;font-weight:500;letter-spacing:.07em;text-transform:uppercase;
  color:var(--t2);margin-bottom:20px
}
.cg-hero-eyebrow-dot{width:5px;height:5px;border-radius:50%;background:var(--acc)}
.cg-hero-h1{
  font-size:36px;font-weight:700;letter-spacing:-.04em;line-height:1.1;
  color:var(--t0);margin:0 0 16px
}
.cg-hero-p{font-size:14px;line-height:1.65;color:var(--t2);max-width:520px;margin:0 0 32px}

/* ── Scan box ──────────────────────────────────────── */
.cg-scan-box{
  background:var(--s1);border:1px solid var(--b1);border-radius:var(--rxl);
  padding:22px;margin-bottom:32px
}
.cg-field-label{
  font-size:11px;font-weight:500;letter-spacing:.05em;text-transform:uppercase;
  color:var(--t2);margin-bottom:6px
}

/* ════════════════════════════════════════════════════
   RESULTS
   ════════════════════════════════════════════════════ */
/* Stat bar */
.cg-stats{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:24px}
.cg-stat{
  background:var(--s1);border:1px solid var(--b1);border-radius:var(--rl);
  padding:20px;position:relative;overflow:hidden
}
.cg-stat-accent{
  position:absolute;top:0;left:0;right:0;height:2px;
  background:linear-gradient(90deg,var(--acc),transparent)
}
.cg-stat-accent.ok{background:linear-gradient(90deg,var(--ok),transparent)}
.cg-stat-accent.warn{background:linear-gradient(90deg,var(--warn),transparent)}
.cg-stat-accent.err{background:linear-gradient(90deg,var(--err),transparent)}
.cg-stat-lbl{
  font-size:11px;font-weight:500;letter-spacing:.05em;text-transform:uppercase;
  color:var(--t2);margin-bottom:12px
}
.cg-stat-val{
  font-size:30px;font-weight:700;letter-spacing:-.04em;line-height:1;color:var(--t0)
}
.cg-stat-val.ok{color:#4ade80}
.cg-stat-val.warn{color:#fbbf24}
.cg-stat-val.err{color:#f87171}
.cg-stat-val.inf{color:var(--inf)}
.cg-stat-sub{font-size:12px;color:var(--t2);margin-top:6px;font-weight:400}

/* Two column grid */
.cg-two{display:grid;grid-template-columns:3fr 2fr;gap:12px;margin-bottom:12px}

/* Cards */
.cg-card{
  background:var(--s1);border:1px solid var(--b1);border-radius:var(--rl);padding:22px
}
.cg-card-lbl{
  font-size:10px;font-weight:600;letter-spacing:.07em;text-transform:uppercase;
  color:var(--t2);margin-bottom:18px;padding-bottom:12px;border-bottom:1px solid var(--b0)
}

/* KV rows inside cards */
.cg-kv{display:flex;gap:10px;padding:9px 0;border-bottom:1px solid var(--b0);align-items:baseline}
.cg-kv:last-child{border-bottom:none;padding-bottom:2px}
.cg-kv-k{
  font-size:11px;font-weight:500;color:var(--t2);min-width:82px;flex-shrink:0
}
.cg-kv-v{font-size:12px;color:var(--t1);word-break:break-all;line-height:1.45}
.cg-kv-v.mono{
  font-family:'Fira Code','Cascadia Mono',monospace;font-size:11px;color:var(--t1)
}

/* Summary bullets */
.cg-bullet{display:flex;gap:10px;padding:10px 0;border-bottom:1px solid var(--b0);align-items:flex-start}
.cg-bullet:last-child{border-bottom:none;padding-bottom:0}
.cg-bullet-dot{
  width:5px;height:5px;border-radius:50%;background:var(--acc);
  flex-shrink:0;margin-top:7px
}
.cg-bullet-txt{font-size:13px;color:var(--t1);line-height:1.55}

/* TLS big num */
.cg-tls-num{font-size:44px;font-weight:700;letter-spacing:-.05em;line-height:1;margin-bottom:3px}
.cg-tls-sub{font-size:12px;color:var(--t2);margin-bottom:20px}

/* Section header */
.cg-sh{
  display:flex;align-items:baseline;gap:10px;margin:32px 0 12px;
  padding-bottom:12px;border-bottom:1px solid var(--b1)
}
.cg-sh-title{font-size:14px;font-weight:600;color:var(--t0);letter-spacing:-.015em}
.cg-sh-meta{font-size:12px;color:var(--t2)}

/* Finding rows */
.cg-fi{padding:13px 0;border-bottom:1px solid var(--b0)}
.cg-fi:last-child{border-bottom:none;padding-bottom:2px}
.cg-fi-row{display:flex;align-items:center;gap:8px;margin-bottom:5px}
.cg-fi-dot{width:6px;height:6px;border-radius:50%;flex-shrink:0}
.cg-fi-name{font-size:13px;font-weight:500;color:var(--t0);flex:1;line-height:1.3}
.cg-fi-desc{font-size:12px;color:var(--t2);margin:0 0 6px 14px;line-height:1.5}
.cg-fi-foot{display:flex;align-items:center;gap:8px;margin-left:14px;flex-wrap:wrap}
.cg-chip{
  font-family:'Fira Code','Cascadia Mono',monospace;font-size:11px;color:var(--t2);
  background:var(--s3);border:1px solid var(--b0);padding:2px 8px;
  border-radius:5px;max-width:340px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap
}
.cg-rec{font-size:12px;color:var(--t1);line-height:1.4}

/* Severity badges */
.cg-badge{
  font-size:10px;font-weight:600;letter-spacing:.04em;text-transform:uppercase;
  padding:2px 7px;border-radius:4px;flex-shrink:0
}
.badge-H{background:var(--err-g);color:#fca5a5;border:1px solid var(--err-b)}
.badge-M{background:var(--warn-g);color:#fcd34d;border:1px solid var(--warn-b)}
.badge-L{background:var(--inf-g);color:#7dd3fc;border:1px solid var(--inf-b)}
.badge-I{background:var(--ok-g);color:#86efac;border:1px solid var(--ok-b)}

/* Export */
.cg-export{
  background:var(--s1);border:1px solid var(--b1);border-radius:var(--rl);
  padding:22px;margin-bottom:12px
}
.cg-export-grid{display:flex;align-items:flex-start;justify-content:space-between;gap:24px}
.cg-export-info{font-size:13px;color:var(--t2);line-height:1.65;max-width:520px}
.cg-export-info li{margin-bottom:4px}
.cg-export-action{flex-shrink:0;min-width:160px}

/* ════════════════════════════════════════════════════
   AUTH SCREEN
   ════════════════════════════════════════════════════ */
.cg-auth-bg{
  min-height:100vh;display:flex;flex-direction:column;
  align-items:center;justify-content:center;padding:24px;
  background:radial-gradient(ellipse 60% 40% at 50% 0%,rgba(91,106,240,.08),transparent 70%)
}

/* ════════════════════════════════════════════════════
   FOOTER
   ════════════════════════════════════════════════════ */
.cg-footer{
  border-top:1px solid var(--b1);padding:16px 28px;
  display:flex;align-items:center;justify-content:space-between
}
.cg-footer span{font-size:11px;color:var(--t3)}
</style>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────
# AUTH  (stdlib only — no bcrypt)
# ─────────────────────────────────────────────────────────────
DB_FILE = "cyberguard.db"

def _db_init():
    with closing(sqlite3.connect(DB_FILE)) as c:
        c.execute("""CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,created_at TEXT NOT NULL)""")
        c.commit()

def _pw_hash(p):
    s=os.urandom(16);dk=hashlib.pbkdf2_hmac("sha256",p.encode(),s,260_000)
    return f"pbkdf2${s.hex()}${dk.hex()}"

def _pw_verify(p,stored):
    try:
        _,sh,dh=stored.split("$");dk=hashlib.pbkdf2_hmac("sha256",p.encode(),bytes.fromhex(sh),260_000)
        return dk.hex()==dh
    except:return False

def create_user(name,email,password):
    try:
        with closing(sqlite3.connect(DB_FILE)) as c:
            c.execute("INSERT INTO users(name,email,password_hash,created_at)VALUES(?,?,?,?)",
                (name.strip(),email.strip().lower(),_pw_hash(password),datetime.utcnow().isoformat()))
            c.commit()
        return True,"Account created."
    except sqlite3.IntegrityError:return False,"That email is already registered."
    except Exception as e:return False,str(e)

def authenticate_user(email,password):
    with closing(sqlite3.connect(DB_FILE)) as c:
        row=c.execute("SELECT id,name,email,password_hash FROM users WHERE email=?",(email.strip().lower(),)).fetchone()
    if row and _pw_verify(password,row[3]):return True,{"id":row[0],"name":row[1],"email":row[2]}
    return False,None

# ─────────────────────────────────────────────────────────────
# SCANNER
# ─────────────────────────────────────────────────────────────
_UA="CyberGuard/2.0 (authorized defensive review)"

_HDRS={
    "Strict-Transport-Security":{"w":14,"sev":"High",
        "desc":"Forces browsers to use HTTPS for all future requests, preventing protocol downgrade and SSL stripping attacks.",
        "fix":"Strict-Transport-Security: max-age=31536000; includeSubDomains"},
    "Content-Security-Policy":{"w":16,"sev":"High",
        "desc":"Controls which resources the browser may load, dramatically reducing the XSS attack surface.",
        "fix":"Define a restrictive CSP policy tailored to your application's actual resource requirements."},
    "X-Frame-Options":{"w":8,"sev":"Medium",
        "desc":"Prevents the page from being embedded in iframes on other domains, blocking clickjacking.",
        "fix":"X-Frame-Options: DENY"},
    "X-Content-Type-Options":{"w":8,"sev":"Medium",
        "desc":"Prevents browsers from MIME-sniffing responses, blocking content-type confusion attacks.",
        "fix":"X-Content-Type-Options: nosniff"},
    "Referrer-Policy":{"w":6,"sev":"Low",
        "desc":"Controls how much referrer information is passed to other origins when navigating away.",
        "fix":"Referrer-Policy: strict-origin-when-cross-origin"},
    "Permissions-Policy":{"w":6,"sev":"Low",
        "desc":"Restricts which browser APIs and device features this page is permitted to use.",
        "fix":"Define a Permissions-Policy covering camera, microphone, geolocation, etc."},
}
_OPT=["Cross-Origin-Opener-Policy","Cross-Origin-Resource-Policy","Cross-Origin-Embedder-Policy"]
_PATHS=["/robots.txt","/security.txt","/.well-known/security.txt","/sitemap.xml"]

def _norm(u):
    u=u.strip()
    return("https://"+u)if u and not u.startswith(("http://","https://"))else u

def _host(u):return urlparse(u).hostname or ""

def _fetch(u):
    return requests.get(u,timeout=10,headers={"User-Agent":_UA},allow_redirects=True)

def _ssl(host,port=443):
    r={"enabled":False,"issuer":None,"subject":None,"valid_to":None,"days_remaining":None,"error":None}
    try:
        ctx=ssl.create_default_context()
        with socket.create_connection((host,port),timeout=6)as sock:
            with ctx.wrap_socket(sock,server_hostname=host)as ss:cert=ss.getpeercert()
        r["enabled"]=True
        iss=dict(x[0]for x in cert.get("issuer",[]))
        sub=dict(x[0]for x in cert.get("subject",[]))
        r["issuer"]=iss.get("organizationName")or str(iss)
        r["subject"]=sub.get("commonName")or str(sub)
        vt=datetime.strptime(cert["notAfter"],"%b %d %H:%M:%S %Y %Z")
        r["valid_to"]=vt.strftime("%d %b %Y")
        r["days_remaining"]=(vt.replace(tzinfo=timezone.utc)-datetime.now(timezone.utc)).days
    except Exception as e:r["error"]=str(e)
    return r

def _proto(iu,fu):
    return[
        {"cat":"Protocol","name":"HTTPS on input URL","ok":iu.startswith("https://"),
         "sev":"High","w":14,"val":iu,
         "desc":"Verifies the target URL uses HTTPS, ensuring encrypted transport from the start.",
         "fix":"Ensure all traffic begins on https://."},
        {"cat":"Protocol","name":"HTTPS on final URL","ok":fu.startswith("https://"),
         "sev":"High","w":14,"val":fu,
         "desc":"Verifies the final landing page after all redirects is served over HTTPS.",
         "fix":"Issue a permanent 301 redirect from HTTP to HTTPS."},
    ]

def _headers(resp):
    out=[]
    for h,m in _HDRS.items():
        p=h in resp.headers
        out.append({"cat":"Security Headers","name":h,"ok":p,
            "sev":"Info"if p else m["sev"],"w":m["w"],
            "val":resp.headers.get(h,"Not set"),
            "desc":m["desc"],"fix":"Header is correctly configured."if p else m["fix"]})
    for h in _OPT:
        p=h in resp.headers
        out.append({"cat":"Security Headers","name":h,"ok":p,
            "sev":"Info"if p else "Low","w":3,
            "val":resp.headers.get(h,"Not set"),
            "desc":"Cross-origin isolation header providing additional defence-in-depth hardening.",
            "fix":"Configured."if p else f"Consider adding {h} for improved isolation."})
    return out

def _cookies(resp):
    raw=resp.raw.headers.get_all("Set-Cookie")if hasattr(resp.raw.headers,"get_all")else[]
    if not raw:
        return[{"cat":"Cookies","name":"Set-Cookie presence","ok":True,"sev":"Info","w":0,
                "val":"None observed","desc":"No cookies were issued in this response.","fix":"No action required."}]
    out=[]
    for i,c in enumerate(raw,1):
        low=c.lower()
        miss=[f for f,k in[("Secure","secure"),("HttpOnly","httponly"),("SameSite","samesite")]if k not in low]
        out.append({"cat":"Cookies","name":f"Cookie #{i}","ok":not miss,
            "sev":"Info"if not miss else"Medium","w":8,
            "val":c[:90]+("…"if len(c)>90 else""),
            "desc":"Cookie security attributes control whether cookies can be intercepted or forged.",
            "fix":"All security attributes present."if not miss else f"Add missing attributes: {', '.join(miss)}."})
    return out

def _disclosure(resp):
    out=[]
    for h,lbl in[("Server","Server header"),("X-Powered-By","X-Powered-By header")]:
        val=resp.headers.get(h)
        out.append({"cat":"Information Disclosure","name":lbl,"ok":not bool(val),
            "sev":"Info"if not val else"Low","w":5,"val":val or"Not present",
            "desc":"Exposing server/framework version strings helps attackers find applicable CVEs.",
            "fix":"Not exposed — good."if not val else f"Remove or redact the {h} response header."})
    return out

def _paths(base):
    sess=requests.Session();out=[]
    for p in _PATHS:
        url=urljoin(base,p)
        try:
            r=sess.get(url,timeout=5,headers={"User-Agent":_UA},allow_redirects=True)
            ok=r.status_code==200
            out.append({"cat":"Security Files","name":p,"ok":ok,
                "sev":"Info"if ok else"Low","w":3,"val":f"HTTP {r.status_code}",
                "desc":"Standard file that aids security researchers and responsible disclosure.",
                "fix":"Accessible."if ok else f"Consider publishing {p}."})
        except:
            out.append({"cat":"Security Files","name":p,"ok":False,"sev":"Low","w":3,
                "val":"Unreachable","desc":"Standard security disclosure file.",
                "fix":f"Consider publishing {p}."})
    return out

def _score(findings,ssl_info):
    mp=sum(f["w"]for f in findings if f["w"]>0)+10
    ea=sum(f["w"]for f in findings if f["ok"]and f["w"]>0)
    if ssl_info.get("enabled"):
        d=ssl_info.get("days_remaining")
        ea+=10 if(d is None or d>=45)else 6 if d>=15 else 3 if d>=0 else 0
    s=round(ea/mp*100)if mp else 0
    if s>=85:return s,"Strong"
    if s>=70:return s,"Moderate"
    if s>=50:return s,"Needs Improvement"
    return s,"High Risk"

def _summary(findings,ssl_info):
    pts=[]
    hi=[f["name"]for f in findings if not f["ok"]and f["sev"]=="High"]
    md=[f["name"]for f in findings if not f["ok"]and f["sev"]=="Medium"]
    if hi:pts.append(f"Critical gaps requiring attention: {', '.join(hi[:3])}.")
    if md:pts.append(f"Medium-severity issues detected: {', '.join(md[:3])}.")
    d=ssl_info.get("days_remaining")
    if ssl_info.get("enabled")and d is not None and d<30:
        pts.append(f"TLS certificate expires in {d} days — urgent renewal required.")
    if not pts:pts.append("No critical security configuration issues were identified in this review.")
    return pts

def run_scan(url):
    t=_norm(url);resp=_fetch(t);h=_host(t)
    ssl_info=_ssl(h)if h else{"enabled":False,"error":"No hostname"}
    findings=_proto(t,resp.url)+_headers(resp)+_cookies(resp)+_disclosure(resp)+_paths(resp.url)
    score,rating=_score(findings,ssl_info)
    return{"input_url":t,"final_url":resp.url,"hostname":h,
           "status_code":resp.status_code,"ssl_info":ssl_info,
           "findings":findings,"score":score,"rating":rating,
           "summary":_summary(findings,ssl_info),
           "scanned_at":datetime.utcnow().strftime("%d %b %Y, %H:%M UTC")}

# ─────────────────────────────────────────────────────────────
# PDF REPORT  — clean, structured A4
# ─────────────────────────────────────────────────────────────
C={
    "navy":   colors.HexColor("#0f172a"),
    "navy2":  colors.HexColor("#1e293b"),
    "blue":   colors.HexColor("#3b5bdb"),
    "text":   colors.HexColor("#1e293b"),
    "muted":  colors.HexColor("#64748b"),
    "sub":    colors.HexColor("#94a3b8"),
    "bdr":    colors.HexColor("#e2e8f0"),
    "bg":     colors.HexColor("#ffffff"),
    "bg1":    colors.HexColor("#f8fafc"),
    "bg2":    colors.HexColor("#f1f5f9"),
    "bg3":    colors.HexColor("#e2e8f0"),
    "green":  colors.HexColor("#16a34a"),
    "amber":  colors.HexColor("#d97706"),
    "red":    colors.HexColor("#dc2626"),
    "white":  colors.HexColor("#ffffff"),
    "acc_lt": colors.HexColor("#e0e7ff"),
}

def _PS(n,sz,col,bold=False,lead=None,sb=0,sa=4,indent=0):
    return ParagraphStyle(n,fontSize=sz,textColor=col,
        fontName="Helvetica-Bold"if bold else"Helvetica",
        leading=lead or round(sz*1.5),spaceBefore=sb,spaceAfter=sa,leftIndent=indent)

def _sev_c(s):return{"High":C["red"],"Medium":C["amber"],"Low":C["blue"],"Info":C["green"]}.get(s,C["muted"])
def _rat_c(r):return{"Strong":C["green"],"Moderate":C["amber"],"Needs Improvement":C["amber"],"High Risk":C["red"]}.get(r,C["muted"])

def _hl(sa=8,sb=0,color=None):
    return HRFlowable(width="100%",thickness=0.5,color=color or C["bdr"],spaceBefore=sb,spaceAfter=sa)

class _HF:
    def __init__(self,company,analyst,date):
        self.co=company;self.an=analyst;self.dt=date
    def __call__(self,cv,doc):
        W,H=A4;cv.saveState()
        # ── Header bar ────────────────────────────────────────
        cv.setFillColor(C["navy"]);cv.rect(0,H-50,W,50,fill=1,stroke=0)
        # accent strip
        cv.setFillColor(C["blue"]);cv.rect(0,H-50,4,50,fill=1,stroke=0)
        # shield icon area
        cv.setFillColor(colors.HexColor("#1e3a8a"))
        cv.roundRect(W-50*mm,H-42,30*mm,33,4,fill=1,stroke=0)
        # logo text
        cv.setFont("Helvetica-Bold",13);cv.setFillColor(C["white"])
        cv.drawString(12*mm,H-22,"CyberGuard")
        cv.setFont("Helvetica",8);cv.setFillColor(colors.HexColor("#94a3b8"))
        cv.drawString(12*mm,H-35,"Security Review Platform")
        # right meta
        cv.setFont("Helvetica",8);cv.setFillColor(colors.HexColor("#94a3b8"))
        cv.drawRightString(W-12*mm,H-22,self.co)
        cv.drawRightString(W-12*mm,H-35,self.dt)
        # ── Footer bar ────────────────────────────────────────
        cv.setFillColor(C["bg2"]);cv.rect(0,0,W,26,fill=1,stroke=0)
        cv.setStrokeColor(C["bdr"]);cv.setLineWidth(0.5);cv.line(0,26,W,26)
        cv.setFont("Helvetica",7);cv.setFillColor(C["sub"])
        cv.drawString(12*mm,9,f"Analyst: {self.an}  ·  Confidential — Authorised Defensive Review Only")
        cv.drawRightString(W-12*mm,9,f"Page {doc.page}")
        cv.restoreState()

def build_pdf(scan,company,analyst):
    buf=io.BytesIO()
    W,H=A4;LM=RM=13*mm;TM=58;BM=34;CW=W-LM-RM
    doc=BaseDocTemplate(buf,pagesize=A4,leftMargin=LM,rightMargin=RM,topMargin=TM,bottomMargin=BM)
    frame=Frame(LM,BM,CW,H-TM-BM,id="body")
    cb=_HF(company,analyst,scan["scanned_at"])
    doc.addPageTemplates([PageTemplate(id="main",frames=[frame],onPage=cb)])

    S={
        "h1":  _PS("h1",  20,C["navy"],  bold=True, lead=24,sa=6),
        "h2":  _PS("h2",  11,C["navy"],  bold=True, lead=15,sb=18,sa=6),
        "h3":  _PS("h3",   9,C["muted"],bold=True, lead=13,sb=0, sa=3),
        "body":_PS("b",    9,C["text"],             lead=14,sa=3),
        "sm":  _PS("sm", 8.5,C["text"],             lead=13,sa=2),
        "mu":  _PS("mu",   8,C["muted"],            lead=12,sa=2),
        "code":_PS("cd",   8,C["muted"],            lead=11,sa=2),
        "disc":_PS("dc", 7.5,C["muted"],            lead=11,sa=0),
    }

    def kv(rows,k_w=38*mm):
        data=[]
        for k,v in rows:
            data.append([Paragraph(k,S["h3"]),Paragraph(v,S["sm"])])
        t=Table(data,colWidths=[k_w,CW-k_w])
        t.setStyle(TableStyle([
            ("FONTSIZE",    (0,0),(-1,-1),8.5),
            ("LEADING",     (0,0),(-1,-1),12),
            ("TOPPADDING",  (0,0),(-1,-1),6),
            ("BOTTOMPADDING",(0,0),(-1,-1),6),
            ("LEFTPADDING", (0,0),(-1,-1),8),
            ("RIGHTPADDING",(0,0),(-1,-1),8),
            ("BACKGROUND",  (0,0),(0,-1), C["bg2"]),
            ("BACKGROUND",  (1,0),(1,-1), C["bg"]),
            ("TEXTCOLOR",   (0,0),(0,-1), C["muted"]),
            ("TEXTCOLOR",   (1,0),(1,-1), C["text"]),
            ("FONTNAME",    (0,0),(0,-1), "Helvetica-Bold"),
            ("LINEBELOW",   (0,0),(-1,-1),0.5,C["bdr"]),
        ]))
        return t

    story=[]

    # ── Cover block ───────────────────────────────────────────
    rc=_rat_c(scan["rating"])
    # Score badge
    score_badge=Table([
        [Paragraph(f'<font size="28" color="{rc.hexval()}"><b>{scan["score"]}</b></font>'
                   f'<font size="11" color="#94a3b8"> / 100</font>',S["body"])],
        [Paragraph(f'<font color="{rc.hexval()}"><b>{scan["rating"]}</b></font>',S["mu"])],
    ],colWidths=[55*mm])
    score_badge.setStyle(TableStyle([
        ("ALIGN",(0,0),(-1,-1),"RIGHT"),("PADDING",(0,0),(-1,-1),0),("VALIGN",(0,0),(-1,-1),"BOTTOM"),
    ]))
    cover=Table([[Paragraph("Website Security<br/>Review Report",S["h1"]),score_badge]],
        colWidths=[CW-58*mm,58*mm])
    cover.setStyle(TableStyle([
        ("VALIGN",(0,0),(-1,-1),"BOTTOM"),("PADDING",(0,0),(-1,-1),0),
        ("LINEBELOW",(0,0),(-1,0),0.8,C["navy"]),("BOTTOMPADDING",(0,0),(-1,0),14),
    ]))
    story+=[cover,Spacer(1,14)]

    # ── Engagement details ────────────────────────────────────
    story.append(kv([
        ("Client",       company),
        ("Target URL",   scan["input_url"]),
        ("Final URL",    scan["final_url"]),
        ("Analyst",      analyst),
        ("Reviewed",     scan["scanned_at"]),
        ("HTTP Status",  str(scan["status_code"])),
    ]))
    story.append(Spacer(1,6))

    # ── Score summary row ─────────────────────────────────────
    story+=[Paragraph("Assessment Overview",S["h2"]),_hl()]

    def score_cell(label,value,color,sub=""):
        inner=[
            [Paragraph(f'<font size="7" color="#64748b"><b>{label.upper()}</b></font>',S["mu"])],
            [Paragraph(f'<font size="18" color="{color.hexval()}"><b>{value}</b></font>',S["body"])],
        ]
        if sub:inner.append([Paragraph(f'<font size="7" color="#94a3b8">{sub}</font>',S["mu"])])
        t=Table(inner,colWidths=[(CW-6*mm)/4])
        t.setStyle(TableStyle([
            ("ALIGN",(0,0),(-1,-1),"CENTER"),("PADDING",(0,0),(-1,-1),8),
            ("VALIGN",(0,0),(-1,-1),"MIDDLE"),
        ]))
        return t

    ssl=scan["ssl_info"]
    d=ssl.get("days_remaining",0)
    dc=C["green"]if(d or 0)>45 else C["amber"]if(d or 0)>15 else C["red"]
    ssl_val="Active"if ssl.get("enabled")else"None"
    ssl_col=C["green"]if ssl.get("enabled")else C["red"]

    overview_row=Table([[
        score_cell("Score",       f'{scan["score"]}/100',  rc,         scan["rating"]),
        score_cell("TLS",         ssl_val,                 ssl_col,    f"{d} days"if ssl.get("enabled")else""),
        score_cell("HTTP",        str(scan["status_code"]),C["blue"],  "Response code"),
        score_cell("Issues",      str(sum(1 for f in scan["findings"]if not f["ok"])),
                   C["amber"],f'of {len(scan["findings"])} checks'),
    ]],colWidths=[(CW-3*mm)/4]*4)
    overview_row.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(-1,-1),C["bg1"]),
        ("BOX",(0,0),(-1,-1),0.5,C["bdr"]),
        ("LINEBEFORE",(1,0),(3,0),0.5,C["bdr"]),
        ("PADDING",(0,0),(-1,-1),0),
        ("VALIGN",(0,0),(-1,-1),"MIDDLE"),
    ]))
    story+=[overview_row,Spacer(1,6)]

    # ── TLS details ───────────────────────────────────────────
    story+=[Paragraph("TLS / SSL Certificate",S["h2"]),_hl()]
    if ssl.get("enabled"):
        story.append(kv([
            ("Issuer",   ssl.get("issuer","—")),
            ("Subject",  ssl.get("subject","—")),
            ("Valid To", ssl.get("valid_to","—")),
            ("Days Left",f'<font color="{dc.hexval()}"><b>{d}</b></font>'),
        ]))
    else:
        story.append(Paragraph(f"TLS unavailable: {ssl.get('error','unknown')}",S["mu"]))
    story.append(Spacer(1,4))

    # ── Executive Summary ─────────────────────────────────────
    story+=[Paragraph("Executive Summary",S["h2"]),_hl()]
    for pt in scan["summary"]:
        story.append(Paragraph(f"<bullet>&#x2014;</bullet> {pt}",_PS("bp",9,C["text"],lead=14,sa=3,indent=10)))
    story.append(Spacer(1,4))

    # ── Findings table ────────────────────────────────────────
    story+=[Paragraph("Detailed Findings",S["h2"]),_hl()]

    # Column widths
    cws=[38*mm,28*mm,16*mm,13*mm,CW-38*mm-28*mm-16*mm-13*mm]
    hdr=[Paragraph(f"<b>{t}</b>",S["h3"])
         for t in["Finding","Category","Severity","Result","Recommendation"]]
    rows=[hdr]
    for f in scan["findings"]:
        sc2=_sev_c(f["sev"])
        pass_col=C["green"]if f["ok"]else C["red"]
        rows.append([
            Paragraph(f["name"],    S["sm"]),
            Paragraph(f["cat"],     S["sm"]),
            Paragraph(f'<font color="{sc2.hexval()}"><b>{f["sev"]}</b></font>',S["sm"]),
            Paragraph(f'<font color="{pass_col.hexval()}"><b>{"Pass"if f["ok"]else"Fail"}</b></font>',S["sm"]),
            Paragraph(f["fix"],     S["sm"]),
        ])

    ft=Table(rows,colWidths=cws,repeatRows=1)
    ft.setStyle(TableStyle([
        ("FONTSIZE",        (0,0),(-1,-1),8),
        ("LEADING",         (0,0),(-1,-1),12),
        ("TOPPADDING",      (0,0),(-1,-1),6),
        ("BOTTOMPADDING",   (0,0),(-1,-1),6),
        ("LEFTPADDING",     (0,0),(-1,-1),7),
        ("RIGHTPADDING",    (0,0),(-1,-1),7),
        ("VALIGN",          (0,0),(-1,-1),"TOP"),
        ("BACKGROUND",      (0,0),(-1, 0),C["navy"]),
        ("TEXTCOLOR",       (0,0),(-1, 0),C["white"]),
        ("FONTNAME",        (0,0),(-1, 0),"Helvetica-Bold"),
        ("ROWBACKGROUNDS",  (0,1),(-1,-1),[C["bg"],C["bg1"]]),
        ("LINEBELOW",       (0,0),(-1,-1),0.4,C["bdr"]),
        ("BOX",             (0,0),(-1,-1),0.5,C["bdr"]),
    ]))
    story.append(ft)
    story.append(Spacer(1,20))

    # ── Scope notice ──────────────────────────────────────────
    disc_data=[[Paragraph(
        "<b>Scope Notice</b> — This report covers passive, defensive web configuration analysis only. "
        "No offensive, intrusive, or exploitative testing was performed. "
        "This document is intended for authorised assessment, portfolio demonstration, and security awareness.",
        _PS("di",8,C["muted"],lead=12))]]
    disc=Table(disc_data,colWidths=[CW])
    disc.setStyle(TableStyle([
        ("BACKGROUND",   (0,0),(-1,-1),C["bg2"]),
        ("LINEABOVE",    (0,0),(-1, 0),2,C["blue"]),
        ("TOPPADDING",   (0,0),(-1,-1),10),
        ("BOTTOMPADDING",(0,0),(-1,-1),10),
        ("LEFTPADDING",  (0,0),(-1,-1),12),
        ("RIGHTPADDING", (0,0),(-1,-1),12),
    ]))
    story.append(disc)

    doc.build(story)
    pdf=buf.getvalue();buf.close();return pdf

# ─────────────────────────────────────────────────────────────
# APP STATE
# ─────────────────────────────────────────────────────────────
_db_init()
if "user"      not in st.session_state:st.session_state.user=None
if "last_scan" not in st.session_state:st.session_state.last_scan=None

# ═════════════════════════════════════════════════════════════
# AUTH SCREEN
# ═════════════════════════════════════════════════════════════
if st.session_state.user is None:
    # Three columns — centre column holds the auth card
    _,mid,_=st.columns([1,1.1,1])
    with mid:
        st.markdown('<div style="height:72px"></div>',unsafe_allow_html=True)

        # Brand mark
        st.markdown("""
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">
          <div style="width:32px;height:32px;border-radius:8px;
               background:linear-gradient(135deg,#5b6af0,#8b5cf6);
               display:flex;align-items:center;justify-content:center;
               font-size:15px;flex-shrink:0">🛡️</div>
          <span style="font-size:16px;font-weight:700;letter-spacing:-.025em;color:#f4f4f6">CyberGuard</span>
        </div>
        <p style="font-size:12px;color:#60607a;margin:0 0 28px 0;padding:0">
          Professional website security reviews
        </p>
        """,unsafe_allow_html=True)

        # Card
        st.markdown("""<div style="background:#111115;border:1px solid rgba(255,255,255,0.09);
        border-radius:16px;padding:26px 24px 20px">""",unsafe_allow_html=True)

        t_in,t_up=st.tabs(["Sign in","Create account"])

        with t_in:
            st.markdown('<p style="font-size:16px;font-weight:600;letter-spacing:-.02em;'
                        'color:#f4f4f6;margin:6px 0 22px">Welcome back</p>',unsafe_allow_html=True)
            em=st.text_input("Email",key="li_em",placeholder="you@company.com")
            pw=st.text_input("Password",type="password",key="li_pw",placeholder="Your password")
            st.markdown('<div style="height:6px"></div>',unsafe_allow_html=True)
            if st.button("Sign in →",use_container_width=True,key="btn_li"):
                if not em or not pw:st.error("Enter your email and password.")
                else:
                    ok,user=authenticate_user(em,pw)
                    if ok:st.session_state.user=user;st.rerun()
                    else:st.error("Incorrect email or password.")

        with t_up:
            st.markdown('<p style="font-size:16px;font-weight:600;letter-spacing:-.02em;'
                        'color:#f4f4f6;margin:6px 0 22px">Create your account</p>',unsafe_allow_html=True)
            nm =st.text_input("Full name",   key="su_nm",placeholder="Alex Johnson")
            em2=st.text_input("Work email",  key="su_em",placeholder="alex@company.com")
            pw2=st.text_input("Password",    key="su_pw",placeholder="Min. 8 characters",type="password")
            st.markdown('<div style="height:6px"></div>',unsafe_allow_html=True)
            if st.button("Create account →",use_container_width=True,key="btn_su"):
                if not nm or not em2 or not pw2:st.error("All fields are required.")
                elif len(pw2)<8:st.error("Password must be at least 8 characters.")
                else:
                    ok,msg=create_user(nm,em2,pw2)
                    if ok:st.success(msg+" You can now sign in.")
                    else:st.error(msg)

        st.markdown('</div>',unsafe_allow_html=True)
        st.markdown('<p style="font-size:11px;color:#3a3a50;text-align:center;margin-top:14px">'
                    'Authorised use only · Do not scan without permission</p>',unsafe_allow_html=True)
    st.stop()

# ═════════════════════════════════════════════════════════════
# MAIN APP
# ═════════════════════════════════════════════════════════════
user=st.session_state.user

# Sidebar
with st.sidebar:
    st.markdown(f"<p style='font-size:14px;font-weight:600;color:#f4f4f6;margin-bottom:3px'>{user['name']}</p>",unsafe_allow_html=True)
    st.markdown(f"<p style='font-size:11px;color:#60607a;margin-top:0'>{user['email']}</p>",unsafe_allow_html=True)
    st.divider()
    st.caption("Only scan websites you own or have explicit written permission to assess.")
    st.write("")
    if st.button("Sign out",use_container_width=True):
        st.session_state.user=None;st.session_state.last_scan=None;st.rerun()

# ── Top nav ──────────────────────────────────────────────────
st.markdown(f"""
<div class="cg-nav">
  <div class="cg-nav-left">
    <div class="cg-brand">
      <div class="cg-brand-icon">🛡️</div>
      <span class="cg-brand-name">CyberGuard</span>
    </div>
    <span class="cg-nav-tag">Defensive Analysis</span>
  </div>
  <div class="cg-nav-right">
    <div class="cg-nav-user">
      <div class="cg-online"></div>
      {user['name']}
    </div>
  </div>
</div>
""",unsafe_allow_html=True)

# ── Page wrapper ─────────────────────────────────────────────
st.markdown('<div class="cg-wrap">',unsafe_allow_html=True)

# ── Hero ─────────────────────────────────────────────────────
st.markdown("""
<div class="cg-hero">
  <div class="cg-hero-eyebrow">
    <span class="cg-hero-eyebrow-dot"></span>
    Security Review Platform
  </div>
  <h1 class="cg-hero-h1">Website security,<br>reviewed in seconds.</h1>
  <p class="cg-hero-p">
    Run a comprehensive passive security assessment — TLS certificates, security headers,
    cookie attributes, and information disclosure checks. Export a polished, client-ready
    PDF report in one click.
  </p>
</div>
""",unsafe_allow_html=True)

# ── Scan input ───────────────────────────────────────────────
st.markdown('<div class="cg-scan-box">',unsafe_allow_html=True)
c1,c2,c3=st.columns([5,3,1.4],gap="medium")
with c1:
    target_url=st.text_input("Target URL",placeholder="https://example.com",key="k_url")
with c2:
    client_name=st.text_input("Client name",placeholder="Acme Corporation",key="k_cl")
with c3:
    st.markdown('<div style="height:27px"></div>',unsafe_allow_html=True)
    scan_btn=st.button("Run scan",use_container_width=True,key="k_scan")
st.markdown('</div>',unsafe_allow_html=True)

if scan_btn:
    if not target_url.strip():
        st.error("Please enter a target URL.")
    else:
        try:
            with st.spinner("Running security checks…"):
                st.session_state.last_scan=run_scan(target_url)
        except requests.exceptions.SSLError:
            st.error("SSL handshake failed. Verify the target supports HTTPS.")
        except requests.exceptions.ConnectionError:
            st.error("Could not connect to target. Check the URL and try again.")
        except requests.exceptions.Timeout:
            st.error("Request timed out. The target may be unreachable.")
        except Exception as e:
            st.error(f"Error: {e}")

# ── RESULTS ──────────────────────────────────────────────────
scan=st.session_state.last_scan

if scan:
    ssl_info=scan["ssl_info"]
    ssl_days=ssl_info.get("days_remaining")
    issues=sum(1 for f in scan["findings"]if not f["ok"])
    total=len(scan["findings"])

    # Rating → colour class
    sc_cls={"Strong":"ok","Moderate":"warn","Needs Improvement":"warn","High Risk":"err"}.get(scan["rating"],"")
    ssl_cls="ok"if ssl_info.get("enabled")else"err"
    iss_cls="err"if issues>4 else"warn"if issues>0 else"ok"

    # ── Stat bar ─────────────────────────────────────────────
    st.markdown(f"""
    <div class="cg-stats">
      <div class="cg-stat">
        <div class="cg-stat-accent {sc_cls}"></div>
        <div class="cg-stat-lbl">Security Score</div>
        <div class="cg-stat-val {sc_cls}">{scan['score']}<span style="font-size:16px;font-weight:400;color:var(--t3)"> / 100</span></div>
        <div class="cg-stat-sub">{scan['rating']}</div>
      </div>
      <div class="cg-stat">
        <div class="cg-stat-accent {ssl_cls}"></div>
        <div class="cg-stat-lbl">TLS / SSL</div>
        <div class="cg-stat-val {ssl_cls}">{'Active' if ssl_info.get('enabled') else 'None'}</div>
        <div class="cg-stat-sub">{f"{ssl_days} days remaining" if ssl_days is not None and ssl_info.get('enabled') else "Certificate status"}</div>
      </div>
      <div class="cg-stat">
        <div class="cg-stat-accent"></div>
        <div class="cg-stat-lbl">HTTP Status</div>
        <div class="cg-stat-val">{scan['status_code']}</div>
        <div class="cg-stat-sub">Final response code</div>
      </div>
      <div class="cg-stat">
        <div class="cg-stat-accent {iss_cls}"></div>
        <div class="cg-stat-lbl">Issues Found</div>
        <div class="cg-stat-val {iss_cls}">{issues}</div>
        <div class="cg-stat-sub">of {total} checks performed</div>
      </div>
    </div>
    """,unsafe_allow_html=True)

    # ── Summary + TLS ─────────────────────────────────────────
    col_l,col_r=st.columns([3,2],gap="medium")

    with col_l:
        st.markdown('<div class="cg-card"><div class="cg-card-lbl">Executive Summary</div>',unsafe_allow_html=True)
        for pt in scan["summary"]:
            st.markdown(f"""<div class="cg-bullet">
              <div class="cg-bullet-dot"></div>
              <span class="cg-bullet-txt">{pt}</span>
            </div>""",unsafe_allow_html=True)
        st.markdown(f"""
        <div style="margin-top:18px">
          <div class="cg-kv"><span class="cg-kv-k">Input URL</span><span class="cg-kv-v mono">{scan['input_url']}</span></div>
          <div class="cg-kv"><span class="cg-kv-k">Final URL</span><span class="cg-kv-v mono">{scan['final_url']}</span></div>
          <div class="cg-kv" style="border-bottom:none"><span class="cg-kv-k">Reviewed</span><span class="cg-kv-v">{scan['scanned_at']}</span></div>
        </div></div>""",unsafe_allow_html=True)

    with col_r:
        st.markdown('<div class="cg-card"><div class="cg-card-lbl">TLS Certificate</div>',unsafe_allow_html=True)
        if ssl_info.get("enabled"):
            d=ssl_info.get("days_remaining",0)
            dc="#4ade80"if d>45 else"#fbbf24"if d>15 else"#f87171"
            st.markdown(f"""
            <div class="cg-tls-num" style="color:{dc}">{d}</div>
            <div class="cg-tls-sub">days until certificate expiry</div>
            <div class="cg-kv"><span class="cg-kv-k">Issuer</span><span class="cg-kv-v">{ssl_info.get('issuer','—')}</span></div>
            <div class="cg-kv"><span class="cg-kv-k">Subject</span><span class="cg-kv-v">{ssl_info.get('subject','—')}</span></div>
            <div class="cg-kv" style="border-bottom:none"><span class="cg-kv-k">Valid to</span><span class="cg-kv-v">{ssl_info.get('valid_to','—')}</span></div>
            </div>""",unsafe_allow_html=True)
        else:
            st.markdown(f"""
            <div style="font-size:26px;font-weight:700;color:#f87171;margin-bottom:6px">Unavailable</div>
            <div style="font-size:12px;color:var(--t2)">{ssl_info.get('error','TLS not detected.')}</div>
            </div>""",unsafe_allow_html=True)

    # ── Findings ─────────────────────────────────────────────
    st.markdown(f"""
    <div class="cg-sh">
      <span class="cg-sh-title">Findings</span>
      <span class="cg-sh-meta">{issues} issue{'s' if issues!=1 else ''} detected across {total} checks</span>
    </div>""",unsafe_allow_html=True)

    cats={}
    for f in scan["findings"]:cats.setdefault(f["cat"],[]).append(f)
    bc={"High":"H","Medium":"M","Low":"L","Info":"I"}

    for cat,items in cats.items():
        passed=sum(1 for f in items if f["ok"])
        fail_count=len(items)-passed
        status_emoji="✓" if fail_count==0 else f"⚠ {fail_count}"

        with st.expander(f"**{cat}** — {passed}/{len(items)} passed"):
            for item in items:
                dot=("#4ade80"if item["ok"]else
                     "#f87171"if item["sev"]=="High"else
                     "#fbbf24"if item["sev"]=="Medium"else
                     "#7dd3fc"if item["sev"]=="Low"else"#86efac")
                cls=bc.get(item["sev"],"I")
                st.markdown(f"""
                <div class="cg-fi">
                  <div class="cg-fi-row">
                    <div class="cg-fi-dot" style="background:{dot}"></div>
                    <div class="cg-fi-name">{item['name']}</div>
                    <span class="cg-badge badge-{cls}">{item['sev']}</span>
                  </div>
                  <div class="cg-fi-desc">{item['desc']}</div>
                  <div class="cg-fi-foot">
                    <span class="cg-chip">{item['val']}</span>
                    <span class="cg-rec">&#8594; {item['fix']}</span>
                  </div>
                </div>""",unsafe_allow_html=True)

    # ── Export ───────────────────────────────────────────────
    st.markdown("""
    <div class="cg-sh" style="margin-top:32px">
      <span class="cg-sh-title">Export Report</span>
    </div>""",unsafe_allow_html=True)

    ex1,ex2=st.columns([3,1],gap="medium")
    with ex1:
        st.markdown("""
        <div class="cg-export">
          <div class="cg-card-lbl">PDF Report</div>
          <p class="cg-export-info">
            A structured A4 PDF report including:
            <ul>
              <li>Engagement details &amp; assessment overview</li>
              <li>TLS certificate summary with expiry status</li>
              <li>Executive summary with key findings</li>
              <li>Full findings table — severity, pass/fail, remediation</li>
              <li>Scope disclaimer for client delivery</li>
            </ul>
          </p>
        </div>""",unsafe_allow_html=True)
    with ex2:
        st.markdown('<div style="height:10px"></div>',unsafe_allow_html=True)
        pdf_bytes=build_pdf(scan,client_name or "—",user["name"])
        st.download_button(
            "⬇  Download PDF",
            data=pdf_bytes,
            file_name=f"cyberguard-{scan['hostname']}.pdf",
            mime="application/pdf",
            use_container_width=True,
        )
        st.caption("Suitable for portfolio, client, and internal review.")

st.markdown('</div>',unsafe_allow_html=True)

# ── Footer ───────────────────────────────────────────────────
st.markdown("""
<div class="cg-footer">
  <span>CyberGuard &nbsp;·&nbsp; Pamupro Cyber</span>
  <span>Authorised defensive reviews only — do not scan without permission</span>
</div>
""",unsafe_allow_html=True)
