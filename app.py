"""
CyberGuard v2 – Business Website Security Review Platform
Modern SaaS-style Streamlit application.
"""

import sys, os
sys.path.insert(0, os.path.dirname(__file__))

import requests
import streamlit as st

from utils.auth import authenticate_user, create_user, init_db
from utils.scanner import run_scan
from utils.report import build_pdf

# ============================================================
# PAGE CONFIG
# ============================================================
st.set_page_config(
    page_title="CyberGuard — Security Review Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ============================================================
# GLOBAL CSS  –  Premium dark SaaS theme
# Uses Syne (display) + DM Sans (body) from Google Fonts
# ============================================================
st.markdown("""
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Syne:wght@600;700;800&family=DM+Sans:wght@300;400;500;600&display=swap" rel="stylesheet">

<style>
/* ── Reset & base ──────────────────────────────────────── */
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

html, body, [class*="css"] {
    font-family: var(--font-body) !important;
    color: var(--text) !important;
}

.stApp {
    background:
        radial-gradient(ellipse 80% 40% at 50% -10%, rgba(43,91,255,0.14) 0%, transparent 60%),
        radial-gradient(ellipse 40% 30% at 90% 20%, rgba(56,189,248,0.07) 0%, transparent 50%),
        linear-gradient(180deg, #060c18 0%, #07101f 100%);
    min-height: 100vh;
}

/* hide default streamlit chrome */
#MainMenu, footer, header { visibility: hidden; }
.block-container { padding: 0 !important; max-width: 100% !important; }

/* ── Sidebar ───────────────────────────────────────────── */
[data-testid="stSidebar"] {
    background: var(--surface) !important;
    border-right: 1px solid var(--border) !important;
}

/* ── Inputs ─────────────────────────────────────────────── */
input[type="text"], input[type="password"], input[type="email"],
[data-testid="stTextInput"] input {
    background: var(--surface2) !important;
    border: 1px solid var(--border2) !important;
    border-radius: 10px !important;
    color: var(--text) !important;
    font-family: var(--font-body) !important;
    font-size: 0.95rem !important;
    padding: 0.65rem 1rem !important;
    transition: border-color 0.2s;
}
input:focus { border-color: var(--blue) !important; outline: none !important; }

/* ── Buttons ─────────────────────────────────────────────── */
.stButton > button {
    background: linear-gradient(135deg, #2B5BFF 0%, #1a3fa8 100%) !important;
    color: #fff !important;
    border: none !important;
    border-radius: 10px !important;
    font-family: var(--font-body) !important;
    font-weight: 600 !important;
    font-size: 0.92rem !important;
    padding: 0.65rem 1.4rem !important;
    cursor: pointer !important;
    transition: all 0.2s !important;
    box-shadow: 0 4px 20px rgba(43,91,255,0.30) !important;
}
.stButton > button:hover {
    transform: translateY(-1px) !important;
    box-shadow: 0 6px 28px rgba(43,91,255,0.45) !important;
}

/* Download button */
[data-testid="stDownloadButton"] > button {
    background: linear-gradient(135deg, #0ea5e9 0%, #2B5BFF 100%) !important;
    width: 100% !important;
}

/* ── Expander ─────────────────────────────────────────────── */
[data-testid="stExpander"] {
    background: var(--surface2) !important;
    border: 1px solid var(--border) !important;
    border-radius: 12px !important;
    margin-bottom: 0.5rem !important;
}
[data-testid="stExpander"] summary {
    font-family: var(--font-body) !important;
    font-weight: 500 !important;
    color: var(--text) !important;
}

/* ── Alert / info boxes ─────────────────────────────────── */
[data-testid="stAlert"] {
    border-radius: 10px !important;
    border: 1px solid var(--border2) !important;
}

/* ── Metric ─────────────────────────────────────────────── */
[data-testid="stMetric"] {
    background: var(--surface2) !important;
    border: 1px solid var(--border) !important;
    border-radius: 14px !important;
    padding: 1rem !important;
}

/* ── Tabs ─────────────────────────────────────────────── */
[data-testid="stTabs"] [role="tablist"] {
    border-bottom: 1px solid var(--border2) !important;
    gap: 0.2rem !important;
}
[data-testid="stTabs"] button {
    font-family: var(--font-body) !important;
    font-weight: 500 !important;
    color: var(--muted) !important;
    border-radius: 8px 8px 0 0 !important;
    padding: 0.55rem 1.1rem !important;
    border: none !important;
    background: transparent !important;
}
[data-testid="stTabs"] button[aria-selected="true"] {
    color: var(--blue) !important;
    border-bottom: 2px solid var(--blue) !important;
    background: rgba(43,91,255,0.06) !important;
}

/* ── Spinner ────────────────────────────────────────────── */
[data-testid="stSpinner"] { color: var(--blue) !important; }

/* ── Scrollbar ──────────────────────────────────────────── */
::-webkit-scrollbar { width: 5px; background: var(--bg); }
::-webkit-scrollbar-thumb { background: var(--surface2); border-radius: 4px; }

/* ── Custom components ──────────────────────────────────── */
.cg-navbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 1rem 2.5rem;
    border-bottom: 1px solid var(--border);
    background: rgba(6,12,24,0.80);
    backdrop-filter: blur(16px);
    position: sticky; top: 0; z-index: 100;
}
.cg-logo {
    font-family: var(--font-head);
    font-size: 1.35rem;
    font-weight: 800;
    color: #fff;
    letter-spacing: -0.03em;
}
.cg-logo span { color: var(--blue); }
.cg-badge {
    display: inline-flex; align-items: center; gap: 0.35rem;
    font-size: 0.72rem; font-weight: 600; letter-spacing: 0.05em;
    text-transform: uppercase;
    color: var(--cyan);
    background: rgba(56,189,248,0.10);
    border: 1px solid rgba(56,189,248,0.20);
    border-radius: 999px;
    padding: 0.28rem 0.75rem;
}
.cg-user-pill {
    display: inline-flex; align-items: center; gap: 0.5rem;
    font-size: 0.87rem; color: var(--subtle);
    background: var(--surface2);
    border: 1px solid var(--border2);
    border-radius: 999px;
    padding: 0.35rem 1rem;
}
.cg-hero {
    padding: 3.5rem 2.5rem 2.5rem;
    max-width: 900px;
}
.cg-eyebrow {
    font-size: 0.75rem; font-weight: 600; letter-spacing: 0.12em;
    text-transform: uppercase; color: var(--blue);
    margin-bottom: 0.8rem;
}
.cg-headline {
    font-family: var(--font-head);
    font-size: 3rem; font-weight: 800;
    line-height: 1.05; letter-spacing: -0.04em;
    color: #fff;
    margin-bottom: 1rem;
}
.cg-headline em { color: var(--blue); font-style: normal; }
.cg-desc {
    font-size: 1.05rem; color: var(--subtle);
    line-height: 1.6; max-width: 580px;
    margin-bottom: 0;
}
.cg-scan-box {
    background: var(--surface);
    border: 1px solid var(--border2);
    border-radius: 18px;
    padding: 1.75rem 2rem;
    margin: 0 2.5rem 2rem;
    box-shadow: 0 8px 40px rgba(0,0,0,0.3);
}
.cg-scan-label {
    font-size: 0.75rem; font-weight: 600; letter-spacing: 0.08em;
    text-transform: uppercase; color: var(--muted);
    margin-bottom: 0.4rem;
}
.cg-metrics {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 1rem;
    margin: 0 2.5rem 2rem;
}
.cg-metric {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 16px;
    padding: 1.25rem 1.35rem;
    position: relative;
    overflow: hidden;
}
.cg-metric::before {
    content: '';
    position: absolute; top: 0; left: 0;
    width: 100%; height: 2px;
    background: linear-gradient(90deg, var(--blue), transparent);
}
.cg-metric-label {
    font-size: 0.76rem; font-weight: 600; letter-spacing: 0.06em;
    text-transform: uppercase; color: var(--muted);
    margin-bottom: 0.5rem;
}
.cg-metric-value {
    font-family: var(--font-head);
    font-size: 2rem; font-weight: 700;
    color: #fff; letter-spacing: -0.03em;
    line-height: 1;
}
.cg-metric-sub {
    font-size: 0.77rem; color: var(--muted);
    margin-top: 0.3rem;
}
.cg-section {
    margin: 0 2.5rem 2rem;
}
.cg-section-head {
    font-family: var(--font-head);
    font-size: 1.1rem; font-weight: 700;
    color: #fff; margin-bottom: 0.2rem;
}
.cg-section-sub {
    font-size: 0.82rem; color: var(--muted);
    margin-bottom: 1rem;
}
.cg-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 16px;
    padding: 1.5rem;
}
.cg-card-inner {
    background: var(--surface2);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 1.2rem 1.4rem;
}
.cg-finding-icon-ok   { color: var(--green); font-size: 1rem; }
.cg-finding-icon-warn { color: var(--amber); font-size: 1rem; }
.cg-finding-icon-bad  { color: var(--red);   font-size: 1rem; }
.cg-sev-high   { color: var(--red);   font-weight: 600; font-size: 0.8rem; }
.cg-sev-medium { color: var(--amber); font-weight: 600; font-size: 0.8rem; }
.cg-sev-low    { color: var(--cyan);  font-weight: 600; font-size: 0.8rem; }
.cg-sev-info   { color: var(--green); font-weight: 600; font-size: 0.8rem; }
.cg-score-ring {
    display: inline-flex; align-items: baseline; gap: 3px;
}
.cg-score-big {
    font-family: var(--font-head);
    font-size: 3.2rem; font-weight: 800;
    letter-spacing: -0.04em; line-height: 1;
}
.cg-score-denom { font-size: 1rem; color: var(--muted); }
.cg-auth-wrap {
    min-height: 100vh;
    display: flex; flex-direction: column;
    align-items: center; justify-content: center;
    padding: 2rem;
    background:
        radial-gradient(ellipse 70% 50% at 50% 0%, rgba(43,91,255,0.15), transparent 60%),
        var(--bg);
}
.cg-auth-logo {
    font-family: var(--font-head);
    font-size: 1.8rem; font-weight: 800;
    color: #fff; letter-spacing: -0.04em;
    margin-bottom: 0.3rem;
    text-align: center;
}
.cg-auth-logo span { color: var(--blue); }
.cg-auth-tagline {
    font-size: 0.9rem; color: var(--muted);
    text-align: center; margin-bottom: 2.5rem;
}
.cg-auth-card {
    background: var(--surface);
    border: 1px solid var(--border2);
    border-radius: 20px;
    padding: 2.2rem 2rem;
    width: 100%; max-width: 460px;
    box-shadow: 0 20px 60px rgba(0,0,0,0.4);
}
.cg-auth-title {
    font-family: var(--font-head);
    font-size: 1.4rem; font-weight: 700;
    color: #fff; margin-bottom: 1.5rem;
}
.cg-divider {
    border: none; border-top: 1px solid var(--border);
    margin: 1.5rem 0;
}
.cg-tag {
    display: inline-block;
    font-size: 0.72rem; font-weight: 600;
    letter-spacing: 0.04em; text-transform: uppercase;
    padding: 0.22rem 0.65rem;
    border-radius: 6px;
    margin-right: 0.35rem;
}
.cg-tag-high   { background: rgba(239,68,68,0.12);   color: var(--red);   border: 1px solid rgba(239,68,68,0.2);   }
.cg-tag-medium { background: rgba(245,158,11,0.12);  color: var(--amber); border: 1px solid rgba(245,158,11,0.2);  }
.cg-tag-low    { background: rgba(56,189,248,0.10);  color: var(--cyan);  border: 1px solid rgba(56,189,248,0.18); }
.cg-tag-info   { background: rgba(34,197,94,0.10);   color: var(--green); border: 1px solid rgba(34,197,94,0.18);  }
.cg-summary-bullet {
    display: flex; align-items: flex-start; gap: 0.6rem;
    padding: 0.65rem 0;
    border-bottom: 1px solid var(--border);
    font-size: 0.9rem; color: var(--subtle);
}
.cg-summary-bullet:last-child { border-bottom: none; }
.cg-summary-bullet .icon { flex-shrink: 0; margin-top: 1px; }
.cg-footer {
    padding: 1.5rem 2.5rem;
    border-top: 1px solid var(--border);
    display: flex; align-items: center; justify-content: space-between;
    font-size: 0.78rem; color: var(--muted);
}

/* Rating colours */
.rating-strong { color: var(--green) !important; }
.rating-moderate { color: var(--amber) !important; }
.rating-needs { color: var(--amber) !important; }
.rating-high { color: var(--red) !important; }
</style>
""", unsafe_allow_html=True)

# ============================================================
# INIT
# ============================================================
init_db()
if "user" not in st.session_state:
    st.session_state.user = None
if "last_scan" not in st.session_state:
    st.session_state.last_scan = None
if "auth_tab" not in st.session_state:
    st.session_state.auth_tab = "login"


# ============================================================
# HELPERS
# ============================================================
def _rating_css(rating: str) -> str:
    return {"Strong": "rating-strong", "Moderate": "rating-moderate",
            "Needs Improvement": "rating-needs", "High Risk": "rating-high"}.get(rating, "")

def _sev_class(sev: str) -> str:
    return {"High": "cg-sev-high", "Medium": "cg-sev-medium",
            "Low": "cg-sev-low", "Info": "cg-sev-info"}.get(sev, "cg-sev-info")

def _tag_class(sev: str) -> str:
    return {"High": "cg-tag-high", "Medium": "cg-tag-medium",
            "Low": "cg-tag-low", "Info": "cg-tag-info"}.get(sev, "cg-tag-info")

def _icon(present: bool, severity: str) -> str:
    if present:
        return "✅"
    if severity == "High":
        return "🔴"
    if severity == "Medium":
        return "🟡"
    return "🔵"


# ============================================================
# AUTH SCREEN
# ============================================================
if st.session_state.user is None:
    st.markdown('<div class="cg-auth-wrap">', unsafe_allow_html=True)
    st.markdown("""
        <div class="cg-auth-logo">Cyber<span>Guard</span></div>
        <div class="cg-auth-tagline">Professional website security reviews for modern teams</div>
    """, unsafe_allow_html=True)

    tab_login, tab_signup = st.tabs(["Sign In", "Create Account"])

    with tab_login:
        st.markdown('<div class="cg-auth-card">', unsafe_allow_html=True)
        st.markdown('<div class="cg-auth-title">Welcome back</div>', unsafe_allow_html=True)
        email_l = st.text_input("Email address", key="li_email", placeholder="you@company.com")
        pass_l  = st.text_input("Password", type="password", key="li_pass", placeholder="••••••••")
        st.write("")
        if st.button("Sign In →", use_container_width=True, key="btn_login"):
            if not email_l or not pass_l:
                st.error("Please enter both email and password.")
            else:
                ok, user = authenticate_user(email_l, pass_l)
                if ok:
                    st.session_state.user = user
                    st.rerun()
                else:
                    st.error("Invalid email or password.")
        st.markdown('</div>', unsafe_allow_html=True)

    with tab_signup:
        st.markdown('<div class="cg-auth-card">', unsafe_allow_html=True)
        st.markdown('<div class="cg-auth-title">Create your account</div>', unsafe_allow_html=True)
        name_s  = st.text_input("Full Name", key="su_name", placeholder="Alex Johnson")
        email_s = st.text_input("Work Email", key="su_email", placeholder="alex@company.com")
        pass_s  = st.text_input("Password (min 8 chars)", type="password", key="su_pass", placeholder="••••••••")
        st.write("")
        if st.button("Create Account →", use_container_width=True, key="btn_signup"):
            if not name_s or not email_s or not pass_s:
                st.error("Please complete all fields.")
            elif len(pass_s) < 8:
                st.error("Password must be at least 8 characters.")
            else:
                ok, msg = create_user(name_s, email_s, pass_s)
                if ok:
                    st.success(msg + "  Switch to Sign In to continue.")
                else:
                    st.error(msg)
        st.markdown('</div>', unsafe_allow_html=True)

    st.markdown('</div>', unsafe_allow_html=True)
    st.stop()


# ============================================================
# MAIN APP — NAV BAR
# ============================================================
user = st.session_state.user
col_nav_l, col_nav_r = st.columns([6, 1])
with col_nav_l:
    st.markdown(f"""
    <div class="cg-navbar">
        <div style="display:flex;align-items:center;gap:1rem;">
            <span class="cg-logo">Cyber<span>Guard</span></span>
            <span class="cg-badge">🛡 Defensive Analysis</span>
        </div>
        <div class="cg-user-pill">
            👤 &nbsp;{user['name']}
        </div>
    </div>
    """, unsafe_allow_html=True)

# Logout in sidebar to keep nav clean
with st.sidebar:
    st.markdown(f"### {user['name']}")
    st.caption(user["email"])
    st.divider()
    st.info("CyberGuard performs passive defensive checks only. Only scan websites you own or have explicit permission to assess.")
    if st.button("🚪  Log Out", use_container_width=True):
        st.session_state.user = None
        st.session_state.last_scan = None
        st.rerun()


# ============================================================
# HERO + SCAN INPUT
# ============================================================
st.markdown("""
<div class="cg-hero">
    <div class="cg-eyebrow">Security Review Platform</div>
    <div class="cg-headline">Website security<br>reviewed in <em>seconds.</em></div>
    <div class="cg-desc">Run a comprehensive defensive assessment — SSL, headers, cookies, information disclosure, and more — then export a polished client-ready PDF report.</div>
</div>
""", unsafe_allow_html=True)

st.markdown('<div class="cg-scan-box">', unsafe_allow_html=True)
c1, c2, c3 = st.columns([3, 2, 1])
with c1:
    st.markdown('<div class="cg-scan-label">Target website URL</div>', unsafe_allow_html=True)
    target_url = st.text_input("URL", label_visibility="collapsed",
                                placeholder="https://example.com", key="url_input")
with c2:
    st.markdown('<div class="cg-scan-label">Client / Company Name</div>', unsafe_allow_html=True)
    client_name = st.text_input("Client", label_visibility="collapsed",
                                 placeholder="Nexora Commerce Ltd", key="client_input")
with c3:
    st.markdown('<div class="cg-scan-label">&nbsp;</div>', unsafe_allow_html=True)
    scan_clicked = st.button("Run Scan →", use_container_width=True, key="btn_scan")
st.markdown('</div>', unsafe_allow_html=True)

# ============================================================
# RUN SCAN
# ============================================================
if scan_clicked:
    if not target_url:
        st.error("Please enter a website URL to scan.")
    else:
        try:
            with st.spinner("🔍  Running defensive security checks…"):
                st.session_state.last_scan = run_scan(target_url)
            st.success("✅  Scan completed successfully.")
        except requests.exceptions.SSLError:
            st.error("SSL connection failed. Verify the target supports HTTPS correctly.")
        except requests.exceptions.ConnectionError:
            st.error("Cannot reach target. Check the URL and try again.")
        except requests.exceptions.Timeout:
            st.error("Target timed out. It may be down or blocking requests.")
        except Exception as exc:
            st.error(f"Unexpected error: {exc}")


# ============================================================
# RESULTS
# ============================================================
scan = st.session_state.last_scan

if scan:
    ssl_info = scan["ssl_info"]

    # ── Metric cards ──────────────────────────────────────
    rating_cls = _rating_css(scan["rating"])
    ssl_days = ssl_info.get("days_remaining")
    ssl_label = f"{ssl_days}d" if ssl_days is not None else "Active"
    ssl_sub = "days until expiry" if ssl_days is not None else "TLS enabled"

    st.markdown(f"""
    <div class="cg-metrics">
        <div class="cg-metric">
            <div class="cg-metric-label">Security Score</div>
            <div class="cg-score-ring">
                <span class="cg-score-big {rating_cls}">{scan['score']}</span>
                <span class="cg-score-denom">/100</span>
            </div>
            <div class="cg-metric-sub">{scan['rating']}</div>
        </div>
        <div class="cg-metric">
            <div class="cg-metric-label">TLS / SSL</div>
            <div class="cg-metric-value" style="color:{'var(--green)' if ssl_info.get('enabled') else 'var(--red)'}">
                {"✓ Active" if ssl_info.get('enabled') else "✗ None"}
            </div>
            <div class="cg-metric-sub">{ssl_label if ssl_info.get('enabled') else "TLS not detected"}</div>
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

    # ── Two-column layout: summary + TLS ──────────────────
    col_left, col_right = st.columns([1.3, 0.7], gap="medium")

    with col_left:
        st.markdown('<div class="cg-section">', unsafe_allow_html=True)
        st.markdown('<div class="cg-section-head">Executive Summary</div>', unsafe_allow_html=True)
        st.markdown('<div class="cg-section-sub">Key observations from this security review</div>', unsafe_allow_html=True)
        st.markdown('<div class="cg-card">', unsafe_allow_html=True)
        for pt in scan["summary"]:
            st.markdown(f"""
            <div class="cg-summary-bullet">
                <span class="icon">◈</span>
                <span>{pt}</span>
            </div>
            """, unsafe_allow_html=True)
        st.markdown('<hr class="cg-divider">', unsafe_allow_html=True)
        st.markdown(f"""
        <div style="font-size:0.83rem;color:var(--muted);line-height:1.8;">
            <b style="color:var(--subtle)">Input URL</b><br>{scan['input_url']}<br>
            <b style="color:var(--subtle)">Final URL</b><br>{scan['final_url']}<br>
            <b style="color:var(--subtle)">Scanned</b><br>{scan['scanned_at']}
        </div>
        """, unsafe_allow_html=True)
        st.markdown('</div></div>', unsafe_allow_html=True)

    with col_right:
        st.markdown('<div class="cg-section">', unsafe_allow_html=True)
        st.markdown('<div class="cg-section-head">TLS Certificate</div>', unsafe_allow_html=True)
        st.markdown('<div class="cg-section-sub">SSL/TLS inspection results</div>', unsafe_allow_html=True)
        st.markdown('<div class="cg-card">', unsafe_allow_html=True)
        if ssl_info.get("enabled"):
            days = ssl_info.get("days_remaining", 0)
            day_color = "var(--green)" if days > 45 else "var(--amber)" if days > 15 else "var(--red)"
            st.markdown(f"""
            <div style="margin-bottom:1rem;">
                <span style="font-family:var(--font-head);font-size:2rem;font-weight:700;color:{day_color}">{days}</span>
                <span style="color:var(--muted);font-size:0.85rem;"> days remaining</span>
            </div>
            <div style="font-size:0.85rem;color:var(--subtle);line-height:2.1;">
                <b style="color:var(--text)">Issuer</b><br>
                <span style="color:var(--muted)">{ssl_info.get('issuer','—')}</span><br>
                <b style="color:var(--text)">Subject</b><br>
                <span style="color:var(--muted)">{ssl_info.get('subject','—')}</span><br>
                <b style="color:var(--text)">Valid To</b><br>
                <span style="color:var(--muted)">{ssl_info.get('valid_to','—')}</span>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown(f"""
            <div style="color:var(--red);font-size:2rem;margin-bottom:0.5rem;">✗</div>
            <div style="color:var(--muted);font-size:0.88rem;">TLS unavailable<br>{ssl_info.get('error','')}</div>
            """, unsafe_allow_html=True)
        st.markdown('</div></div>', unsafe_allow_html=True)

    # ── Findings ──────────────────────────────────────────
    st.markdown('<div class="cg-section">', unsafe_allow_html=True)
    st.markdown('<div class="cg-section-head">Detailed Findings</div>', unsafe_allow_html=True)
    st.markdown('<div class="cg-section-sub">Expand each check for full details and remediation guidance</div>', unsafe_allow_html=True)

    # Group by category
    categories: dict[str, list] = {}
    for f in scan["findings"]:
        categories.setdefault(f["category"], []).append(f)

    for cat, items in categories.items():
        ok_count = sum(1 for f in items if f["present"])
        total = len(items)
        with st.expander(f"**{cat}** — {ok_count}/{total} checks passed"):
            for item in items:
                icon = _icon(item["present"], item["severity"])
                sev_tag = f'<span class="cg-tag {_tag_class(item["severity"])}">{item["severity"]}</span>'
                cols = st.columns([0.05, 0.95])
                with cols[0]:
                    st.markdown(f"<div style='font-size:1.1rem;padding-top:2px'>{icon}</div>", unsafe_allow_html=True)
                with cols[1]:
                    st.markdown(f"""
                    <div style="padding-bottom:0.75rem;border-bottom:1px solid var(--border);margin-bottom:0.75rem">
                        <div style="display:flex;align-items:center;gap:0.5rem;margin-bottom:0.3rem">
                            <span style="font-weight:600;font-size:0.93rem;color:var(--text)">{item['name']}</span>
                            {sev_tag}
                        </div>
                        <div style="font-size:0.83rem;color:var(--muted);margin-bottom:0.35rem">{item['description']}</div>
                        <div style="font-size:0.82rem;">
                            <span style="color:var(--subtle)">Value: </span>
                            <code style="background:var(--surface2);padding:2px 6px;border-radius:5px;font-size:0.78rem;color:var(--cyan)">{item['value'] or '—'}</code>
                        </div>
                        <div style="font-size:0.82rem;margin-top:0.3rem">
                            <span style="color:var(--subtle)">Recommendation: </span>
                            <span style="color:{'var(--green)' if item['present'] else 'var(--amber)'}">{item['recommendation']}</span>
                        </div>
                    </div>
                    """, unsafe_allow_html=True)

    st.markdown('</div>', unsafe_allow_html=True)

    # ── Export ────────────────────────────────────────────
    st.markdown('<div class="cg-section">', unsafe_allow_html=True)
    st.markdown('<div class="cg-section-head">Export Report</div>', unsafe_allow_html=True)
    st.markdown('<div class="cg-section-sub">Download a professional client-ready PDF</div>', unsafe_allow_html=True)
    st.markdown('<div class="cg-card">', unsafe_allow_html=True)

    rep_col1, rep_col2 = st.columns([2, 1])
    with rep_col1:
        st.markdown("""
        <div style="font-size:0.9rem;color:var(--subtle);line-height:1.8;">
            The generated PDF includes:<br>
            &nbsp;• Cover page with client & analyst details<br>
            &nbsp;• Score card and TLS certificate summary<br>
            &nbsp;• Executive summary with key findings<br>
            &nbsp;• Full findings table with remediation guidance<br>
            &nbsp;• Scope disclaimer for client delivery
        </div>
        """, unsafe_allow_html=True)
    with rep_col2:
        pdf_bytes = build_pdf(scan, client_name or "Sample Client", user["name"])
        st.download_button(
            "⬇  Download PDF Report",
            data=pdf_bytes,
            file_name=f"cyberguard_review_{scan['hostname']}.pdf",
            mime="application/pdf",
            use_container_width=True,
        )
        st.caption("Suitable for portfolio, internal review, and authorized client delivery.")

    st.markdown('</div></div>', unsafe_allow_html=True)

# ============================================================
# FOOTER
# ============================================================
st.markdown("""
<div class="cg-footer">
    <span>CyberGuard v2 &nbsp;·&nbsp; Defensive security reviews by <b>Pamupro Cyber</b></span>
    <span>⚠ Authorized use only — do not scan websites without permission</span>
</div>
""", unsafe_allow_html=True)
