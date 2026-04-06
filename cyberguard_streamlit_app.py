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
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

# =====================================
# PAGE SETUP
# =====================================
st.set_page_config(page_title="CyberGuard SaaS", page_icon="🛡️", layout="wide")

st.markdown(
    """
    <style>
    .stApp {
        background:
            radial-gradient(circle at top right, rgba(56,189,248,0.12), transparent 22%),
            radial-gradient(circle at top left, rgba(168,85,247,0.10), transparent 20%),
            linear-gradient(180deg, #050816 0%, #0b1120 100%);
        color: #e5eefc;
    }
    .block-container {
        padding-top: 1.5rem;
        padding-bottom: 2rem;
        max-width: 1200px;
    }
    h1, h2, h3, h4 {
        color: #f8fbff;
        letter-spacing: -0.02em;
    }
    .hero-card, .soft-card {
        border: 1px solid rgba(148, 163, 184, 0.16);
        background: linear-gradient(180deg, rgba(15,23,42,0.82), rgba(15,23,42,0.66));
        backdrop-filter: blur(12px);
        border-radius: 22px;
        padding: 1.2rem 1.25rem;
        box-shadow: 0 10px 40px rgba(2, 6, 23, 0.28);
    }
    .hero-title {
        font-size: 2.3rem;
        font-weight: 700;
        line-height: 1.05;
        margin-bottom: 0.4rem;
    }
    .hero-sub {
        font-size: 1.02rem;
        color: #cbd5e1;
        margin-bottom: 0;
    }
    .pill {
        display: inline-block;
        font-size: 0.82rem;
        color: #93c5fd;
        background: rgba(59,130,246,0.10);
        border: 1px solid rgba(59,130,246,0.18);
        border-radius: 999px;
        padding: 0.3rem 0.6rem;
        margin-right: 0.4rem;
        margin-bottom: 0.35rem;
    }
    .stat-card {
        border: 1px solid rgba(148, 163, 184, 0.14);
        background: rgba(15,23,42,0.72);
        border-radius: 18px;
        padding: 1rem;
        min-height: 108px;
    }
    .stat-label {
        color: #94a3b8;
        font-size: 0.82rem;
        margin-bottom: 0.25rem;
    }
    .stat-value {
        color: #f8fbff;
        font-size: 1.5rem;
        font-weight: 700;
    }
    .section-label {
        color: #7dd3fc;
        font-size: 0.82rem;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        margin-bottom: 0.45rem;
    }
    .risk-strong { color: #34d399; font-weight: 700; }
    .risk-moderate { color: #fbbf24; font-weight: 700; }
    .risk-weak { color: #fb7185; font-weight: 700; }
    </style>
    """,
    unsafe_allow_html=True,
)

DB_FILE = "cyberguard_users.db"
TIMEOUT = 8

PRIMARY_HEADERS = {
    "Strict-Transport-Security": {
        "weight": 14,
        "severity": "High",
        "desc": "Forces HTTPS in supported browsers.",
        "advice": "Enable HSTS with an appropriate max-age once HTTPS is fully enforced.",
    },
    "Content-Security-Policy": {
        "weight": 16,
        "severity": "High",
        "desc": "Helps reduce script injection and XSS exposure.",
        "advice": "Define a restrictive Content-Security-Policy tailored to the app.",
    },
    "X-Frame-Options": {
        "weight": 8,
        "severity": "Medium",
        "desc": "Helps reduce clickjacking risk.",
        "advice": "Set X-Frame-Options to DENY or SAMEORIGIN.",
    },
    "X-Content-Type-Options": {
        "weight": 8,
        "severity": "Medium",
        "desc": "Prevents MIME sniffing in browsers.",
        "advice": "Set X-Content-Type-Options to nosniff.",
    },
    "Referrer-Policy": {
        "weight": 6,
        "severity": "Low",
        "desc": "Controls how much referrer information is shared.",
        "advice": "Use a strict Referrer-Policy, such as strict-origin-when-cross-origin.",
    },
    "Permissions-Policy": {
        "weight": 6,
        "severity": "Low",
        "desc": "Restricts access to browser features.",
        "advice": "Define a Permissions-Policy based on application needs.",
    },
}

OPTIONAL_HEADERS = [
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
    "Cross-Origin-Embedder-Policy",
]

SAFE_COMMON_PATHS = [
    "/robots.txt",
    "/security.txt",
    "/.well-known/security.txt",
    "/sitemap.xml",
]


# =====================================
# DATABASE / AUTH
# =====================================
def get_db_connection():
    return sqlite3.connect(DB_FILE, check_same_thread=False)


def init_db():
    with closing(get_db_connection()) as conn:
        cur = conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.commit()


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def create_user(name: str, email: str, password: str) -> tuple[bool, str]:
    try:
        with closing(get_db_connection()) as conn:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO users (name, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
                (name.strip(), email.strip().lower(), hash_password(password), datetime.utcnow().isoformat()),
            )
            conn.commit()
        return True, "Account created successfully."
    except sqlite3.IntegrityError:
        return False, "That email is already registered."


def authenticate_user(email: str, password: str) -> tuple[bool, dict | None]:
    with closing(get_db_connection()) as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT id, name, email FROM users WHERE email = ? AND password_hash = ?",
            (email.strip().lower(), hash_password(password)),
        )
        row = cur.fetchone()
        if row:
            return True, {"id": row[0], "name": row[1], "email": row[2]}
    return False, None


# =====================================
# SCANNING HELPERS
# =====================================
def normalize_url(raw: str) -> str:
    raw = raw.strip()
    if not raw:
        return ""
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw
    return raw


def extract_hostname(url: str) -> str:
    return urlparse(url).hostname or ""


def fetch_response(url: str) -> requests.Response:
    headers = {
        "User-Agent": "CyberGuard/1.0 (Authorized Defensive Review Only)"
    }
    return requests.get(url, timeout=TIMEOUT, headers=headers, allow_redirects=True)


def get_ssl_info(hostname: str, port: int = 443) -> dict:
    result = {
        "enabled": False,
        "issuer": None,
        "subject": None,
        "valid_to": None,
        "days_remaining": None,
        "error": None,
    }
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as secure_sock:
                cert = secure_sock.getpeercert()
                result["enabled"] = True
                issuer = dict(x[0] for x in cert.get("issuer", []))
                subject = dict(x[0] for x in cert.get("subject", []))
                result["issuer"] = issuer.get("organizationName") or str(issuer)
                result["subject"] = subject.get("commonName") or str(subject)
                valid_to = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                result["valid_to"] = valid_to
                result["days_remaining"] = (valid_to.replace(tzinfo=timezone.utc) - datetime.now(timezone.utc)).days
    except Exception as exc:
        result["error"] = str(exc)
    return result


def assess_protocol(input_url: str, final_url: str) -> list[dict]:
    findings = []
    findings.append(
        {
            "name": "HTTPS on initial URL",
            "present": input_url.startswith("https://"),
            "severity": "High",
            "weight": 14,
            "value": input_url,
            "description": "Checks whether the supplied target starts with HTTPS.",
            "recommendation": "Ensure public traffic starts on HTTPS.",
        }
    )
    findings.append(
        {
            "name": "HTTPS on final destination",
            "present": final_url.startswith("https://"),
            "severity": "High",
            "weight": 14,
            "value": final_url,
            "description": "Checks whether the final landing page uses HTTPS.",
            "recommendation": "Redirect all traffic to HTTPS.",
        }
    )
    return findings


def assess_security_headers(resp: requests.Response) -> list[dict]:
    findings = []
    for header, meta in PRIMARY_HEADERS.items():
        findings.append(
            {
                "name": header,
                "present": header in resp.headers,
                "severity": "Info" if header in resp.headers else meta["severity"],
                "weight": meta["weight"],
                "value": resp.headers.get(header, ""),
                "description": meta["desc"],
                "recommendation": "Configured" if header in resp.headers else meta["advice"],
            }
        )
    for header in OPTIONAL_HEADERS:
        findings.append(
            {
                "name": header,
                "present": header in resp.headers,
                "severity": "Info" if header in resp.headers else "Low",
                "weight": 3,
                "value": resp.headers.get(header, ""),
                "description": "Additional isolation and browser hardening header.",
                "recommendation": "Configured" if header in resp.headers else f"Consider adding {header} if compatible with the app.",
            }
        )
    return findings


def assess_cookies(resp: requests.Response) -> list[dict]:
    findings = []
    cookie_headers = resp.raw.headers.get_all("Set-Cookie") if hasattr(resp.raw.headers, "get_all") else []
    if not cookie_headers:
        findings.append(
            {
                "name": "Cookies observed",
                "present": True,
                "severity": "Info",
                "weight": 0,
                "value": "No Set-Cookie headers observed",
                "description": "No cookies were observed in this response.",
                "recommendation": "No action required unless the application should issue session cookies.",
            }
        )
        return findings

    for idx, cookie in enumerate(cookie_headers, start=1):
        low = cookie.lower()
        missing = []
        if "secure" not in low:
            missing.append("Secure")
        if "httponly" not in low:
            missing.append("HttpOnly")
        if "samesite" not in low:
            missing.append("SameSite")
        findings.append(
            {
                "name": f"Cookie #{idx} flags",
                "present": len(missing) == 0,
                "severity": "Info" if len(missing) == 0 else "Medium",
                "weight": 8,
                "value": cookie,
                "description": "Checks whether cookies include core defensive flags.",
                "recommendation": "Configured" if len(missing) == 0 else f"Add missing flags: {', '.join(missing)}.",
            }
        )
    return findings


def assess_info_disclosure(resp: requests.Response) -> list[dict]:
    findings = []
    for header_name, label in [("Server", "Server header exposure"), ("X-Powered-By", "X-Powered-By exposure")]:
        exposed = resp.headers.get(header_name)
        findings.append(
            {
                "name": label,
                "present": not bool(exposed),
                "severity": "Info" if not exposed else "Low",
                "weight": 5,
                "value": exposed or "Not exposed",
                "description": "Checks whether platform details are disclosed in headers.",
                "recommendation": "Configured" if not exposed else f"Minimize or remove {header_name} disclosure in production.",
            }
        )
    return findings


def assess_safe_paths(base_url: str) -> list[dict]:
    findings = []
    session = requests.Session()
    headers = {"User-Agent": "CyberGuard/1.0 (Authorized Defensive Review Only)"}
    for path in SAFE_COMMON_PATHS:
        full_url = urljoin(base_url, path)
        try:
            resp = session.get(full_url, timeout=4, headers=headers, allow_redirects=True)
            present = resp.status_code == 200
            findings.append(
                {
                    "name": f"{path} availability",
                    "present": present,
                    "severity": "Info" if present else "Low",
                    "weight": 3,
                    "value": f"HTTP {resp.status_code}",
                    "description": "Checks for commonly expected public security/discovery files.",
                    "recommendation": "Present" if present else f"Consider publishing {path} where appropriate.",
                }
            )
        except Exception:
            findings.append(
                {
                    "name": f"{path} availability",
                    "present": False,
                    "severity": "Low",
                    "weight": 3,
                    "value": "Unreachable",
                    "description": "Checks for commonly expected public security/discovery files.",
                    "recommendation": f"Consider publishing {path} where appropriate.",
                }
            )
    return findings


def calculate_score(findings: list[dict], ssl_info: dict) -> tuple[int, str]:
    max_score = sum(item["weight"] for item in findings if item["weight"] > 0) + 10
    earned = sum(item["weight"] for item in findings if item["present"] and item["weight"] > 0)

    if ssl_info.get("enabled"):
        days = ssl_info.get("days_remaining")
        if days is None:
            earned += 6
        elif days < 0:
            earned += 0
        elif days < 15:
            earned += 3
        elif days < 45:
            earned += 6
        else:
            earned += 10

    score = round((earned / max_score) * 100) if max_score else 0
    if score >= 85:
        return score, "Strong"
    if score >= 70:
        return score, "Moderate"
    if score >= 50:
        return score, "Needs Improvement"
    return score, "High Risk"


def summarize_findings(findings: list[dict], ssl_info: dict) -> list[str]:
    points = []
    important = [f["name"] for f in findings if not f["present"] and f["severity"] in ["High", "Medium"]]
    if important:
        points.append("Priority improvements identified: " + ", ".join(important[:4]) + ".")
    if ssl_info.get("enabled"):
        days = ssl_info.get("days_remaining")
        if days is not None and days < 30:
            points.append(f"TLS certificate expires soon with {days} days remaining.")
    if not points:
        points.append("No major defensive configuration issues were identified in the reviewed checks.")
    return points


def run_scan(url: str) -> dict:
    target = normalize_url(url)
    hostname = extract_hostname(target)
    response = fetch_response(target)
    ssl_info = get_ssl_info(hostname) if hostname else {"enabled": False, "error": "No hostname"}

    findings = []
    findings.extend(assess_protocol(target, response.url))
    findings.extend(assess_security_headers(response))
    findings.extend(assess_cookies(response))
    findings.extend(assess_info_disclosure(response))
    findings.extend(assess_safe_paths(response.url))

    score, rating = calculate_score(findings, ssl_info)

    return {
        "input_url": target,
        "final_url": response.url,
        "hostname": hostname,
        "status_code": response.status_code,
        "ssl_info": ssl_info,
        "findings": findings,
        "score": score,
        "rating": rating,
        "summary": summarize_findings(findings, ssl_info),
        "scanned_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
    }


# =====================================
# PDF REPORT
# =====================================
def build_pdf_report(scan_result: dict, company_name: str, analyst_name: str) -> bytes:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=32, leftMargin=32, topMargin=32, bottomMargin=28)
    styles = getSampleStyleSheet()
    story = []

    title = f"CyberGuard Security Review Report"
    story.append(Paragraph(title, styles["Title"]))
    story.append(Spacer(1, 12))
    story.append(Paragraph(f"<b>Client:</b> {company_name}", styles["Normal"]))
    story.append(Paragraph(f"<b>Target:</b> {scan_result['input_url']}", styles["Normal"]))
    story.append(Paragraph(f"<b>Analyst:</b> {analyst_name}", styles["Normal"]))
    story.append(Paragraph(f"<b>Reviewed At:</b> {scan_result['scanned_at']}", styles["Normal"]))
    story.append(Spacer(1, 12))

    summary_table = Table(
        [
            ["Overall Score", f"{scan_result['score']}/100"],
            ["Risk Rating", scan_result["rating"]],
            ["HTTP Status", str(scan_result["status_code"])],
            ["Final URL", scan_result["final_url"]],
        ],
        colWidths=[130, 360],
    )
    summary_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#0f172a")),
                ("PADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )
    story.append(summary_table)
    story.append(Spacer(1, 16))

    story.append(Paragraph("Executive Summary", styles["Heading2"]))
    for point in scan_result["summary"]:
        story.append(Paragraph(f"• {point}", styles["Normal"]))
    story.append(Spacer(1, 12))

    story.append(Paragraph("Detailed Findings", styles["Heading2"]))
    table_data = [["Finding", "Severity", "Status", "Recommendation"]]
    for item in scan_result["findings"]:
        table_data.append([
            item["name"],
            item["severity"],
            "Present" if item["present"] else "Issue Observed",
            item["recommendation"],
        ])

    findings_table = Table(table_data, colWidths=[150, 70, 90, 200])
    findings_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#cbd5e1")),
                ("BACKGROUND", (0, 1), (-1, -1), colors.white),
                ("TEXTCOLOR", (0, 1), (-1, -1), colors.HexColor("#111827")),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("PADDING", (0, 0), (-1, -1), 6),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    story.append(findings_table)
    story.append(Spacer(1, 14))

    story.append(Paragraph("Scope Notice", styles["Heading2"]))
    story.append(
        Paragraph(
            "This review covers defensive web configuration checks only and is intended for authorized assessment, client demonstrations, and security awareness workflows.",
            styles["Normal"],
        )
    )

    doc.build(story)
    pdf_value = buffer.getvalue()
    buffer.close()
    return pdf_value


# =====================================
# UI HELPERS
# =====================================
def render_stat(label: str, value: str):
    st.markdown(
        f"""
        <div class='stat-card'>
            <div class='stat-label'>{label}</div>
            <div class='stat-value'>{value}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def rating_class(rating: str) -> str:
    if rating == "Strong":
        return "risk-strong"
    if rating == "Moderate":
        return "risk-moderate"
    return "risk-weak"


# =====================================
# APP STATE
# =====================================
init_db()
if "user" not in st.session_state:
    st.session_state.user = None
if "last_scan" not in st.session_state:
    st.session_state.last_scan = None


# =====================================
# AUTH UI
# =====================================
if st.session_state.user is None:
    st.markdown(
        """
        <div class='hero-card'>
            <div class='section-label'>CyberGuard Platform</div>
            <div class='hero-title'>Modern website security reviews for business teams</div>
            <p class='hero-sub'>A startup-style security review platform for authorised client assessments, portfolio demos, and lightweight website hardening reports.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.write("")
    left, right = st.columns(2)

    with left:
        st.markdown("<div class='soft-card'>", unsafe_allow_html=True)
        st.subheader("Sign In")
        login_email = st.text_input("Email", key="login_email")
        login_password = st.text_input("Password", type="password", key="login_password")
        if st.button("Log In", use_container_width=True):
            ok, user = authenticate_user(login_email, login_password)
            if ok:
                st.session_state.user = user
                st.rerun()
            else:
                st.error("Invalid login details.")
        st.markdown("</div>", unsafe_allow_html=True)

    with right:
        st.markdown("<div class='soft-card'>", unsafe_allow_html=True)
        st.subheader("Create Account")
        signup_name = st.text_input("Full Name", key="signup_name")
        signup_email = st.text_input("Work Email", key="signup_email")
        signup_password = st.text_input("Create Password", type="password", key="signup_password")
        if st.button("Create Account", use_container_width=True):
            if not signup_name or not signup_email or not signup_password:
                st.error("Please complete all fields.")
            elif len(signup_password) < 6:
                st.error("Use at least 6 characters for the password.")
            else:
                ok, msg = create_user(signup_name, signup_email, signup_password)
                if ok:
                    st.success(msg + " You can now sign in.")
                else:
                    st.error(msg)
        st.markdown("</div>", unsafe_allow_html=True)

    st.stop()


# =====================================
# MAIN APP
# =====================================
with st.sidebar:
    st.markdown(f"### Welcome, {st.session_state.user['name']}")
    st.caption(st.session_state.user["email"])
    st.write("Use CyberGuard only on websites you own or have explicit authorization to assess.")
    if st.button("Log Out", use_container_width=True):
        st.session_state.user = None
        st.session_state.last_scan = None
        st.rerun()

st.markdown(
    """
    <div class='hero-card'>
        <div class='section-label'>CyberGuard SaaS</div>
        <div class='hero-title'>Business-facing web security reviews with a client-ready finish</div>
        <p class='hero-sub'>Run streamlined defensive checks, generate polished PDF reports, and present your security work like a modern startup product.</p>
        <div style='margin-top:0.8rem;'>
            <span class='pill'>Client-ready PDF</span>
            <span class='pill'>Modern SaaS UI</span>
            <span class='pill'>Defensive web checks</span>
            <span class='pill'>Portfolio-ready</span>
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)

st.write("")
input_col, client_col = st.columns([1.2, 0.8])
with input_col:
    target_url = st.text_input("Website URL", placeholder="https://example.com")
with client_col:
    client_name = st.text_input("Client / Company Name", placeholder="Nexora Commerce Ltd")

scan_now = st.button("Run Security Review", type="primary")

if scan_now:
    if not target_url:
        st.error("Please enter a website URL.")
    else:
        try:
            with st.spinner("Reviewing website defensive controls..."):
                st.session_state.last_scan = run_scan(target_url)
            st.success("Review completed successfully.")
        except requests.exceptions.SSLError:
            st.error("SSL connection failed. Verify the target supports HTTPS correctly.")
        except requests.exceptions.ConnectionError:
            st.error("Unable to reach the target. Check the domain and try again.")
        except requests.exceptions.Timeout:
            st.error("The target did not respond in time.")
        except Exception as exc:
            st.error(f"Unexpected error: {exc}")

scan_result = st.session_state.last_scan
if scan_result:
    st.write("")
    m1, m2, m3, m4 = st.columns(4)
    with m1:
        render_stat("Overall Score", f"{scan_result['score']}/100")
    with m2:
        render_stat("HTTP Status", str(scan_result["status_code"]))
    with m3:
        render_stat("TLS", "Enabled" if scan_result["ssl_info"].get("enabled") else "Unavailable")
    with m4:
        st.markdown(
            f"""
            <div class='stat-card'>
                <div class='stat-label'>Risk Rating</div>
                <div class='stat-value {rating_class(scan_result['rating'])}'>{scan_result['rating']}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.write("")
    left, right = st.columns([1.15, 0.85])

    with left:
        st.markdown("<div class='soft-card'>", unsafe_allow_html=True)
        st.markdown("<div class='section-label'>Executive Summary</div>", unsafe_allow_html=True)
        st.subheader("Key observations")
        for bullet in scan_result["summary"]:
            st.write(f"- {bullet}")
        st.write("")
        st.write(f"**Input URL:** {scan_result['input_url']}")
        st.write(f"**Final URL:** {scan_result['final_url']}")
        st.write(f"**Hostname:** {scan_result['hostname']}")
        st.write(f"**Reviewed At:** {scan_result['scanned_at']}")
        st.markdown("</div>", unsafe_allow_html=True)

    with right:
        st.markdown("<div class='soft-card'>", unsafe_allow_html=True)
        st.markdown("<div class='section-label'>TLS Overview</div>", unsafe_allow_html=True)
        ssl_info = scan_result["ssl_info"]
        if ssl_info.get("enabled"):
            st.write(f"**Issuer:** {ssl_info.get('issuer')}")
            st.write(f"**Subject:** {ssl_info.get('subject')}")
            st.write(f"**Days Remaining:** {ssl_info.get('days_remaining')}")
            st.write(f"**Valid To:** {ssl_info.get('valid_to')}")
        else:
            st.warning(f"TLS details unavailable: {ssl_info.get('error')}")
        st.markdown("</div>", unsafe_allow_html=True)

    st.write("")
    st.markdown("<div class='soft-card'>", unsafe_allow_html=True)
    st.markdown("<div class='section-label'>Detailed Findings</div>", unsafe_allow_html=True)
    st.subheader("Defensive checks reviewed")
    for item in scan_result["findings"]:
        icon = "✅" if item["present"] else "⚠️"
        with st.expander(f"{icon} {item['name']} — {item['severity']}"):
            st.write(f"**Observed Value:** {item['value'] or 'N/A'}")
            st.write(f"**Details:** {item['description']}")
            st.write(f"**Recommendation:** {item['recommendation']}")
    st.markdown("</div>", unsafe_allow_html=True)

    st.write("")
    st.markdown("<div class='soft-card'>", unsafe_allow_html=True)
    st.markdown("<div class='section-label'>Client Deliverables</div>", unsafe_allow_html=True)
    st.subheader("Export report")
    pdf_bytes = build_pdf_report(
        scan_result,
        client_name or "Sample Client",
        st.session_state.user["name"],
    )
    st.download_button(
        "Download PDF Report",
        data=pdf_bytes,
        file_name="cyberguard_security_review.pdf",
        mime="application/pdf",
        use_container_width=True,
    )
    st.caption("This report is suitable for portfolio demonstrations, internal reviews, and authorised client-facing presentations.")
    st.markdown("</div>", unsafe_allow_html=True)

st.write("")
st.caption("CyberGuard by Pamupro Cyber — authorized defensive website reviews only.")
