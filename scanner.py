"""
CyberGuard – Website security scanner
Performs safe, defensive HTTP/TLS checks only.
"""

import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

import requests

TIMEOUT = 10
UA = "CyberGuard/2.0 (+https://cyberguard.app; authorized defensive review)"

PRIMARY_HEADERS: dict[str, dict] = {
    "Strict-Transport-Security": {
        "weight": 14,
        "severity": "High",
        "desc": "Forces browsers to use HTTPS for future requests, preventing SSL stripping attacks.",
        "advice": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
    },
    "Content-Security-Policy": {
        "weight": 16,
        "severity": "High",
        "desc": "Controls which resources the browser is allowed to load, dramatically reducing XSS risk.",
        "advice": "Define a restrictive CSP policy tailored to your application's needs.",
    },
    "X-Frame-Options": {
        "weight": 8,
        "severity": "Medium",
        "desc": "Prevents your pages from being embedded in iframes, blocking clickjacking attacks.",
        "advice": "Add: X-Frame-Options: DENY  (or SAMEORIGIN if framing is needed internally)",
    },
    "X-Content-Type-Options": {
        "weight": 8,
        "severity": "Medium",
        "desc": "Stops browsers from MIME-sniffing, preventing certain content-type confusion attacks.",
        "advice": "Add: X-Content-Type-Options: nosniff",
    },
    "Referrer-Policy": {
        "weight": 6,
        "severity": "Low",
        "desc": "Controls how much referrer information is included with requests.",
        "advice": "Add: Referrer-Policy: strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "weight": 6,
        "severity": "Low",
        "desc": "Restricts which browser features and APIs the page may access.",
        "advice": "Define a Permissions-Policy based on which browser APIs your app actually needs.",
    },
}

OPTIONAL_HEADERS = [
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
    "Cross-Origin-Embedder-Policy",
]

SAFE_PATHS = [
    "/robots.txt",
    "/security.txt",
    "/.well-known/security.txt",
    "/sitemap.xml",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _normalize(raw: str) -> str:
    raw = raw.strip()
    if raw and not raw.startswith(("http://", "https://")):
        raw = "https://" + raw
    return raw


def _hostname(url: str) -> str:
    return urlparse(url).hostname or ""


def _get(url: str, **kwargs) -> requests.Response:
    return requests.get(url, timeout=TIMEOUT, headers={"User-Agent": UA}, allow_redirects=True, **kwargs)


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------

def check_ssl(hostname: str, port: int = 443) -> dict:
    result: dict = {"enabled": False, "issuer": None, "subject": None,
                    "valid_to": None, "days_remaining": None, "error": None}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
        result["enabled"] = True
        issuer = dict(x[0] for x in cert.get("issuer", []))
        subject = dict(x[0] for x in cert.get("subject", []))
        result["issuer"] = issuer.get("organizationName") or str(issuer)
        result["subject"] = subject.get("commonName") or str(subject)
        valid_to = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        result["valid_to"] = valid_to.strftime("%Y-%m-%d")
        result["days_remaining"] = (valid_to.replace(tzinfo=timezone.utc) - datetime.now(timezone.utc)).days
    except Exception as exc:
        result["error"] = str(exc)
    return result


def check_protocol(input_url: str, final_url: str) -> list[dict]:
    return [
        {
            "category": "Protocol",
            "name": "HTTPS on input URL",
            "present": input_url.startswith("https://"),
            "severity": "High",
            "weight": 14,
            "value": input_url,
            "description": "Verifies the supplied URL uses HTTPS rather than plain HTTP.",
            "recommendation": "Use HTTPS:// as the canonical starting point for all traffic.",
        },
        {
            "category": "Protocol",
            "name": "HTTPS on final destination",
            "present": final_url.startswith("https://"),
            "severity": "High",
            "weight": 14,
            "value": final_url,
            "description": "Verifies the page the browser ultimately lands on is served over HTTPS.",
            "recommendation": "Ensure all HTTP requests are permanently redirected (301) to HTTPS.",
        },
    ]


def check_headers(resp: requests.Response) -> list[dict]:
    findings = []
    for header, meta in PRIMARY_HEADERS.items():
        present = header in resp.headers
        findings.append({
            "category": "Security Headers",
            "name": header,
            "present": present,
            "severity": "Info" if present else meta["severity"],
            "weight": meta["weight"],
            "value": resp.headers.get(header, "—"),
            "description": meta["desc"],
            "recommendation": "✓ Configured" if present else meta["advice"],
        })
    for header in OPTIONAL_HEADERS:
        present = header in resp.headers
        findings.append({
            "category": "Security Headers",
            "name": header,
            "present": present,
            "severity": "Info" if present else "Low",
            "weight": 3,
            "value": resp.headers.get(header, "—"),
            "description": "Additional cross-origin isolation header for defence-in-depth.",
            "recommendation": "✓ Configured" if present else f"Consider adding {header} for additional isolation.",
        })
    return findings


def check_cookies(resp: requests.Response) -> list[dict]:
    raw_headers = resp.raw.headers.get_all("Set-Cookie") if hasattr(resp.raw.headers, "get_all") else []
    if not raw_headers:
        return [{
            "category": "Cookies",
            "name": "Cookie presence",
            "present": True,
            "severity": "Info",
            "weight": 0,
            "value": "No Set-Cookie headers in this response",
            "description": "No cookies were set in the initial response.",
            "recommendation": "No action required for this response.",
        }]
    findings = []
    for idx, cookie in enumerate(raw_headers, 1):
        low = cookie.lower()
        missing = [f for f, kw in [("Secure", "secure"), ("HttpOnly", "httponly"), ("SameSite", "samesite")] if kw not in low]
        findings.append({
            "category": "Cookies",
            "name": f"Cookie #{idx} security flags",
            "present": len(missing) == 0,
            "severity": "Info" if not missing else "Medium",
            "weight": 8,
            "value": cookie[:120] + ("…" if len(cookie) > 120 else ""),
            "description": "Cookies lacking Secure/HttpOnly/SameSite flags can be stolen or forged.",
            "recommendation": "✓ All flags present" if not missing else f"Add missing flags: {', '.join(missing)}",
        })
    return findings


def check_disclosure(resp: requests.Response) -> list[dict]:
    findings = []
    for h, label in [("Server", "Server header disclosure"), ("X-Powered-By", "X-Powered-By disclosure")]:
        val = resp.headers.get(h)
        findings.append({
            "category": "Information Disclosure",
            "name": label,
            "present": not bool(val),
            "severity": "Info" if not val else "Low",
            "weight": 5,
            "value": val or "Not exposed",
            "description": "Exposing server/framework versions helps attackers select targeted exploits.",
            "recommendation": "✓ Not exposed" if not val else f"Remove or genericise the {h} header in production.",
        })
    return findings


def check_paths(base_url: str) -> list[dict]:
    session = requests.Session()
    findings = []
    for path in SAFE_PATHS:
        url = urljoin(base_url, path)
        try:
            r = session.get(url, timeout=5, headers={"User-Agent": UA}, allow_redirects=True)
            ok = r.status_code == 200
            findings.append({
                "category": "Security Files",
                "name": f"{path}",
                "present": ok,
                "severity": "Info" if ok else "Low",
                "weight": 3,
                "value": f"HTTP {r.status_code}",
                "description": "Standard files that aid security researchers and automated scanners.",
                "recommendation": "✓ Present" if ok else f"Consider publishing {path} to aid responsible disclosure.",
            })
        except Exception:
            findings.append({
                "category": "Security Files",
                "name": f"{path}",
                "present": False,
                "severity": "Low",
                "weight": 3,
                "value": "Unreachable",
                "description": "Standard files that aid security researchers and automated scanners.",
                "recommendation": f"Consider publishing {path} to aid responsible disclosure.",
            })
    return findings


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

def _score(findings: list[dict], ssl_info: dict) -> tuple[int, str]:
    max_pts = sum(f["weight"] for f in findings if f["weight"] > 0) + 10
    earned = sum(f["weight"] for f in findings if f["present"] and f["weight"] > 0)
    if ssl_info.get("enabled"):
        days = ssl_info.get("days_remaining")
        earned += 10 if (days is None or days >= 45) else 6 if days >= 15 else 3 if days >= 0 else 0
    score = round(earned / max_pts * 100) if max_pts else 0
    if score >= 85:
        return score, "Strong"
    if score >= 70:
        return score, "Moderate"
    if score >= 50:
        return score, "Needs Improvement"
    return score, "High Risk"


def _summary(findings: list[dict], ssl_info: dict) -> list[str]:
    points = []
    critical = [f["name"] for f in findings if not f["present"] and f["severity"] == "High"]
    medium = [f["name"] for f in findings if not f["present"] and f["severity"] == "Medium"]
    if critical:
        points.append(f"High-severity gaps detected: {', '.join(critical[:3])}.")
    if medium:
        points.append(f"Medium-severity issues: {', '.join(medium[:3])}.")
    days = ssl_info.get("days_remaining")
    if ssl_info.get("enabled") and days is not None and days < 30:
        points.append(f"TLS certificate expires in {days} days — renew promptly.")
    if not points:
        points.append("No critical defensive configuration issues were identified.")
    return points


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def run_scan(url: str) -> dict:
    target = _normalize(url)
    resp = _get(target)
    hostname = _hostname(target)
    ssl_info = check_ssl(hostname) if hostname else {"enabled": False, "error": "No hostname"}

    findings: list[dict] = []
    findings += check_protocol(target, resp.url)
    findings += check_headers(resp)
    findings += check_cookies(resp)
    findings += check_disclosure(resp)
    findings += check_paths(resp.url)

    score, rating = _score(findings, ssl_info)

    return {
        "input_url": target,
        "final_url": resp.url,
        "hostname": hostname,
        "status_code": resp.status_code,
        "ssl_info": ssl_info,
        "findings": findings,
        "score": score,
        "rating": rating,
        "summary": _summary(findings, ssl_info),
        "scanned_at": datetime.utcnow().strftime("%d %b %Y, %H:%M UTC"),
    }
