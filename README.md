# ⚡ XSS Hunter Pro v2 — by zwanski

> Advanced web vulnerability scanner for authorized bug bounty testing. Built by a hunter, for hunters.

[![Streamlit](https://img.shields.io/badge/Streamlit-FF4B4B?style=for-the-badge&logo=streamlit&logoColor=white)](https://streamlit.io)
[![Python](https://img.shields.io/badge/Python-3.9+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)

![XSS Hunter Pro v2](https://img.shields.io/badge/version-2.0-00f0a0?style=flat-square)
![Modules](https://img.shields.io/badge/modules-8-blue?style=flat-square)
![Payloads](https://img.shields.io/badge/payloads-150+-red?style=flat-square)

---

## What is this?

A professional-grade web security scanner with an interactive Streamlit UI. Covers XSS (reflected, stored, DOM, blind), CORS misconfigurations, security header auditing, password reset ATO testing, and AI-powered analysis via OpenRouter.

**Not a toy scanner.** This is built from real bug bounty experience across HackerOne, Bugcrowd, and Bug Bounty Switzerland programs.

---

## Features

### 🎯 XSS Scanner
- **150+ payloads** across 10 categories (reflected, event handlers, SVG, attribute breakout, DOM, WAF bypass, template injection, blind OOB, polyglots)
- **8 reflection contexts** detected: script, event-handler, url-attribute, quoted-attribute, html-body, css, comment, partial
- **Smart payload mutation engine** — auto-generates WAF bypass variants when WAF is detected
- **Concurrent scanning** with configurable thread pool
- **Scope validator** — prevents accidental out-of-scope requests
- **Response diffing** — baseline comparison for accurate reflection detection

### 🛡️ Security Header Audit
- Content-Security-Policy analysis (unsafe-inline, unsafe-eval, data:, wildcards)
- CORS header inspection
- Cookie flag analysis (HttpOnly, Secure, SameSite)
- HSTS, X-Frame-Options, X-Content-Type-Options
- Actionable findings with severity ratings

### 🔗 CORS Misconfiguration Scanner
- Active origin reflection testing with 5 vectors
- Detects reflected origins with credentials (Critical)
- Null origin bypass detection
- Wildcard CORS identification

### 🔐 Password Reset ATO Module
- **Email parameter manipulation** (array injection, separator abuse, CRLF)
- **HTTP parameter pollution** (duplicate params, mixed arrays)
- **JSON key injection** (duplicate keys, nested objects, backup_email)
- **Host header poisoning** (X-Forwarded-Host, X-Original-Host, Forwarded)
- **Token reuse testing**
- **IDOR on reset endpoints** (user_id manipulation)
- **Rate limit bypass** (IP header spoofing)
- **Email canonicalization bypass** (plus addressing, dots, unicode homoglyphs)

### 🤖 AI Analysis (OpenRouter)
- AI-powered vulnerability analysis and exploitation guidance
- Smart payload suggestions based on detected context and WAF
- Report writing assistance
- Uses OpenRouter API (bring your own key)

### 🧬 Payload Lab
- Encoder/decoder (HTML entities, URL, double URL, base64, unicode, hex, charcode)
- Blind XSS builder with configurable exfiltration
- WAF bypass mutation generator
- Full searchable payload library

### 📊 Report Generator
- HackerOne format
- Bugcrowd format
- Bug Bounty Switzerland format
- Generic markdown
- JSON/CSV export

### 📖 Cheatsheet
- Context detection guide
- WAF evasion matrix
- CSP bypass strategies
- DOM XSS source-sink reference
- Report quality checklist

---

## Quick Start

### Install

```bash
git clone https://github.com/zwanski2019/xss-hunter-pro.git
cd xss-hunter-pro
pip install -r requirements.txt
```

### Run

```bash
streamlit run xss_hunter_v2.py
```

### Configure AI (Optional)

Set your OpenRouter API key via the sidebar or environment variable:

```bash
export OPENROUTER_API_KEY="sk-or-v1-your-key-here"
streamlit run xss_hunter_v2.py
```

---

## Usage

### Basic XSS Scan
1. Enter target URL with parameters: `https://target.com/search?q=test`
2. Select scan mode (Quick / Standard / Deep / Stealth)
3. Choose payload categories
4. Click **START SCAN**

### Password Reset ATO Testing
1. Go to **🔐 Reset ATO** in the sidebar
2. Enter the password reset endpoint URL
3. Set victim and attacker emails
4. Select test categories
5. Click **RUN TESTS**

### CORS Testing
1. Go to **🔗 CORS Checker**
2. Enter an API endpoint URL
3. Click **Test CORS**

### AI Analysis
1. Go to **🤖 AI Assist**
2. Enter your OpenRouter API key (or set env var)
3. Paste a finding or describe a scenario
4. Get exploitation guidance, payload suggestions, or report drafts

---

## Scan Modes

| Mode | What it does | Speed |
|------|-------------|-------|
| **Quick** | URL parameter fuzzing only | Fast |
| **Standard** | URL params + HTML form fuzzing | Medium |
| **Deep** | URL + Forms + Headers + Crawl + DOM analysis | Slow |
| **Stealth** | Deep + WAF bypass mutations + extra delay | Slowest |

---

## Tech Stack

- **Python 3.9+**
- **Streamlit** — Interactive web UI
- **Requests** — HTTP client
- **Pandas** — Data handling and export
- **OpenRouter API** — AI-powered analysis (optional)
- **Threading** — Concurrent scanning

---

## Project Structure

```
xss-hunter-pro/
├── xss_hunter_v2.py      # Main application
├── requirements.txt       # Dependencies
├── README.md             # This file
├── .env.example          # Environment variable template
└── LICENSE               # MIT License
```

---

## Responsible Use

This tool is designed for **authorized security testing only**. Before scanning any target:

- ✅ Ensure you have written authorization or the target is in a bug bounty program scope
- ✅ Use the scope validator to prevent out-of-scope requests
- ✅ Respect rate limits (configurable delay between requests)
- ✅ Add your bug bounty tracking header in Extra Headers
- ❌ Never scan targets without permission
- ❌ Never use findings for unauthorized access

---

## Author

**Mohamed Ibrahim** (zwanski)
- 🌐 [zwanski.bio](https://zwanski.bio)
- 🐛 [HackerOne](https://hackerone.com/zwanski)
- 🐛 [Bugcrowd](https://bugcrowd.com/zwanski)
- 🐛 [Bug Bounty Switzerland](https://bugbounty.ch)
- 🐙 [GitHub](https://github.com/zwanski2019)

---

## License

MIT — see [LICENSE](LICENSE) for details.
