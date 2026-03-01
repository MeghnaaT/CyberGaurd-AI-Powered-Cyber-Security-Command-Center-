# 🛡️ AI-Powered Cyber Security Command Center

A Flask-based cybersecurity toolkit with a unified dashboard, modular analyzers (URL, file, IP/domain, email headers), and an integrated AI chat assistant.

---

## 📌 What This Project Does

This project provides practical, explainable security checks for common threat-hunting tasks:

- **URL Analyzer** for phishing-style URL heuristics, SSL checks, and WHOIS snippets
- **File Scanner** for static file inspection (hashes, magic signatures, entropy, threat rules)
- **IP / Domain Lookup** for DNS resolution + lightweight OSINT enrichment
- **Email Header Analyzer** for SPF/DKIM/DMARC risk scoring
- **Dashboard Summary** with recent scan history and aggregate threat score
- **AI Chat Assistant** (`/ask-ai`) with Gemini model auto-selection and safe fallback mode

It also retains educational legacy tools:

- `/analyze-phishing` (legacy heuristic endpoint)
- `/scan-file` (legacy compatibility wrapper)
- password strength checker
- phishing simulation and attack-log demos

---

## 🧱 Current Architecture

### Backend
- **Framework:** Flask + Flask-CORS
- **Main app:** `app.py`
- **Data store:** in-memory `scan_history` list (for dashboard/summary)
- **AI Integration:** `google.generativeai` with runtime model discovery via `genai.list_models()`

### Frontend
- **Template:** `templates/index.html` (panel-based pages)
- **Client:** `static/script.js` (async fetch calls + human-readable result renderers)
- **Styling:** `static/style.css` (glassmorphism, dark/light theme, global chatbot)
- **Extras:** Chart.js + jsPDF loaded from CDN for dashboard/reporting flows

---

## ✅ Features

## 1) URL Analyzer (`POST /api/url-analyzer`)
Checks:
- Long URL
- Too many dots/subdomains
- Suspicious TLDs (`.xyz`, `.top`, `.tk`, `.zip`, `.gq`, `.cf`)
- IP used as domain
- Abnormal ports
- SSL certificate validation (for HTTPS URLs)
- WHOIS lookup excerpt

Response includes: normalized URL, findings, risk score, verdict, SSL info, WHOIS details.

## 2) File Scanner (`POST /api/file-scanner`)
Checks:
- MD5 and SHA256 hashes
- File signature from magic bytes (JPEG/PNG/PDF/ZIP/EXE/ELF)
- Shannon entropy
- Risk rules for executables, high entropy, risky extensions, tiny unknown payloads

Response includes: signature, entropy, rule hits, threat score, and verdict.

## 3) IP / Domain Lookup (`POST /api/ip-lookup`)
Checks:
- IP validation or domain resolution
- DNS A/AAAA extraction for domains
- OSINT enrichment from `ip-api.com`
- Basic risk scoring signals

## 4) Email Header Analyzer (`POST /api/email-analyzer`)
Checks:
- Parses raw headers
- Reads `Authentication-Results`
- SPF / DKIM / DMARC pass/fail
- Reply-To mismatch heuristic
- Risk score + verdict

## 5) Dashboard Summary (`GET /api/dashboard-summary`)
Provides:
- module scan counts
- recent scans
- total scans
- computed final threat score

## 6) AI Assistant
- `GET /ai-status`: returns current model config status
- `POST /ask-ai`: answers cybersecurity questions
  - Uses Gemini model when available
  - Falls back gracefully if model is unavailable

---

## 🔌 API Reference (Quick)

### URL Analyzer
```bash
curl -X POST http://127.0.0.1:5000/api/url-analyzer \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.xyz:8080/login"}'
File Scanner
curl -X POST http://127.0.0.1:5000/api/file-scanner \
  -F "file=@/path/to/file.pdf"
IP / Domain Lookup
curl -X POST http://127.0.0.1:5000/api/ip-lookup \
  -H "Content-Type: application/json" \
  -d '{"indicator":"8.8.8.8"}'
Email Header Analyzer
curl -X POST http://127.0.0.1:5000/api/email-analyzer \
  -H "Content-Type: application/json" \
  -d '{"headers":"From: test@example.com\nAuthentication-Results: spf=pass dkim=pass dmarc=pass"}'
AI Chat
curl -X POST http://127.0.0.1:5000/ask-ai \
  -H "Content-Type: application/json" \
  -d '{"question":"What is phishing?"}'
🖥️ UI Notes
Dashboard and tools are served from:

/dashboard

/url-analyzer

/file-scanner

/ip-lookup

/email-analyzer

Theme toggle (dark/light) is persisted in localStorage

Chatbot widget is globally available in the UI

Tool outputs are rendered in human-readable format (not raw JSON dumps)

🚀 Local Setup
1) Create and activate virtual environment
macOS/Linux
python -m venv venv
source venv/bin/activate
Windows (PowerShell)
python -m venv venv
venv\Scripts\Activate.ps1
2) Install dependencies
pip install -r requirements.txt
3) Configure environment
Create a .env file in project root:

GEMINI_API_KEY=your_api_key_here
If GEMINI_API_KEY is not valid/available, chat still works in fallback mode.

4) Run
python app.py
Open: http://127.0.0.1:5000

📁 Important Files
app.py — Flask routes, analyzers, scoring, AI integration

templates/index.html — main UI structure

static/script.js — frontend behaviors + API calls + renderers

static/style.css — theme/glassmorphism/chat styles

requirements.txt — Python dependencies

⚠️ Security & Deployment Notes
This project is intended for learning/prototyping and controlled analysis workflows.

Flask debug server is not production-ready.

For production deployment, use a proper WSGI server + reverse proxy + TLS.

Add auth/rate limiting before exposing publicly.

WHOIS / OSINT lookups depend on external network availability.

📜 Disclaimer
This tool is for educational and authorized security analysis purposes only.
Use responsibly and only on data/systems you own or are permitted to test.

