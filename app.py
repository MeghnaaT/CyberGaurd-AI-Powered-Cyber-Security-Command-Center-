from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv

import datetime as dt
import hashlib
import ipaddress
import json
import logging
import math
import os
import re
import socket
import ssl
from collections import Counter
from difflib import SequenceMatcher
from email.parser import Parser
from urllib.parse import urlparse
from urllib.request import urlopen

import google.generativeai as genai

load_dotenv()
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

app = Flask(__name__)
CORS(app)

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

logging.basicConfig(level=logging.INFO, format="%(asctime)s — %(levelname)s — %(message)s")
logger = logging.getLogger(__name__)

SUSPICIOUS_TLDS = {".xyz", ".top", ".tk", ".zip", ".gq", ".cf"}
MAGIC_SIGNATURES = {
    b"\xFF\xD8\xFF": "JPEG Image",
    b"\x89PNG": "PNG Image",
    b"%PDF": "PDF Document",
    b"PK\x03\x04": "ZIP Archive",
    b"MZ": "Windows Executable",
    b"\x7fELF": "ELF Executable",
}

scan_history = []
POPULAR_BRANDS = [
    "google.com",
    "microsoft.com",
    "amazon.com",
    "facebook.com",
    "instagram.com",
    "paypal.com",
    "apple.com",
    "netflix.com",
]


def push_history(module: str, score: int, target: str):
    scan_history.append(
        {
            "module": module,
            "score": int(score),
            "target": target,
            "timestamp": dt.datetime.utcnow().isoformat() + "Z",
        }
    )
    if len(scan_history) > 100:
        del scan_history[:-100]


def normalize_url(url: str) -> str:
    url = (url or "").strip()
    if not re.match(r"^https?://", url, re.I):
        url = "http://" + url
    return url


def detect_type_from_header(data: bytes) -> str:
    header = data[:8]
    for sig, name in MAGIC_SIGNATURES.items():
        if header.startswith(sig):
            return name
    return "Unknown"


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def lookup_whois(domain: str) -> dict:
    result = {"domain": domain, "raw": "", "server": "whois.iana.org"}
    try:
        with socket.create_connection(("whois.iana.org", 43), timeout=4) as s:
            s.sendall((domain + "\r\n").encode())
            data = s.recv(4096).decode("utf-8", errors="ignore")
        refer_match = re.search(r"refer:\s*(\S+)", data, re.I)
        refer = refer_match.group(1) if refer_match else None
        if refer:
            result["server"] = refer
            with socket.create_connection((refer, 43), timeout=5) as s2:
                s2.sendall((domain + "\r\n").encode())
                chunks = []
                while True:
                    chunk = s2.recv(4096)
                    if not chunk:
                        break
                    chunks.append(chunk)
            result["raw"] = b"".join(chunks).decode("utf-8", errors="ignore")[:5000]
        else:
            result["raw"] = data
    except Exception as exc:
        result["error"] = str(exc)
    return result


def ssl_certificate_check(hostname: str) -> dict:
    info = {"hostname": hostname, "valid": False}
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=4) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
        not_after = cert.get("notAfter")
        expiry = dt.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z") if not_after else None
        days_left = (expiry - dt.datetime.utcnow()).days if expiry else None
        info.update({"valid": True, "issuer": cert.get("issuer"), "days_left": days_left})
    except Exception as exc:
        info["error"] = str(exc)
    return info


def compute_final_threat_score(scores: list[int]) -> int:
    if not scores:
        return 0
    weighted = sum(scores) / len(scores)
    return min(100, int(round(weighted)))


def legacy_phishing_score(text: str) -> tuple[str, int, list[str]]:
    score = 0
    reasons = []
    lowered = text.lower()

    if len(text) > 75:
        score += 10
        reasons.append("Very long URL/message")
    if "@" in text:
        score += 20
        reasons.append("Contains @ symbol")
    if text.count(".") > 3:
        score += 10
        reasons.append("Too many subdomains")
    if re.search(r"\d{3,}", text):
        score += 10
        reasons.append("Contains long number sequences")

    for tld in SUSPICIOUS_TLDS:
        if lowered.endswith(tld):
            score += 15
            reasons.append(f"Suspicious TLD: {tld}")

    hostname = urlparse(normalize_url(text)).hostname or ""
    for legit in POPULAR_BRANDS:
        similarity = SequenceMatcher(None, hostname, legit).ratio()
        if similarity > 0.85 and hostname != legit:
            score += 35
            reasons.append(f"Looks like fake version of {legit}")

    verdict = "Likely Safe ✅"
    if score >= 60:
        verdict = "High Risk 🚩 Likely Phishing"
    elif score >= 30:
        verdict = "Suspicious ⚠️"
    return verdict, score, reasons


@app.route("/")
def home():
    return render_template("index.html", active_page="dashboard")


@app.route("/info")
def info_page():
    return render_template("info.html")


@app.route("/about")
def about_page():
    return render_template("about.html")


@app.route("/dashboard")
def dashboard_page():
    return render_template("index.html", active_page="dashboard")


@app.route("/url-analyzer")
def url_page():
    return render_template("index.html", active_page="url")


@app.route("/file-scanner")
def file_page():
    return render_template("index.html", active_page="file")


@app.route("/ip-lookup")
def ip_page():
    return render_template("index.html", active_page="ip")


@app.route("/email-analyzer")
def email_page():
    return render_template("index.html", active_page="email")


@app.route("/api/url-analyzer", methods=["POST"])
def api_url_analyzer():
    data = request.get_json(force=True, silent=True) or {}
    raw_url = data.get("url", "")
    if not raw_url.strip():
        return jsonify({"error": "URL is required"}), 400

    url = normalize_url(raw_url)
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    port = parsed.port

    score = 0
    findings = []

    if len(url) > 75:
        score += 15
        findings.append("Long URL detected")
    if url.count(".") > 4:
        score += 10
        findings.append("Too many dots/subdomains")
    if any(hostname.endswith(tld) for tld in SUSPICIOUS_TLDS):
        score += 20
        findings.append("Suspicious TLD")
    try:
        ipaddress.ip_address(hostname)
        score += 20
        findings.append("IP address used as domain")
    except Exception:
        pass
    if port and port not in (80, 443):
        score += 15
        findings.append(f"Abnormal port: {port}")

    ssl_info = ssl_certificate_check(hostname) if parsed.scheme == "https" and hostname else {"valid": False}
    if parsed.scheme == "https" and not ssl_info.get("valid"):
        score += 15
        findings.append("SSL certificate verification failed")

    whois = lookup_whois(hostname) if hostname else {"error": "No domain extracted"}
    verdict = "Low Risk" if score < 30 else "Medium Risk" if score < 60 else "High Risk"

    push_history("url", score, hostname or url)
    return jsonify(
        {
            "url": url,
            "hostname": hostname,
            "port": port,
            "findings": findings,
            "risk_score": score,
            "verdict": verdict,
            "ssl": ssl_info,
            "whois_excerpt": whois.get("raw", "")[:600],
            "whois_server": whois.get("server"),
            "whois_error": whois.get("error"),
        }
    )


@app.route("/api/file-scanner", methods=["POST"])
def api_file_scanner():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    uploaded = request.files["file"]
    if not uploaded.filename:
        return jsonify({"error": "Invalid file name"}), 400

    path = os.path.join(app.config["UPLOAD_FOLDER"], uploaded.filename)
    uploaded.save(path)
    data = open(path, "rb").read()

    md5_hash = hashlib.md5(data).hexdigest()
    sha256_hash = hashlib.sha256(data).hexdigest()
    signature = detect_type_from_header(data)
    entropy = round(shannon_entropy(data), 3)

    rules = []
    score = 0
    if signature in {"Windows Executable", "ELF Executable"}:
        score += 35
        rules.append("Executable binary detected")
    if entropy > 7.2:
        score += 25
        rules.append("High entropy (possible packed/encrypted payload)")
    if uploaded.filename.lower().endswith((".exe", ".js", ".bat", ".scr")):
        score += 20
        rules.append("Potentially dangerous extension")
    if len(data) < 120 and signature == "Unknown":
        score += 10
        rules.append("Tiny unknown file payload")

    verdict = "Clean" if score < 30 else "Suspicious" if score < 60 else "Malicious"
    push_history("file", score, uploaded.filename)

    return jsonify(
        {
            "filename": uploaded.filename,
            "size_bytes": len(data),
            "md5": md5_hash,
            "sha256": sha256_hash,
            "signature": signature,
            "entropy": entropy,
            "threat_score": score,
            "threat_verdict": verdict,
            "rules_triggered": rules,
        }
    )


@app.route("/scan-file", methods=["POST"])
def legacy_scan_file():
    """Backward-compatible endpoint for existing frontend integrations."""
    result = api_file_scanner()
    if isinstance(result, tuple):
        return result
    data = result.get_json() or {}
    if data.get("error"):
        return jsonify(data), 400
    return jsonify(
        {
            "filename": data.get("filename"),
            "size_bytes": data.get("size_bytes"),
            "detected_type": data.get("signature"),
            "entropy_percentage": f"{round((float(data.get('entropy', 0)) / 8) * 100, 2)}%",
            "magic_number": "N/A",
            "message": "File scanned successfully",
            "status": "ok",
        }
    )


@app.route("/analyze-phishing", methods=["POST"])
def legacy_analyze_phishing():
    data = request.get_json(force=True, silent=True) or {}
    text = (data.get("text") or "").strip()
    if not text:
        return jsonify({"error": "No text provided"}), 400
    verdict, score, reasons = legacy_phishing_score(text)
    return jsonify({"verdict": verdict, "risk_score": score, "reasons": reasons})


@app.route("/check-password", methods=["POST"])
def check_password():
    data = request.get_json(force=True, silent=True) or {}
    pwd = str(data.get("password") or "")
    if not pwd:
        return jsonify({"error": "No password provided"}), 400
    score = 0
    feedback = []
    if len(pwd) >= 12:
        score += 30
    else:
        feedback.append("Use at least 12 characters")
    if any(c.isupper() for c in pwd):
        score += 20
    else:
        feedback.append("Add uppercase letters")
    if any(c.islower() for c in pwd):
        score += 20
    else:
        feedback.append("Add lowercase letters")
    if any(c.isdigit() for c in pwd):
        score += 15
    else:
        feedback.append("Add numbers")
    if any(c in "!@#$%^&*()-_+=" for c in pwd):
        score += 15
    else:
        feedback.append("Add special characters")
    strength = "Weak" if score < 50 else "Moderate" if score < 80 else "Strong"
    return jsonify({"score": score, "strength": strength, "feedback": feedback})


@app.route("/start-simulation", methods=["GET"])
def start_simulation():
    return jsonify({"message": "Simulation started — a fake phishing email was generated (educational only)."})


@app.route("/view-attacks", methods=["GET"])
def view_attacks():
    demo = [
        {"time": "10:01", "type": "Port scan", "src": "192.168.1.5"},
        {"time": "10:02", "type": "Brute force", "src": "45.12.89.34"},
        {"time": "10:03", "type": "Suspicious download", "src": "103.45.22.9"},
    ]
    return jsonify({"attacks": demo})


@app.route("/api/ip-lookup", methods=["POST"])
def api_ip_lookup():
    data = request.get_json(force=True, silent=True) or {}
    indicator = (data.get("indicator") or "").strip()
    if not indicator:
        return jsonify({"error": "IP or domain is required"}), 400

    is_ip = True
    ip_value = indicator
    try:
        ipaddress.ip_address(indicator)
    except Exception:
        is_ip = False
        try:
            ip_value = socket.gethostbyname(indicator)
        except Exception:
            ip_value = None

    dns_records = {}
    if not is_ip:
        try:
            infos = socket.getaddrinfo(indicator, None)
            dns_records["A/AAAA"] = sorted({i[4][0] for i in infos})
        except Exception as exc:
            dns_records["error"] = str(exc)

    osint = {}
    if ip_value:
        try:
            with urlopen(f"http://ip-api.com/json/{ip_value}?fields=status,country,regionName,city,isp,org,as,query", timeout=5) as resp:
                osint = json.loads(resp.read().decode("utf-8"))
        except Exception as exc:
            osint = {"status": "fail", "error": str(exc)}

    score = 0
    if osint.get("status") == "success" and osint.get("country") in {"", None}:
        score += 10
    if isinstance(osint.get("as"), str) and "hosting" in osint.get("as", "").lower():
        score += 20

    push_history("ip/domain", score, indicator)
    return jsonify({"indicator": indicator, "resolved_ip": ip_value, "dns_records": dns_records, "osint": osint, "risk_score": score})


@app.route("/api/email-analyzer", methods=["POST"])
def api_email_analyzer():
    data = request.get_json(force=True, silent=True) or {}
    raw_headers = (data.get("headers") or "").strip()
    if not raw_headers:
        return jsonify({"error": "Email headers are required"}), 400

    parsed = Parser().parsestr(raw_headers)
    auth_results = parsed.get("Authentication-Results", "")

    spf = "pass" if "spf=pass" in auth_results.lower() else "fail"
    dkim = "pass" if "dkim=pass" in auth_results.lower() else "fail"
    dmarc = "pass" if "dmarc=pass" in auth_results.lower() else "fail"

    received_headers = parsed.get_all("Received", []) or []
    from_header = parsed.get("From", "")
    reply_to = parsed.get("Reply-To", "")

    score = 0
    findings = []
    if spf == "fail":
        score += 20
        findings.append("SPF validation failed")
    if dkim == "fail":
        score += 20
        findings.append("DKIM validation failed")
    if dmarc == "fail":
        score += 20
        findings.append("DMARC validation failed")
    if reply_to and from_header and reply_to.lower() not in from_header.lower():
        score += 15
        findings.append("Reply-To does not match From")

    push_history("email", score, from_header or "header-upload")
    return jsonify(
        {
            "from": from_header,
            "reply_to": reply_to,
            "received_hops": len(received_headers),
            "spf": spf,
            "dkim": dkim,
            "dmarc": dmarc,
            "findings": findings,
            "risk_score": score,
            "verdict": "Suspicious" if score >= 40 else "Likely Safe",
        }
    )


@app.route("/api/dashboard-summary")
def api_dashboard_summary():
    module_counts = Counter(item["module"] for item in scan_history)
    recent = list(reversed(scan_history[-10:]))
    final_score = compute_final_threat_score([item["score"] for item in recent])
    return jsonify(
        {
            "module_counts": module_counts,
            "recent_scans": recent,
            "final_threat_score": final_score,
            "total_scans": len(scan_history),
        }
    )


@app.route("/api/report", methods=["POST"])
def api_report():
    payload = request.get_json(force=True, silent=True) or {}
    modules = payload.get("modules", [])
    scores = [m.get("score", 0) for m in modules if isinstance(m, dict)]
    report = {
        "generated_at": dt.datetime.utcnow().isoformat() + "Z",
        "final_threat_score": compute_final_threat_score(scores),
        "modules": modules,
        "recommendations": [
            "Block high-risk indicators at firewall and secure email gateway.",
            "Enable SPF, DKIM, and DMARC enforcement for enterprise domains.",
            "Quarantine suspicious attachments pending sandbox analysis.",
        ],
    }
    return jsonify(report)


model = None
selected_model_name = None
if GEMINI_API_KEY:
    try:
        genai.configure(api_key=GEMINI_API_KEY)

        candidates = []
        for m in genai.list_models():
            name = getattr(m, "name", "") or ""
            methods = getattr(m, "supported_generation_methods", []) or []
            if "generateContent" in methods and name:
                candidates.append(name)

        preferred_order = [
            "models/gemini-1.5-flash",
            "models/gemini-1.5-pro",
            "models/gemini-1.0-pro",
        ]

        picked = None
        for pref in preferred_order:
            if pref in candidates:
                picked = pref
                break

        if picked is None and candidates:
            picked = candidates[0]

        if picked:
            model = genai.GenerativeModel(picked)
            selected_model_name = picked
            logger.info(f"Selected Gemini model: {picked}")
        else:
            logger.warning("No Gemini model supporting generateContent was found for this API key")
            model = None
    except Exception as exc:
        logger.error(f"Gemini initialization failed: {exc}")
        model = None


@app.route("/ai-status", methods=["GET"])
def ai_status():
    return jsonify({
        "configured": model is not None,
        "model": selected_model_name,
    })


@app.route("/ask-ai", methods=["POST"])
def ask_ai():
    data = request.get_json(force=True, silent=True) or {}
    question = (data.get("question") or "").strip()
    if not question:
        return jsonify({"answer": ""})
    if model is None:
        return jsonify({"answer": "I'm running in offline mode. You can still ask cybersecurity basics, and I'll provide concise guidance from local fallback responses."})
    try:
        response = model.generate_content(f"You are a cybersecurity expert. Answer briefly and clearly:\n{question}")
        return jsonify({"answer": response.text})
    except Exception:
        return jsonify({"answer": "I'm temporarily unable to reach the AI service. Please try again, or ask a simpler cybersecurity question."})


if __name__ == "__main__":
    app.run(debug=True)