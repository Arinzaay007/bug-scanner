from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import requests as req
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from datetime import datetime
import time
import os

from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from webdriver_manager.chrome import ChromeDriverManager

app = Flask(__name__, static_folder="..")
CORS(app)

# ─── Payloads ────────────────────────────────────────────────────────────────

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert(1)>",
    "'><script>alert(1)</script>",
]

SQLI_PAYLOADS = [
    "'",
    "' OR '1'='1",
    "' OR '1'='1' --",
]

SQLI_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sqlstate", "mysql_fetch", "pg_query",
    "syntax error", "ora-",
]

LOGIN_BYPASS_PAYLOADS = [
    {"username": "admin' --",           "password": "anything"},
    {"username": "' OR '1'='1' --",     "password": "' OR '1'='1' --"},
    {"username": "admin",               "password": "' OR '1'='1' --"},
]

SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://127.0.0.1:80",
    "http://localhost:22",
]

SECURITY_HEADERS = [
    ("Strict-Transport-Security", "Missing HSTS header",                        "Medium"),
    ("X-Content-Type-Options",    "Missing X-Content-Type-Options",              "Low"),
    ("X-Frame-Options",           "Missing X-Frame-Options (Clickjacking risk)", "Medium"),
    ("Content-Security-Policy",   "Missing Content-Security-Policy",             "Medium"),
    ("X-XSS-Protection",          "Missing X-XSS-Protection",                    "Low"),
    ("Referrer-Policy",           "Missing Referrer-Policy",                     "Low"),
]

# ─── Selenium driver ──────────────────────────────────────────────────────────

def get_driver():
    opts = Options()
    opts.add_argument("--headless")
    opts.add_argument("--no-sandbox")
    opts.add_argument("--disable-dev-shm-usage")
    opts.add_argument("--disable-gpu")
    opts.add_argument("--window-size=1280,800")
    opts.add_argument("user-agent=Mozilla/5.0 BugScanner/2.0")
    driver = webdriver.Chrome(
        service=Service(ChromeDriverManager().install()),
        options=opts
    )
    driver.set_page_load_timeout(15)
    return driver

# ─── HTTP session for form submissions ───────────────────────────────────────

SESSION = req.Session()
SESSION.headers.update({"User-Agent": "Mozilla/5.0 BugScanner/2.0"})

def safe_get(url, **kw):
    try:
        return SESSION.get(url, timeout=8, allow_redirects=True, **kw)
    except Exception:
        return None

def safe_post(url, data=None, **kw):
    try:
        return SESSION.post(url, data=data, timeout=8, allow_redirects=True, **kw)
    except Exception:
        return None

# ─── Crawl with Selenium (handles JS-rendered pages) ─────────────────────────

def crawl(base_url, max_pages=5):
    visited   = set()
    to_visit  = [base_url]
    all_forms = []
    log       = []
    domain    = urlparse(base_url).netloc
    driver    = None

    try:
        log.append("[*] Starting Chrome (headless)...")
        driver = get_driver()

        while to_visit and len(visited) < max_pages:
            url = to_visit.pop(0)
            if url in visited:
                continue
            visited.add(url)

            try:
                driver.get(url)
                WebDriverWait(driver, 8).until(
                    EC.presence_of_element_located((By.TAG_NAME, "body"))
                )
                time.sleep(1)

                html = driver.page_source
                soup = BeautifulSoup(html, "html.parser")

                forms_on_page = 0
                for form in soup.find_all("form"):
                    action = form.attrs.get("action", "").strip()
                    method = form.attrs.get("method", "get").strip().lower()
                    inputs = []
                    for tag in form.find_all(["input", "textarea", "select"]):
                        name  = tag.attrs.get("name")
                        itype = tag.attrs.get("type", "text")
                        if name:
                            inputs.append({"name": name, "type": itype})
                    if inputs:
                        all_forms.append({
                            "action": urljoin(url, action) if action else url,
                            "method": method,
                            "inputs": inputs,
                            "page":   url,
                        })
                        forms_on_page += 1

                for a in soup.find_all("a", href=True):
                    full = urljoin(url, a["href"])
                    p    = urlparse(full)
                    if p.netloc == domain and p.scheme in ("http","https") and full not in visited:
                        to_visit.append(full)

                log.append(f"[+] Crawled: {url} ({forms_on_page} form(s))")

            except Exception as e:
                log.append(f"[!] Skipped {url}: {str(e)[:80]}")

    finally:
        if driver:
            driver.quit()
            log.append("[*] Browser closed.")

    return all_forms, visited, log

# ─── Scan modules ─────────────────────────────────────────────────────────────

def test_xss(forms, findings, log):
    log.append("[*] Running XSS tests...")
    found = False
    for form in forms:
        target = form["action"]
        for payload in XSS_PAYLOADS:
            data = {i["name"]: payload for i in form["inputs"]}
            r = safe_post(target, data) if form["method"] == "post" else safe_get(target, params=data)
            if r and payload in r.text:
                log.append(f"[!!] XSS FOUND at {target}")
                findings.append({"type": "XSS", "severity": "High", "url": target, "payload": payload})
                found = True
            else:
                log.append(f"[ok] No XSS: {payload[:40]}")
    if not found:
        log.append("[+] No XSS vulnerabilities found.")

def test_sqli(forms, findings, log):
    log.append("[*] Running SQL Injection tests...")
    found = False
    for form in forms:
        target = form["action"]
        for payload in SQLI_PAYLOADS:
            data = {i["name"]: payload for i in form["inputs"]}
            r = safe_post(target, data) if form["method"] == "post" else safe_get(target, params=data)
            if r:
                body = r.text.lower()
                for err in SQLI_ERRORS:
                    if err in body:
                        log.append(f"[!!] SQLi FOUND at {target} — error: {err}")
                        findings.append({"type": "SQL Injection", "severity": "Critical", "url": target, "payload": payload})
                        found = True
                        break
                else:
                    log.append(f"[ok] No SQLi: {payload[:30]}")
    if not found:
        log.append("[+] No SQL Injection found.")

def test_login_bypass(forms, findings, log):
    log.append("[*] Running Login Bypass tests...")
    found = False
    for form in forms:
        inputs = [i["name"].lower() for i in form["inputs"]]
        if not any(k in inputs for k in ["username","user","email","password","pass"]):
            continue
        target = form["action"]
        for pl in LOGIN_BYPASS_PAYLOADS:
            data = {}
            for inp in form["inputs"]:
                nm = inp["name"].lower()
                if "user" in nm or "email" in nm:
                    data[inp["name"]] = pl["username"]
                elif "pass" in nm:
                    data[inp["name"]] = pl["password"]
                else:
                    data[inp["name"]] = "test"
            r = safe_post(target, data)
            if r and any(k in r.text.lower() for k in ["dashboard","welcome","logout","profile","account"]):
                log.append(f"[!!] Login Bypass FOUND at {target}")
                findings.append({"type": "Login Bypass", "severity": "Critical", "url": target, "payload": str(pl)})
                found = True
            else:
                log.append(f"[ok] No bypass: {str(pl)[:50]}")
    if not found:
        log.append("[+] No Login Bypass found.")

def test_ssrf(forms, findings, log):
    log.append("[*] Running SSRF tests...")
    found = False
    for form in forms:
        target = form["action"]
        for payload in SSRF_PAYLOADS:
            data = {i["name"]: payload for i in form["inputs"]}
            r = safe_post(target, data) if form["method"] == "post" else safe_get(target, params=data)
            if r and any(k in r.text.lower() for k in ["ami-id","instance-id","root:","ssh-rsa"]):
                log.append(f"[!!] SSRF FOUND at {target}")
                findings.append({"type": "SSRF", "severity": "Critical", "url": target, "payload": payload})
                found = True
            else:
                log.append(f"[ok] No SSRF: {payload[:50]}")
    if not found:
        log.append("[+] No SSRF found.")

def test_headers(base_url, findings, log):
    log.append("[*] Checking security headers...")
    r = safe_get(base_url)
    if not r:
        log.append("[!] Could not fetch headers.")
        return
    for header, desc, severity in SECURITY_HEADERS:
        if header not in r.headers:
            log.append(f"[!!] {desc}")
            findings.append({"type": "Missing Header", "severity": severity, "url": base_url, "payload": desc})
        else:
            log.append(f"[ok] {header} present")

# ─── Routes ───────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return send_from_directory("..", "index.html")

@app.route("/api/scan", methods=["POST"])
def scan():
    body      = request.get_json(force=True, silent=True) or {}
    target    = (body.get("target") or "").strip()
    max_pages = min(int(body.get("max_pages", 5)), 15)
    modules   = body.get("modules", {})

    if not target or not target.startswith(("http://","https://")):
        return jsonify({"error": "Invalid target URL"}), 400

    findings = []
    log      = []

    forms, visited, crawl_log = crawl(target, max_pages)
    log.extend(crawl_log)

    if not forms:
        log.append("[!] No forms found on target pages.")

    if modules.get("xss",     True) and forms: test_xss(forms, findings, log)
    if modules.get("sqli",    True) and forms: test_sqli(forms, findings, log)
    if modules.get("login",   True) and forms: test_login_bypass(forms, findings, log)
    if modules.get("ssrf",    True) and forms: test_ssrf(forms, findings, log)
    if modules.get("headers", True):           test_headers(target, findings, log)

    return jsonify({
        "target":        target,
        "timestamp":     datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "pages_crawled": len(visited),
        "forms_found":   len(forms),
        "findings":      findings,
        "log":           log,
    })

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print("\n  ================================")
    print("     BugScan v2.0")
    print("  ================================")
    print(f"  Running on port {port}\n")
    app.run(debug=False, host="0.0.0.0", port=port)
