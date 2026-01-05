#!/usr/bin/env python3
"""
juice_scan1.py - small educational scanner (synchronous)
Usage:
    python juice_scan1.py http://localhost:3000

Only run against systems you own or are authorized to test.
"""

import sys
import requests
import urllib.parse
import time

# Simple config
TIMEOUT = 8
USER_AGENT = "JuiceScan/1.0 (educational)"
HEADERS = {"User-Agent": USER_AGENT}
DELAY = 0.3

session = requests.Session()
session.headers.update(HEADERS)


def safe_get(path, params=None):
    url = urllib.parse.urljoin(TARGET, path)
    try:
        r = session.get(url, params=params, timeout=TIMEOUT, allow_redirects=True)
        return r
    except Exception as e:
        print(f"[ERROR] GET {url} -> {e}")
        return None


def discover_common_paths():
    print("\n[*] Enumerating common paths...")
    common = [
        "/", "/#/login", "/assets", "/ftp", "/.git/config", "/package.json",
        "/api/Products", "/api/Users", "/api/Orders", "/api/Reviews", "/rest"
    ]
    found = []
    for p in common:
        r = safe_get(p)
        time.sleep(DELAY)
        if r is None:
            print(f"  {p:18} -> no response")
            continue
        status = r.status_code
        print(f"  {p:18} -> {status}")
        if status < 400:
            found.append((p, status))
    return found


def test_reflected_xss():
    print("\n[*] Testing for simple reflected XSS in common endpoints...")
    xss_payloads = ['<script>alert(1)</script>', '"><svg/onload=alert(1)>']
    test_points = [
        ("/", {"q": None}),
        ("/#/search", {"q": None}),
        ("/api/Reviews", {"comment": None})
    ]
    results = []
    for path, params_tpl in test_points:
        for payload in xss_payloads:
            params = {}
            for k in params_tpl:
                params[k] = payload
            r = safe_get(path, params=params)
            time.sleep(DELAY)
            if not r:
                continue
            body = r.text
            if payload in body:
                print(f"  [POSSIBLE XSS] {path} reflected payload found in response.")
                results.append((path, payload))
    return results


def test_sql_injection():
    print("\n[*] Testing for basic SQLi indications on search endpoints...")
    sqli_payloads = ["' OR '1'='1", "' OR '1'='1' -- "]
    paths = ["/rest/products/search", "/api/Products", "/search", "/"]
    findings = []
    for p in paths:
        base = safe_get(p)
        time.sleep(DELAY)
        base_len = len(base.text) if base else 0
        for payload in sqli_payloads:
            params = {"q": payload}
            r = safe_get(p, params=params)
            time.sleep(DELAY)
            if not r:
                continue
            body = (r.text or "").lower()
            if ("sql" in body or "syntax error" in body or abs(len(body) - base_len) > 200):
                print(f"  [POSSIBLE SQLi] {p} payload '{payload}' caused abnormal response (len {len(body)})")
                findings.append((p, payload, r.status_code))
    return findings


def test_idor():
    print("\n[*] Testing for IDOR / Broken Access Control on product endpoints...")
    r = safe_get("/api/Products")
    time.sleep(DELAY)
    findings = []
    if r and r.status_code == 200:
        try:
            data = r.json()
        except Exception:
            data = None
        if isinstance(data, list) and len(data) > 0:
            sample_ids = [item.get("id") for item in data[:3] if isinstance(item, dict) and "id" in item]
            for pid in sample_ids:
                for test_id in (pid + 1, pid + 2, max(pid - 2, 1)):
                    rp = safe_get(f"/api/Products/{test_id}")
                    time.sleep(DELAY)
                    if rp and rp.status_code == 200:
                        print(f"  [POSSIBLE IDOR] Accessed /api/Products/{test_id} (200)")
                        findings.append(("product", test_id))
    else:
        print("  Could not fetch /api/Products; skipping IDOR product check.")
    return findings


def check_sensitive_files():
    print("\n[*] Checking for commonly exposed files/paths...")
    check = ["/package.json", "/config.js", "/.env", "/ftp", "/.git/config"]
    exposed = []
    for p in check:
        r = safe_get(p)
        time.sleep(DELAY)
        if r and r.status_code == 200:
            snippet = (r.text or "")[:300].replace("\n", " ")
            print(f"  [EXPOSED] {p} -> 200, sample: {snippet!r}")
            exposed.append((p, snippet))
    return exposed


def main():
    print(f"JuiceScan -> Target: {TARGET}")
    discover_common_paths()
    x = test_reflected_xss()
    sqli = test_sql_injection()
    idor = test_idor()
    exposed = check_sensitive_files()

    print("\n--- Summary ---")
    print(f"XSS candidates: {len(x)}")
    for item in x: print(" ", item)
    print(f"SQLi candidates: {len(sqli)}")
    for item in sqli: print(" ", item)
    print(f"IDOR candidates: {len(idor)}")
    for item in idor: print(" ", item)
    print(f"Exposed files: {len(exposed)}")
    for item in exposed: print(" ", item[0])


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python juice_scan.py http://localhost:3000")
        sys.exit(1)

    TARGET = sys.argv[1].rstrip("/") + "/"
    main()
