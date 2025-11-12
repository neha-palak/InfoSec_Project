#!/usr/bin/env python3
"""
Simple phishing link scanner demo.
Usage:
  python3 scan_links.py sample_emails/email1.txt
Outputs flagged URLs and reasons.
"""
import re
import sys
from urllib.parse import urlparse

# small blocklist for demo
BLOCKLIST_FILE = "blocklist.txt"

# simple heuristics
OBFUSCATION_PATTERNS = [
    r'(?i)paypal',  # typical brand names to watch for
    r'0fficial',    # letter substitutions
    r'--',          # weird dashes
    r'\d{5,}',      # long numeric strings in domain
]

SHORTENER_DOMAINS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd"}

def load_blocklist(path):
    try:
        with open(path) as f:
            return set(line.strip().lower() for line in f if line.strip())
    except FileNotFoundError:
        return set()

URL_RE = re.compile(r'https?://[^\s)]+', re.IGNORECASE)

def extract_urls(text):
    return URL_RE.findall(text)

def domain_of(url):
    try:
        return urlparse(url).netloc.lower()
    except:
        return ""

def check_url(url, blocklist):
    reasons = []
    dom = domain_of(url)
    if dom in blocklist:
        reasons.append("domain in blocklist")
    if dom.split(':')[0] in SHORTENER_DOMAINS:
        reasons.append("shortened URL (obscures target)")
    # detect obvious obfuscation in the whole url
    for pat in OBFUSCATION_PATTERNS:
        if re.search(pat, url):
            reasons.append(f"matches obfuscation heuristic ({pat})")
    # mismatch display vs actual domain (not implemented here) — placeholder
    return reasons

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 scan_links.py email.txt")
        sys.exit(1)
    path = sys.argv[1]
    with open(path, encoding='utf-8', errors='ignore') as f:
        text = f.read()
    urls = extract_urls(text)
    blocklist = load_blocklist(BLOCKLIST_FILE)
    if not urls:
        print("No URLs found.")
        return
    for u in urls:
        reasons = check_url(u, blocklist)
        print(f"URL: {u}")
        if reasons:
            for r in reasons:
                print("  - FLAGGED:", r)
        else:
            print("  - looks benign (heuristics found no issues)")

if __name__ == "__main__":
    main()
