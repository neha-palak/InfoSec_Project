# #!/usr/bin/env python3

import re
import sys
import json
from html.parser import HTMLParser
from urllib.parse import urlparse

BLOCKLIST_FILE = "blocklist.txt"

OBFUSCATION_PATTERNS = [
    (r'(?i)paypal', "brand keyword (possible impersonation)"),
    (r'0fficial', "character-substitution obfuscation"),
    (r'--', "weird consecutive dashes"),
    (r'\d{5,}', "long numeric sequence"),
]

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "buff.ly", "rb.gy"
}

# Improved URL regex: avoid capturing trailing punctuation like . , ) ] "
URL_RE = re.compile(r'https?://[^\s\)\]\>\'\"\,\;]+', re.IGNORECASE)

def load_blocklist(path):
    try:
        with open(path, encoding='utf-8') as f:
            return set(line.strip().lower() for line in f if line.strip())
    except FileNotFoundError:
        return set()

def extract_urls(text):
    """Return list of URL strings (trim trailing punctuation if present)."""
    raw = URL_RE.findall(text)
    cleaned = []
    for u in raw:
        # strip common trailing punctuation that regex might allow
        u = u.rstrip('.,;:!?)"\']')
        cleaned.append(u)
    return cleaned

def domain_of(url):
    """Return normalized domain (no www, no port) or empty string on parse error."""
    try:
        parsed = urlparse(url)
        netloc = parsed.netloc.lower()
        # strip possible credentials user:pass@host
        if "@" in netloc:
            netloc = netloc.split("@", 1)[1]
        # remove port if present
        if ':' in netloc:
            netloc = netloc.split(':', 1)[0]
        # normalize common www
        if netloc.startswith("www."):
            netloc = netloc[4:]
        return netloc
    except Exception:
        return ""

class LinkTextParser(HTMLParser):
    """Extract (href, text) pairs from HTML content."""
    def __init__(self):
        super().__init__()
        self.stack = []
        self.links = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "a":
            href = None
            for k, v in attrs:
                if k.lower() == "href":
                    href = v
                    break
            self.stack.append((tag, href, ""))
        else:
            self.stack.append((tag, None, ""))

    def handle_endtag(self, tag):
        if not self.stack:
            return
        node = self.stack.pop()
        if node[0].lower() == "a" and node[1]:
            href = node[1]
            text = node[2].strip()
            self.links.append((href, text))
        # bubble text up to parent if exists
        if self.stack and node[2]:
            parent = self.stack[-1]
            self.stack[-1] = (parent[0], parent[1], parent[2] + " " + node[2])

    def handle_data(self, data):
        if self.stack:
            tag, href, curtext = self.stack[-1]
            self.stack[-1] = (tag, href, curtext + data)
        # else ignore

def html_links(text):
    """Return list of (href, text) for anchors in HTML; empty if none."""
    parser = LinkTextParser()
    try:
        parser.feed(text)
        return parser.links
    except Exception:
        return []

def is_ip_domain(dom):
    return bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', dom))

def check_url(url, blocklist):
    reasons = []
    dom = domain_of(url)
    if not dom:
        reasons.append("could not parse domain")
        return reasons

    # blocklist (exact match or subdomain)
    if dom in blocklist:
        reasons.append("domain in blocklist")
    else:
        # check if registered parent is in blocklist (simple suffix match)
        for bad in blocklist:
            if dom == bad or dom.endswith("." + bad):
                reasons.append(f"subdomain of blocklisted domain ({bad})")
                break

    host_only = dom.split(':')[0]
    if host_only in SHORTENER_DOMAINS:
        reasons.append("shortened URL (obscures target)")

    # flag IP-address domains
    if is_ip_domain(host_only):
        reasons.append("direct IP address used as domain")

    # heuristics on full url
    for pat, label in OBFUSCATION_PATTERNS:
        if re.search(pat, url):
            reasons.append(f"matches obfuscation heuristic ({label})")

    # suspicious path / query characteristics
    parsed = urlparse(url)
    path = parsed.path or ""
    query = parsed.query or ""
    if len(path) > 100 or len(query) > 200:
        reasons.append("very long path/query (suspicious or tracking)")
    if path.count('/') > 6:
        reasons.append("deep path with many segments (possible redirector)")
    if url.count('-') > 6:
        reasons.append("excessive hyphenation in URL")

    return reasons

def scan_text(text, blocklist):
    results = []
    # first, check for HTML anchor mismatches if the text looks like HTML
    anchors = html_links(text)
    if anchors:
        for href, disp in anchors:
            # normalize display text and href
            href = href.strip()
            disp = disp.strip()
            reasons = check_url(href, blocklist)
            if disp:
                # if display text contains a domain and it mismatches href domain, flag
                disp_domains = re.findall(r'[a-z0-9\.-]+\.[a-z]{2,}', disp, re.IGNORECASE)
                if disp_domains:
                    disp_dom = disp_domains[0].lower().lstrip('www.')
                    href_dom = domain_of(href)
                    if href_dom and disp_dom not in href_dom:
                        reasons.append(f"display text domain mismatch (display: {disp_dom}, href: {href_dom})")
            results.append({"url": href, "reasons": reasons, "source": "anchor"})
    # also extract plain URLs
    for u in extract_urls(text):
        # skip anchors already processed (they might be identical but safe to include duplicates)
        reasons = check_url(u, blocklist)
        results.append({"url": u, "reasons": reasons, "source": "plain"})
    return results

def print_results(results):
    for r in results:
        print("URL:", r["url"])
        if r["reasons"]:
            for reason in r["reasons"]:
                print("  - FLAGGED:", reason)
        else:
            print("  - looks benign (heuristics found no issues)")
    # Optional: also print JSON summary
    print("\n--- JSON SUMMARY ---")
    print(json.dumps(results, indent=2))

def usage_and_exit():
    print("Usage: python3 scan_links.py email.txt")
    sys.exit(1)

def main():
    if len(sys.argv) < 2:
        usage_and_exit()
    path = sys.argv[1]
    try:
        with open(path, encoding='utf-8', errors='ignore') as f:
            text = f.read()
    except FileNotFoundError:
        print("File not found:", path)
        sys.exit(1)

    blocklist = load_blocklist(BLOCKLIST_FILE)
    results = scan_text(text, blocklist)
    if not results:
        print("No URLs or anchors found.")
        return
    print_results(results)

if __name__ == "__main__":
    main()
