Anti-Phishing Prototype – README

This folder contains the prototype implementation for the Content and Link Analysis Layer of the multi-layered anti-phishing system described in the project report.
The goal of this prototype is to demonstrate how lightweight heuristics and blocklists can identify malicious links in email text files.

1. Files in This Folder
prototype/
├── scan_links.py        # Main script for URL extraction and heuristic analysis
├── blocklist.txt        # Sample malicious domains
└── sample_emails/
    ├── email1.txt       # Phishing example (shortened + obfuscated link)
    ├── email2.txt       # Benign newsletter
    └── email3.txt       # Suspicious / borderline email

2. Requirements

Python 3.8+

No external libraries required (only Python standard library)

This makes the script portable across Windows, macOS, and Linux.

3. How to Run

Open a terminal and navigate to the prototype/ directory:

cd prototype/


Run the script on any of the sample email files:

python3 scan_links.py sample_emails/email1.txt


The script will:

extract all URLs from the email,

check for blocklisted domains,

detect shortened or obfuscated URLs,

and print a summary of flagged results.

Example Output:

URL: https://bit.ly/verify-paypal-12345
  - FLAGGED: shortened URL (obscures target)
  - FLAGGED: matches obfuscation heuristic (brand keyword)

4. How It Works

The script applies several lightweight checks:

Regex-based URL extraction

Domain blocklist lookup

Heuristics for common phishing patterns, such as:

shortened URLs (bit.ly, t.co, etc.)

obfuscated strings (e.g., “0fficial”)

suspicious keywords (“verify”, “account”, “urgent”)

long numeric or hyphenated patterns

Optional HTML anchor-text mismatch detection

JSON summary output for debugging and tracking

This reflects a simplified version of real email-security link scanning.