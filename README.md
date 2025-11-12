### **Project Title**

**Designing a Multi-Layered Anti-Phishing System to Mitigate Malicious Emails and Links**

---

### **Author**

**Name:** Neha Palak

**Course:** CS-3610: Information Security (Monsoon 2025)

**Instructor:** Subhashis Banerjee

---

### **1. Overview**

This project demonstrates a simplified **anti-phishing system** designed to detect and flag suspicious emails and malicious links.
It supports the accompanying 500-word report by showing a practical example of the **content and link analysis layer** described in the proposed multi-layered defense model.

The prototype (`scan_links.py`) scans a sample email text file, extracts URLs, and applies simple heuristics and a blocklist to flag potentially malicious links.

---

### **2. Directory Structure**

```
YourFullName_project/
│
├── report.pdf                     # 500-word written report
├── README.txt                     # this file
└── prototype/
    ├── scan_links.py              # main Python script
    ├── blocklist.txt              # sample malicious domains
    ├── sample_emails/
    │   ├── email1.txt             # phishing example
    │   ├── email2.txt             # benign example
    │   └── email3.txt             # mixed content
    └── README.md                  # short readme for prototype (optional)
```

---

### **3. Requirements**

* Python 3.8 or higher
* No additional libraries required (only built-in modules)

Optional: You can run it on any OS (Windows/macOS/Linux) with Python installed.

---

### **4. How to Run**

1. Open a terminal or command prompt.
2. Navigate to the `prototype/` folder.
3. Run the command:

   ```bash
   python3 scan_links.py sample_emails/email1.txt
   ```
4. The program will print all URLs found in the email and flag those that appear suspicious, based on:

   * Known bad domains in `blocklist.txt`
   * Shortened URLs (e.g., `bit.ly`, `t.co`)
   * Obfuscated patterns (e.g., `0fficial`, long numeric strings)

Example output:

```
URL: https://bit.ly/verify-paypal-12345
  - FLAGGED: shortened URL (obscures target)
  - FLAGGED: matches obfuscation heuristic ((?i)paypal)
```

---

### **5. Test Cases**

| Email File | Description                     | Expected Result                |
| ---------- | ------------------------------- | ------------------------------ |
| email1.txt | Phishing with shortened link    | URL flagged                    |
| email2.txt | Normal company newsletter       | No flags                       |
| email3.txt | Suspicious but not in blocklist | Possibly flagged by heuristics |

---

### **6. Connection to Report**

This prototype represents the **“Content and Link Analysis Layer”** described in the 500-word report.
It demonstrates how simple pattern-based and heuristic checks can help identify malicious links before they reach users, forming one component of a **multi-layered anti-phishing architecture** that also includes:

* SPF/DKIM/DMARC authentication
* UI warnings and banners
* Reporting and monitoring layers

---

### **7. Limitations and Future Work**

* This demo uses static heuristics; a real deployment would integrate live threat intelligence APIs.
* It does not validate SSL certificates or inspect attachments.
* Future work could include machine learning–based URL classification, sandboxed link testing, and integration with mail servers.

---

### **8. References**

* ...
