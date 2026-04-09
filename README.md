# 🔒 CertChecker — SSL/TLS Certificate Inspection CLI

A powerful, feature-rich Python CLI tool for inspecting, monitoring, and reporting on SSL/TLS certificates.

---

## ✨ Features

| Feature | Description |
|---|---|
| **`check`** | Deep inspection of a single domain's certificate |
| **`bulk`** | Check multiple domains from a file at once |
| **`chain`** | Display the full certificate chain (leaf → root) |
| **`monitor`** | Continuously watch certificates for expiry |
| **`compare`** | Side-by-side comparison of two domains |
| **`scan`** | Scan TLS ports and security headers |
| **`report`** | Export JSON / CSV / HTML reports |
| **Expiry alerts** | Color-coded: 🟢 OK / 🟡 Warn / 🟠 Critical / 🔴 Expired |
| **HSTS detection** | HTTP Strict Transport Security analysis |
| **HTTP → HTTPS redirect** | Auto-detect insecure redirect chains |
| **Security headers** | Scan for CSP, X-Frame-Options, Referrer-Policy, etc. |
| **Self-signed detection** | Flag untrusted certificates |
| **Weak key/hash detection** | Warn for SHA1, MD5, small RSA keys |
| **SANs listing** | Full Subject Alternative Names display |
| **Fingerprints** | SHA-1 and SHA-256 fingerprint output |
| **Key usage** | Parsed key usage and extended key usage |
| **OCSP / CRL URLs** | Revocation endpoint listing |

---

## 🚀 Installation

```bash
# Clone the repo / navigate to the folder
cd CertChecker

# Install dependencies
pip install -r requirements.txt

# Install as a command (editable mode)
pip install -e .
```

---

## 📖 Commands

### `check` — Inspect a Single Domain

```bash
certchecker check google.com
certchecker check github.com --port 443
certchecker check example.com --warn-days 60 --critical-days 14
certchecker check example.com --json
certchecker check example.com --json -o result.json
certchecker check example.com --no-http         # skip HTTP security checks
```

### `bulk` — Check Multiple Domains

```bash
certchecker bulk domains.txt
certchecker bulk domains.txt --format html -o report.html
certchecker bulk domains.txt --format json -o results.json
certchecker bulk domains.txt --format csv  -o results.csv
certchecker bulk domains.txt --fail-on-expired   # exit code 1 if expired
certchecker bulk domains.txt --fail-on-warning   # exit code 1 if < warn-days
```

### `chain` — Show Full Certificate Chain

```bash
certchecker chain google.com
certchecker chain github.com --json
```

### `monitor` — Continuous Watch Mode

```bash
certchecker monitor domains.txt
certchecker monitor domains.txt --interval 300       # check every 5 min
certchecker monitor domains.txt --warn-days 60
certchecker monitor domains.txt --alert-only          # only print issues
```

### `compare` — Side-by-Side Comparison

```bash
certchecker compare google.com microsoft.com
certchecker compare github.com gitlab.com --json
```

### `scan` — Port Scan + Security Headers

```bash
certchecker scan example.com
certchecker scan api.example.com --json
```

### `report` — Generate Reports

```bash
certchecker report domains.txt --format html -o report.html
certchecker report domains.txt --format csv  -o report.csv
certchecker report domains.txt --format json -o report.json
```

---

## 📁 domains.txt Format

```
# One hostname per line
# Lines starting with '#' are ignored

google.com
github.com
microsoft.com
```

---

## 🎨 Output Examples

- **`check`**: Rich terminal panel with certificate overview, validity, subject/issuer, key info, SANs, weaknesses, HSTS
- **`bulk`**: Colorized summary table with status badges
- **`chain`**: Hierarchical tree showing leaf → intermediate → root
- **`report --format html`**: Dark-theme HTML dashboard with stats cards
- **`monitor`**: Live streaming log with timestamped alert levels

---

## 🏗 Project Structure

```
CertChecker/
├── certchecker/
│   ├── cli.py          # Click CLI commands
│   ├── checker.py      # Core SSL inspection
│   ├── chain.py        # Certificate chain parsing
│   ├── http_checks.py  # HSTS, redirects, security headers
│   ├── reporter.py     # JSON/CSV/HTML export
│   ├── monitor.py      # Watch mode loop
│   └── utils.py        # Rich display utilities
├── domains.txt         # Sample domains list
├── requirements.txt
├── setup.py
└── README.md
```

---

## 📋 Requirements

- Python 3.8+
- click, rich, cryptography, requests, dnspython

---


