# Cyber-Capstone

A small educational web vulnerability scanner aimed at [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/), a deliberately insecure application built for security training. It probes for a few common OWASP Top 10 issues and ships with a Flask web UI for running scans and viewing the text report.

> **Authorized use only.** Run this tool only against systems you own or have explicit permission to test. The default target is a local Juice Shop instance.

## Features

- Enumerates common paths and reports their HTTP status
- Basic checks for reflected XSS, SQL injection indicators, IDOR on product endpoints, and commonly exposed files
- Flask + Bootstrap web UI to start a scan and download the report
- Plain-text scan reports

## Project structure

```
Cyber-Capstone/
├── src/
│   ├── scanner.py      # Command-line scanner
│   ├── web_ui.py       # Flask + Bootstrap web interface
│   └── launcher.py     # Desktop launcher (CustomTkinter)
├── docs/
│   └── sample_scan_output.log   # Example scanner output against Juice Shop
├── archive/
│   └── web_ui_legacy.py         # Earlier web UI version (JSON reports), kept for reference
├── requirements.txt
└── README.md
```

## Getting started

### 1. Run a local Juice Shop target

```bash
docker run -d -p 3000:3000 bkimminich/juice-shop
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Run a scan

Command line:

```bash
python src/scanner.py http://localhost:3000
```

Web UI:

```bash
python src/web_ui.py
# then open http://127.0.0.1:5000
```

## Known limitations

- Juice Shop is a single-page app that answers many unknown paths with its home page and a 200 status, so some "exposed file" results in the [sample output](docs/sample_scan_output.log) are false positives.
- The checks are simple heuristics, not a replacement for a full scanner such as OWASP ZAP.

## Tech stack

Python, Requests, Flask, Bootstrap, CustomTkinter
