# Sentry Sweep

A lightweight network vulnerability detection and analysis dashboard. Sentry Sweep allows users to configure a scan across a target IP range, discover active hosts and open ports, and review a scored report highlighting insecure protocols, exposed services, and common misconfigurations—complete with plain-language impact summaries and actionable mitigations.

---

## Features

- **Dashboard & History:** View past scan metrics, trend data, and high-level network health scores.
- **Interactive Scan Interface:** Configure IP ranges, observe simulated scan phases in real-time, and monitor a live console output.
- **Detailed Vulnerability Reports:** Access categorized findings with severity ratings, plain-language business impacts, and step-by-step remediation guidance.
- **Educational Architecture:** Learn about the network discovery lifecycle (host discovery → service enumeration → vulnerability assessment).

---

## Pages Overview

| File | Purpose |
| :--- | :--- |
| `index.html` | Dashboard displaying recent scan history, aggregate statistics, and system status. |
| `scan.html` | Interface to configure scan parameters, trigger scans, and observe real-time console feedback. |
| `report.html` | Comprehensive vulnerability report detailing discovered issues, risk scores, and mitigations. |
| `about.html` | Background documentation detailing scanning methodology, limitations, and future roadmap. |

---

## How It Works

Browsers operate within a security sandbox and cannot establish raw network sockets. Consequently, `js/scanner.js` runs a seeded, realistic client-side simulation that mirrors the standard phases of a vulnerability assessment:

1. **Host Discovery** — Identifying responsive IP addresses within the subnet.
2. **Port & Service Enumeration** — Checking common service ports (e.g., HTTP, SSH, FTP, SMB).
3. **Vulnerability Analysis** — Correlating discovered services with known misconfigurations and insecure protocols.

> **Extending to a Live Backend:**  
> The frontend is structured to easily integrate with a live scanning daemon (such as a Python/Flask service using `nmap` or `scapy`). Implementation notes and architectural guidance are provided in `about.html`.

---

## Getting Started

Because Sentry Sweep is built using static assets, **no build step or package installation is required**.

### Prerequisites

To avoid browser CORS and security restrictions associated with opening files via `file://`, serve the files through a local HTTP server.

### Running Locally

1. **Clone or download the repository:**
   ```bash
   git clone [https://github.com/your-username/sentry-sweep.git](https://github.com/your-username/sentry-sweep.git)
   cd sentry-sweep
