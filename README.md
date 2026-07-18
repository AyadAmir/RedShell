# RedShell Advanced Framework

**A unified, browser-based security assessment platform combining network reconnaissance, CVE intelligence, web application scanning, live host monitoring, and AI-assisted risk analysis.**

Built as a Final Year Project. Runs locally, no cloud dependency required (AI features are optional and gracefully degrade to a rule-based engine if no API key is configured).

---

## ⚠️ Authorized Use Only

This tool is built **strictly for authorized security testing** — against systems you own, or have explicit written permission to assess. It ships with a bundled, intentionally-vulnerable demo target (`demo_target/vulnerable_app.py`) specifically so you can run every feature safely without needing real infrastructure.

**Do not** point this at systems you do not own or have authorization to test. Unauthorized scanning/testing of third-party systems is illegal in most jurisdictions (e.g. the Computer Fraud and Abuse Act in the US, the Computer Misuse Act in the UK, PECA 2016 in Pakistan).

All web-scanning checks in this project are **detection-only**: they identify *potential* weaknesses (missing headers, reflected input, error-message disclosure) for a human to manually verify — they do not exploit, extract data, or modify target state.

---

## What it does

| Module | Capability |
|---|---|
| **Recon** | Concurrent TCP connect scan, service identification, banner grabbing, TLS detection, lightweight OS fingerprinting |
| **CVE Intelligence** | Correlates discovered services against the live NVD database, with an offline fallback dataset for demo/no-internet use |
| **Web Scanner** | Security header analysis, cookie flag checks (HttpOnly/Secure/SameSite), TLS enforcement check, safe reflected-input detection, safe SQL-error-disclosure detection |
| **Live Monitor** | Real-time CPU/memory/connection telemetry on the host machine with rule-based + statistical anomaly detection (connection bursts, resource spikes, sensitive port exposure) |
| **AI Analyst** | Sends consolidated findings to Claude for a plain-English executive summary, risk scoring, and prioritized remediation — or falls back to a deterministic rule-based summarizer if no API key is set |

Everything is exposed through **one browser dashboard** (`http://localhost:8000`), with live progress streamed over WebSockets so you can watch each pipeline stage execute in real time — useful for live demos in front of an examiner.

---

## Architecture

```
redshell/
├── backend/
│   ├── main.py                # FastAPI app: REST + WebSocket routes
│   ├── database.py            # SQLite persistence for scan history
│   ├── requirements.txt
│   └── modules/
│       ├── recon.py           # Port scanning & service fingerprinting
│       ├── cve_lookup.py      # NVD API correlation + offline fallback
│       ├── web_scanner.py     # Detection-only web app security checks
│       ├── monitor.py         # Host-based anomaly detection
│       └── ai_analyst.py      # Claude API integration + fallback
├── frontend/
│   ├── index.html             # Single-page dashboard structure + CSS
│   └── app.js                 # Dashboard logic, WebSocket handling
├── demo_target/
│   └── vulnerable_app.py      # Safe, local, intentionally vulnerable Flask app
├── data/                      # SQLite database (created on first run)
├── run_windows.bat            # One-click Windows launcher
├── run_linux_mac.sh           # One-click Linux/macOS launcher
├── .env.example                # API key template
└── README.md
```

**Why this architecture works well for an FYP write-up:**
- Clear separation of concerns (each security capability is its own module)
- REST endpoints for individual module testing + a WebSocket pipeline for the orchestrated "full assessment" flow — demonstrates both synchronous and asynchronous/streaming API design
- SQLite persistence layer shows a complete data lifecycle (scan → store → retrieve → display)
- Graceful degradation pattern (AI Analyst) is a legitimate, examinable software engineering decision you can discuss in your viva

---

## Requirements

- **Python 3.10+** (3.11/3.12 recommended)
- Windows 10/11, or Linux/macOS
- Internet connection (optional — only needed for live NVD CVE lookups and live AI analysis; both have offline fallbacks)

---

## How to run (Windows)

1. Install Python from [python.org](https://www.python.org/downloads/) — **tick "Add Python to PATH"** during install.
2. Download/clone this project folder.
3. Double-click **`run_windows.bat`**.

That's it. The script will:
- Create a virtual environment (first run only)
- Install all dependencies automatically
- Start the demo vulnerable target on port 5050
- Start the RedShell dashboard on port 8000
- Open your browser automatically

## How to run (Linux / macOS)

```bash
chmod +x run_linux_mac.sh
./run_linux_mac.sh
```

## Manual setup (any OS)

```bash
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r backend/requirements.txt
pip install flask                # for the demo target only

# Terminal 1 — demo target
python demo_target/vulnerable_app.py

# Terminal 2 — RedShell backend + dashboard
cd backend
python -m uvicorn main:app --host 0.0.0.0 --port 8000
```

Then open **http://localhost:8000** in any browser.

---

## Enabling the AI Analyst (optional)

Without an API key, the AI Analyst tab and the "AI Risk Analysis" panel still work, using a **deterministic rule-based fallback** (so your demo never breaks). To enable full Claude-powered analysis:

1. Get an API key from [console.anthropic.com](https://console.anthropic.com/)
2. Copy `.env.example` to `.env`
3. Fill in: `ANTHROPIC_API_KEY=your_key_here`
4. Re-run the launcher

The dashboard's top-right pill shows **"AI Analyst Online"** when a key is detected, or **"AI Offline (rule-based fallback)"** otherwise — useful to point out in a demo that the system degrades gracefully rather than breaking.

---

## Using the dashboard

1. **Overview** — Enter a target host/IP and URL, tick which modules to run, click **Run Full Assessment**. Watch the live port-sweep animation and console log as recon → CVE → web scan → AI analysis execute in sequence over a WebSocket.
2. **Recon** — Run a standalone port scan.
3. **CVE Intel** — Run recon + CVE correlation against NVD.
4. **Web Scan** — Run the detection-only web application checks against any URL.
5. **Live Monitor** — Click "Start Monitoring" to watch real-time CPU/memory/connection telemetry on the machine RedShell is running on, with anomaly alerts.
6. **AI Analyst** — Chat about your most recent scan results.
7. **History** — Browse and reopen past assessments (stored in `data/redshell.db`).

### Recommended demo flow for your viva

1. Open **Overview**, target = `127.0.0.1`, URL = `http://127.0.0.1:5050` (the bundled demo target)
2. Run Full Assessment — walk through the live port sweep, then the CVE matches, then the web findings (the demo target deliberately has a missing-header issue, an insecure cookie, a reflected-input issue, and a simulated SQL-error disclosure, so all detection logic has something real to find)
3. Switch to **Live Monitor**, start it, and briefly run something CPU-heavy in another window to show the anomaly detection firing
4. Show the **AI Analyst** tab answering a question about the findings
5. Show **History** to demonstrate persistence

---

## Extending the project (ideas for your report's "Future Work" section)

- Add authenticated scanning (login flows) to the web scanner
- Add a PDF/Word report exporter (there's a `pdf` and `docx` generation pattern you can adapt)
- Add a "scheduled scan" feature using a background task queue
- Expand the monitor module to parse Windows Event Logs or `auditd` on Linux for log-based detection, not just resource/connection telemetry
- Add a proper nmap-style OS fingerprint (e.g. via TTL/window-size analysis) instead of the current port-signature heuristic
- Containerize with Docker Compose for one-command deployment

---

## Legal & Ethical Notes for your report

You should include a section in your FYP report along these lines:

> RedShell is designed around the principle of **authorized, non-destructive assessment**. All web application checks are detection-only: they identify indicators of potential vulnerabilities (e.g. unescaped reflected input, database error signatures) without exploiting them or extracting real data. This design choice reflects real-world DAST (Dynamic Application Security Testing) tool behavior — such as that used by OWASP ZAP or Burp Suite's passive scanner — and was a deliberate decision to keep the framework usable for ethical, authorized security testing only.

This is a genuinely strong point to make to examiners — it shows you understand the *ethics* of security tooling, not just the technical implementation.
