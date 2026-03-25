# CyberWatch — Threat Correlation & Prioritisation Dashboard

> Final Year Project — 6COM2019 Cyber Security and Networks Project  
> BSc Computer Science (Cyber Security and Networks)  
> Aryan Nigam Dalal · SRN 22103810 · University of Hertfordshire  
> Supervisor: Joseph Williams

---

## What This Is

CyberWatch is a browser-based **Cyber Threat Correlation and Prioritisation Dashboard** that helps security analysts cut through alert fatigue by automatically prioritising which threats need attention most urgently.

It addresses the well-documented problem that SOC analysts receive thousands of alerts per day, the vast majority of which are false positives or low-priority noise. CyberWatch gives every detected threat a transparent risk score (0–100) so analysts immediately know what to investigate first.

---

## How It Works

The system runs two completely independent detection engines:

| Engine | Method | Detects |
|--------|--------|---------|
| Feed-Based Correlation | Matches log IPs against known malicious indicators from Abuse.ch, AlienVault OTX and ThreatFox | Known malware C2, ransomware, phishing, botnet infrastructure |
| Behaviour-Based Detection | Evaluates connection patterns using 7 heuristic rules | Zero-day threats, brute-force attempts, reconnaissance activity |

Every detection is scored using a transparent rule set. The analyst sees exactly which rules fired and how many points each contributed — no black box.

**Scoring thresholds:**
- `HIGH` ≥ 70 — immediate action required
- `MEDIUM` 40–69 — investigate promptly
- `LOW` < 40 — log and monitor

---

## Repository Structure

```
cyberwatch-dashboard/
├── index.html          ← Main application (HTML structure only)
├── static/
│   ├── style.css       ← All styling (dark cyberpunk theme)
│   └── app.js          ← All logic: feed DB, correlation engine,
│                          behaviour engine, scoring, charts, UI
└── README.md
```

This is a **multi-file project** — HTML, CSS and JavaScript are separated. The JS implements the full correlation and scoring logic. See `cyberwatch-ml-backend` for the Python/Flask version with live Abuse.ch feeds and ML classification.

---

## Getting Started

**Requirements:** Any modern web browser. No installation. No server. No Python.

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/cyberwatch-dashboard.git
cd cyberwatch-dashboard

# Open in browser
open index.html   # macOS
start index.html  # Windows
xdg-open index.html  # Linux
```

That's it. The dashboard opens immediately.

---

## Features

| Feature | Description |
|---------|-------------|
| Feed database | 15 threat indicators from Abuse.ch, AlienVault OTX, ThreatFox |
| Correlation engine | O(1) hash map lookup — constant time regardless of database size |
| Behaviour engine | 7 heuristic rules, fully independent of any external data |
| Risk scoring | 9 feed rules + 7 behaviour rules, scores 0–100, fully explained |
| Prioritised alerts | Sorted by score descending — most critical always first |
| Filtering & search | Filter by HIGH/MEDIUM/LOW, search by IP or domain |
| Analyst workflow | Mark alerts as Investigated or Blocked directly from the table |
| Manual log entry | Test any IP in real time via the input form |
| Custom indicators | Add your own threat indicators to the feed database |
| Charts | Stacked bar, doughnut, line, pie — all live-updating |
| Activity log | Timestamped system log with severity colour coding |
| Offline | Works with no internet connection — no dependencies at runtime |

---

## Scoring Rules

### Feed-Based Engine

| Rule | Condition | Points |
|------|-----------|--------|
| Ransomware | Tagged as ransomware C2 | +50 |
| Malware C2 | Known C2 server | +40 |
| Phishing | Credential theft site | +30 |
| Botnet | Botnet infrastructure | +25 |
| DDoS / Other | DDoS or other type | +20 |
| Multi-feed | In 2+ feeds | +20 |
| Repeat | IP appears 3+ times in log | +15 |
| Unusual port | Port 4444, 6667, 1337, 31337 | +10 |
| Domain | Malicious domain (not raw IP) | +5 |

### Behaviour-Based Engine

| Rule | Condition | Points |
|------|-----------|--------|
| High frequency | 5+ connections | +40 |
| Brute force | 3+ hits on /login, /admin, /wp-login | +35 |
| Sensitive path | Access to /.env, /config, /backup, /phpinfo | +30 |
| HTTP errors | 3+ 403/404/500 responses | +25 |
| Unusual port | Port 4444, 6667, 1337, 31337 | +20 |
| Off-hours | Active 01:00–05:00 | +15 |
| Upload | POST to /upload or /api/data | +10 |

---

## Testing

All scoring is deterministic — same input always produces the same output.

Expected scores can be calculated by hand from the tables above before running any test. The full test suite (18 cases, all PASS) is documented in the project report.

**Quick test:** Open the dashboard, go to Add Log Entry, enter `185.220.101.12` as the IP with port `4444`. Expected result: `HIGH` priority, score 80.

---

## Limitations

This is a prototype. Known limitations:

1. **Simulated log data** — the 22-entry log is generated at startup. Real syslog parsing is future work.
2. **Static feed database** — 15 indicators only. See `cyberwatch-ml-backend` for live Abuse.ch API integration.
3. **No persistence** — alerts are lost when the browser closes.
4. **Heuristic thresholds** — behaviour rules were set conservatively; calibration against real attack data is needed.
5. **No automated tests** — all testing was manual.

---

## Future Work

- Live Abuse.ch API integration (see `cyberwatch-ml-backend`)
- Python/Flask backend with persistent database (see `cyberwatch-ml-backend`)
- MITRE ATT&CK framework mapping
- ML-based threshold calibration
- Automated Jest test suite

---

## Related Repository

For the Python/Flask version with live Abuse.ch feeds and ML classification:  
👉 **[cyberwatch-ml-backend](https://github.com/YOUR_USERNAME/cyberwatch-ml-backend)**

---

## License

MIT — free to use, modify and share.

---

*University of Hertfordshire · 6COM2019 · 2026*
