# Anonymous Cyber Security Dashboard

> Final Year Project — 6COM2019 Cyber Security and Networks Project
> BSc Computer Science (Cyber Security and Networks)
> Aryan Nigam Dalal · SRN 22103810 · University of Hertfordshire
> Supervisor: Joseph Williams

---

## What This Is

An **Anonymous Cyber Threat Correlation and Prioritisation Dashboard** that helps security analysts cut through alert fatigue by automatically identifying dangerous connections in server logs and ranking them by risk score.

The system addresses a well-documented problem: SOC analysts receive thousands of automated alerts every day, the vast majority of which are false positives. This project tackles that by combining two independent detection engines with a trained machine learning classifier, giving every detected threat a transparent score between 0 and 100 so the most critical alerts are always first.

---

## How It Works — Three Detection Layers

| Layer | What It Does | Technology |
|---|---|---|
| Feed-Based Correlation | Matches log IPs against known malicious indicators from Abuse.ch, AlienVault OTX and ThreatFox | JavaScript / Python |
| Behaviour Detection | Evaluates connection patterns using 7 heuristic rules — no external data needed | JavaScript / Python |
| ML Classification | Trained RandomForest model gives THREAT/BENIGN verdict + confidence % | Python / scikit-learn |

---

## Repository Structure

```
anonymous-cyber-threat-dashboard/
│
├── index.html              ← Main dashboard (opens in any browser, no install)
├── README.md
│
├── static/
│   ├── style.css           ← Dashboard CSS (dark cyberpunk theme)
│   └── app.js              ← All JS: correlation engine, behaviour engine,
│                              scoring model, Chart.js charts, alerts table
│
└── backend/                ← Python/Flask ML backend
    ├── app.py              ← Flask server with 7 REST API endpoints
    ├── requirements.txt    ← pip dependencies
    │
    ├── templates/
    │   └── index.html      ← Jinja2 backend dashboard template
    │
    ├── static/
    │   ├── style.css       ← Backend dashboard CSS
    │   └── app.js          ← Backend dashboard JS (calls Flask API)
    │
    ├── ml/
    │   ├── train_model.py  ← Trains RandomForest on threat_data.csv
    │   ├── classifier.py   ← ThreatClassifier class — loads model, classifies
    │   ├── threat_data.csv ← 200-row labelled training dataset
    │   └── model.pkl       ← Pre-trained model (ready to use)
    │
    └── feeds/
        └── abuse_fetcher.py ← Fetches live Abuse.ch Feodo + URLhaus feeds
```

**Languages used:** HTML · CSS · JavaScript · Python

---

## Quick Start — Dashboard (No Installation)

```bash
# Just open the file — that is all
open index.html        # macOS
start index.html       # Windows
xdg-open index.html    # Linux
```

Opens in any browser. No Python, no server, no terminal.

**To verify it works:**
1. Open `index.html`
2. Click **Run Correlation**
3. HIGH priority alerts appear at top of table sorted by score
4. Go to **Add Log Entry** → enter IP `185.220.101.12`, port `4444`, hour `3`
5. Expected: score **85**, priority **HIGH**, 4 rules in breakdown

---

## Quick Start — Python ML Backend

```bash
cd backend

# Install dependencies
pip install -r requirements.txt

# Train the ML model (first time only — takes ~5 seconds)
python3 ml/train_model.py

# Start the Flask server
python3 app.py

# Open in browser
# http://localhost:5000
```

On startup the server:
1. Fetches live threat feeds from Abuse.ch (Feodo Tracker + URLhaus)
2. Loads the trained RandomForest model from `ml/model.pkl`
3. Starts serving the dashboard at `http://localhost:5000`

---

## ML Model

| Detail | Value |
|---|---|
| Algorithm | RandomForestClassifier (scikit-learn) |
| Training data | 200 labelled rows in `ml/threat_data.csv` |
| Features | 10 (connection count, brute force hits, sensitive paths, error count, unusual port, off hours, upload attempts, feed match, feed count, threat type score) |
| Output | THREAT or BENIGN + confidence percentage (0–100%) |
| Accuracy | 100% on test split |
| Retrain | `python3 backend/ml/train_model.py` |

**Top feature importances (what the model learned):**
```
connection_count      0.284   strongest predictor
threat_type_score     0.199
feed_count            0.174
in_feed               0.142
brute_force_hits      0.098
```

---

## Scoring Rules

### Feed-Based Engine (JavaScript + Python)

| Rule | Condition | Points |
|---|---|---|
| Ransomware | Tagged as ransomware C2 | +50 |
| Malware C2 | Known C2 server | +40 |
| Phishing | Credential theft site | +30 |
| Botnet | Botnet infrastructure | +25 |
| DDoS / Other | DDoS or other type | +20 |
| Multi-feed | In 2+ feeds | +20 |
| Repeat | IP appears 3+ times in log | +15 |
| Unusual port | Port 4444, 6667, 1337, 31337 | +10 |
| Domain | Malicious domain (not raw IP) | +5 |

### Behaviour Engine (7 rules — no external data)

| Rule | Condition | Points |
|---|---|---|
| High frequency | 5+ connections | +40 |
| Brute force | 3+ hits on /login, /admin, /wp-login | +35 |
| Sensitive path | Access to /.env, /config, /backup, /phpinfo | +30 |
| HTTP errors | 3+ 403/404/500 responses | +25 |
| Unusual port | Port 4444, 6667, 1337, 31337 | +20 |
| Off-hours | Active 01:00–05:00 | +15 |
| Upload | POST to /upload or /api/data | +10 |

**Thresholds:** HIGH ≥ 70 · MEDIUM 40–69 · LOW < 40

---

## API Endpoints (Backend)

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/health` | Health check — feed count, ML status |
| POST | `/api/analyze` | Full analysis: feed + behaviour + ML |
| POST | `/api/batch-analyze` | Analyse full log array, ranked results |
| GET | `/api/feed-status` | Abuse.ch cache status |
| POST | `/api/refresh-feed` | Force refresh Abuse.ch feed |
| GET | `/api/indicators` | List loaded threat indicators |
| POST | `/api/predict-only` | ML classifier only — raw feature input |

---

## Live Abuse.ch Feed Integration

The backend fetches from two Abuse.ch endpoints automatically:

- **Feodo Tracker** — botnet C2 server IP blocklist (free, no auth required)
- **URLhaus** — malware distribution URLs and hosts (free, no auth required)

Results are cached for 5 minutes. Call `POST /api/refresh-feed` to force a refresh.

---

## Ethical and Legal Considerations

- Abuse.ch, AlienVault OTX and ThreatFox all publish their feeds freely for security research and tool development — this is their stated purpose
- IP addresses are personal data under UK GDPR — this prototype uses simulated data only
- This tool must only be used to monitor systems the operator is authorised to monitor (Computer Misuse Act 1990)
- All three feed sources are credited fully in the project report

---

## Tech Stack

| Component | Technology |
|---|---|
| Frontend dashboard | HTML5, CSS3, JavaScript (ES6) |
| Charts | Chart.js 4.4.1 |
| Backend server | Python 3.10+, Flask 3.0+ |
| ML classifier | scikit-learn RandomForestClassifier |
| Data processing | pandas, NumPy |
| Live feed fetching | requests |
| Threat feeds | Abuse.ch Feodo Tracker, URLhaus, AlienVault OTX, ThreatFox |

---

## License

MIT — free to use, modify and share.

---

*University of Hertfordshire · 6COM2019 · 2025/2026*
