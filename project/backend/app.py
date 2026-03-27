"""
app.py — CyberWatch ML Backend
================================
Flask application that:
  1. Fetches live threat feeds from Abuse.ch (Feodo Tracker + URLhaus)
  2. Runs rule-based correlation engine (same logic as the HTML prototype)
  3. Runs ML classifier (RandomForest) for yes/no threat verdict
  4. Combines both engines into a unified API response
  5. Serves the dashboard frontend from templates/index.html

Endpoints:
  GET  /                       - Dashboard UI
  POST /api/analyze            - Analyse a log entry (rule engine + ML)
  POST /api/batch-analyze      - Analyse multiple entries at once
  GET  /api/feed-status        - Current Abuse.ch feed status + indicator count
  POST /api/refresh-feed       - Force-refresh the Abuse.ch feed cache
  GET  /api/indicators         - List all loaded threat indicators
  POST /api/predict-only       - ML classifier only (no rule engine)
  GET  /api/health             - Health check

Setup:
  pip install -r requirements.txt
  python3 app.py
"""

import logging
import os
import sys
from datetime import datetime
from typing import List, Dict, Any

from flask import Flask, request, jsonify, render_template

# ── Path setup ────────────────────────────────────────────────────────────────
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from feeds.abuse_fetcher import AbuseFetcher, ThreatIndicator
from ml.classifier import ThreatClassifier

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
)
logger = logging.getLogger(__name__)

# ── Flask app ─────────────────────────────────────────────────────────────────
app = Flask(__name__, template_folder='templates', static_folder='static')

# ── Globals (initialised at startup) ─────────────────────────────────────────
fetcher   = AbuseFetcher(cache_ttl_seconds=300)
classifier = ThreatClassifier(auto_train=True)
FEED_INDEX: Dict[str, ThreatIndicator] = {}   # filled by load_feed()

# ── Scoring constants ─────────────────────────────────────────────────────────
UNUSUAL_PORTS   = {4444, 6667, 1337, 31337, 9090}
SENSITIVE_PATHS = {'/.env', '/config', '/backup', '/phpinfo.php',
                   '/admin', '/wp-login.php'}
AUTH_PATHS      = {'/login', '/admin', '/wp-login.php', '/signin'}
UPLOAD_PATHS    = {'/upload', '/api/data', '/file-upload'}

TYPE_SCORES = {
    'Ransomware': 50,
    'Malware C2': 40,
    'Phishing':   30,
    'Botnet':     25,
    'DDoS':       20,
}


# ══════════════════════════════════════════════════════════════════════════════
# Feed management
# ══════════════════════════════════════════════════════════════════════════════

def load_feed(force: bool = False) -> None:
    """Fetch Abuse.ch feeds and rebuild FEED_INDEX."""
    global FEED_INDEX
    logger.info("Loading Abuse.ch threat feeds...")
    indicators = fetcher.fetch_all(force=force)
    FEED_INDEX = fetcher.build_index(indicators)
    logger.info(f"Feed loaded: {len(FEED_INDEX)} unique indicators in index.")


# ══════════════════════════════════════════════════════════════════════════════
# Rule-based scoring engine  (Python port of the JS prototype logic)
# ══════════════════════════════════════════════════════════════════════════════

def compute_rule_score(
    log_entry:  Dict[str, Any],
    feed_entry: ThreatIndicator,
    occurrences: int
) -> Dict:
    """
    Rule-based scoring — identical logic to the JS prototype.
    Returns: { score, priority, breakdown }
    """
    score = 0
    breakdown = []

    # Base score from threat type
    base = TYPE_SCORES.get(feed_entry.type, 20)
    score += base
    breakdown.append({'rule': f'Threat type: {feed_entry.type}', 'points': base})

    # Multi-feed match
    feed_list = [feed_entry.source]   # Feodo or URLhaus
    if len(feed_list) >= 2:
        score += 20
        breakdown.append({'rule': f'Found in {len(feed_list)} feeds', 'points': 20})

    # Repeat in log
    if occurrences >= 3:
        score += 15
        breakdown.append({'rule': f'Repeated {occurrences}× in log', 'points': 15})

    # Unusual port
    port = int(log_entry.get('port', 80) or 80)
    if port in UNUSUAL_PORTS or feed_entry.port in UNUSUAL_PORTS:
        score += 10
        breakdown.append({'rule': f'Unusual port ({port})', 'points': 10})

    # Domain indicator
    if feed_entry.is_domain:
        score += 5
        breakdown.append({'rule': 'Domain indicator', 'points': 5})

    score = min(score, 100)
    priority = 'HIGH' if score >= 70 else 'MEDIUM' if score >= 40 else 'LOW'

    return {'score': score, 'priority': priority, 'breakdown': breakdown}


def compute_behaviour_score(entries: List[Dict[str, Any]]) -> Dict:
    """
    Behaviour-based heuristic scoring for one IP's log entries.
    Returns: { score, priority, rules_fired, feature_counts }
    """
    score = 0
    rules_fired = []
    n = len(entries)

    # Count relevant patterns
    brute_hits  = sum(1 for e in entries if e.get('path','') in AUTH_PATHS)
    sens_hits   = sum(1 for e in entries if e.get('path','') in SENSITIVE_PATHS)
    error_count = sum(1 for e in entries if str(e.get('status','200')) in {'403','404','500'})
    has_unusual = any(int(e.get('port', 80) or 80) in UNUSUAL_PORTS for e in entries)
    off_hours   = any(1 <= int(e.get('hour', 12) or 12) <= 5 for e in entries)
    has_upload  = any(
        str(e.get('method','GET')).upper() == 'POST' and e.get('path','') in UPLOAD_PATHS
        for e in entries
    )

    if n >= 5:
        score += 40;  rules_fired.append({'rule': f'High frequency ({n} connections)', 'points': 40})
    if brute_hits >= 3:
        score += 35;  rules_fired.append({'rule': f'Brute-force pattern ({brute_hits} auth hits)', 'points': 35})
    if sens_hits >= 1:
        score += 30;  rules_fired.append({'rule': f'Sensitive path access ({sens_hits} hits)', 'points': 30})
    if error_count >= 3:
        score += 25;  rules_fired.append({'rule': f'Excessive errors ({error_count})', 'points': 25})
    if has_unusual:
        score += 20;  rules_fired.append({'rule': 'Unusual port', 'points': 20})
    if off_hours:
        score += 15;  rules_fired.append({'rule': 'Off-hours activity (01:00–05:00)', 'points': 15})
    if has_upload:
        score += 10;  rules_fired.append({'rule': 'Upload attempt (POST)', 'points': 10})

    score = min(score, 100)
    priority = 'HIGH' if score >= 70 else 'MEDIUM' if score >= 40 else 'LOW'

    feature_counts = {
        'connection_count':    n,
        'brute_force_hits':    brute_hits,
        'sensitive_path_hits': sens_hits,
        'error_count':         error_count,
        'unusual_port':        int(has_unusual),
        'off_hours':           int(off_hours),
        'upload_attempt':      int(has_upload),
    }
    return {
        'score':          score,
        'priority':       priority,
        'rules_fired':    rules_fired,
        'feature_counts': feature_counts,
    }


def build_ml_features(
    log_entry:     Dict[str, Any],
    all_entries:   List[Dict[str, Any]],
    feed_entry,  # ThreatIndicator or None
    occurrences:   int
) -> Dict:
    """Build the feature dict that the ML classifier expects."""
    same_ip = [e for e in all_entries if e.get('ip') == log_entry.get('ip')]

    brute_hits  = sum(1 for e in same_ip if e.get('path','') in AUTH_PATHS)
    sens_hits   = sum(1 for e in same_ip if e.get('path','') in SENSITIVE_PATHS)
    error_count = sum(1 for e in same_ip if str(e.get('status','200')) in {'403','404','500'})
    port        = int(log_entry.get('port', 80) or 80)
    hour        = int(log_entry.get('hour', 12) or 12)

    in_feed     = 1 if feed_entry else 0
    feed_count  = 1 if feed_entry else 0
    type_score  = TYPE_SCORES.get(feed_entry.type, 0) if feed_entry else 0

    return {
        'connection_count':    occurrences,
        'brute_force_hits':    brute_hits,
        'sensitive_path_hits': sens_hits,
        'error_count':         error_count,
        'unusual_port':        int(port in UNUSUAL_PORTS),
        'off_hours':           int(1 <= hour <= 5),
        'upload_attempt':      int(
            str(log_entry.get('method','GET')).upper() == 'POST'
            and log_entry.get('path','') in UPLOAD_PATHS
        ),
        'in_feed':             in_feed,
        'feed_count':          feed_count,
        'threat_type_score':   type_score,
    }


# ══════════════════════════════════════════════════════════════════════════════
# Routes
# ══════════════════════════════════════════════════════════════════════════════

@app.route('/')
def index():
    """Serve the dashboard UI."""
    feed_count = len(FEED_INDEX)
    return render_template('index.html',
                           feed_count=feed_count,
                           ml_ready=classifier.is_loaded())


@app.route('/api/health')
def health():
    return jsonify({
        'status':         'ok',
        'feed_indicators': len(FEED_INDEX),
        'ml_loaded':       classifier.is_loaded(),
        'timestamp':       datetime.utcnow().isoformat() + 'Z',
    })


@app.route('/api/feed-status')
def feed_status():
    status = fetcher.get_status()
    status['indicators_in_index'] = len(FEED_INDEX)
    return jsonify(status)


@app.route('/api/refresh-feed', methods=['POST'])
def refresh_feed():
    load_feed(force=True)
    return jsonify({
        'success':    True,
        'indicators': len(FEED_INDEX),
        'message':    f'Feed refreshed: {len(FEED_INDEX)} indicators loaded.',
    })


@app.route('/api/indicators')
def list_indicators():
    """Return up to 200 indicators for the dashboard feed view."""
    items = [ind.to_dict() for ind in list(FEED_INDEX.values())[:200]]
    return jsonify({'count': len(FEED_INDEX), 'indicators': items})


@app.route('/api/analyze', methods=['POST'])
def analyze():
    """
    Analyse a single log entry.

    Request JSON:
    {
      "ip":     "185.220.101.12",
      "method": "GET",
      "path":   "/login",
      "status": "200",
      "port":   4444,
      "hour":   3,
      "log":    [... full current log entries ...]
    }

    Response JSON:
    {
      "ip": "...",
      "feed_match": { score, priority, breakdown } | null,
      "behaviour":  { score, priority, rules_fired } | null,
      "ml": { verdict, is_threat, confidence, confidence_pct, top_features },
      "combined_verdict": "THREAT" | "BENIGN",
      "combined_priority": "HIGH" | "MEDIUM" | "LOW" | "CLEAN",
      "combined_score": 0-100
    }
    """
    data = request.get_json(silent=True) or {}
    ip          = str(data.get('ip', '')).strip()
    log_entries = data.get('log', [data])   # full log if provided, else treat entry alone

    if not ip:
        return jsonify({'error': 'ip is required'}), 400

    # Occurrence count across log
    occ_map  = {}
    for entry in log_entries:
        k = entry.get('ip','')
        occ_map[k] = occ_map.get(k, 0) + 1
    occurrences = occ_map.get(ip, 1)

    # Feed match check
    feed_entry   = FEED_INDEX.get(ip)
    feed_result  = None
    if feed_entry:
        feed_result = compute_rule_score(data, feed_entry, occurrences)

    # Behaviour analysis
    same_ip_entries = [e for e in log_entries if e.get('ip') == ip]
    if not same_ip_entries:
        same_ip_entries = [data]
    beh_result = compute_behaviour_score(same_ip_entries)
    beh_result = beh_result if beh_result['score'] > 0 else None

    # ML classification
    ml_features = build_ml_features(data, log_entries, feed_entry, occurrences)
    ml_result   = classifier.classify(ml_features)
    ml_dict     = {
        'verdict':        ml_result.verdict,
        'is_threat':      ml_result.is_threat,
        'confidence':     ml_result.confidence,
        'confidence_pct': ml_result.confidence_pct,
        'top_features':   ml_result.top_features,
    }

    # Combined verdict
    rule_score = max(
        (feed_result['score'] if feed_result else 0),
        (beh_result['score']  if beh_result  else 0),
    )
    ml_boost = 10 if ml_result.is_threat and ml_result.confidence > 0.75 else 0
    combined_score = min(rule_score + ml_boost, 100)

    if combined_score == 0 and not ml_result.is_threat:
        combined_verdict  = 'BENIGN'
        combined_priority = 'CLEAN'
    elif combined_score >= 70 or (ml_result.is_threat and ml_result.confidence > 0.85):
        combined_verdict  = 'THREAT'
        combined_priority = 'HIGH'
    elif combined_score >= 40 or ml_result.is_threat:
        combined_verdict  = 'THREAT'
        combined_priority = 'MEDIUM'
    elif combined_score > 0:
        combined_verdict  = 'THREAT'
        combined_priority = 'LOW'
    else:
        combined_verdict  = 'BENIGN'
        combined_priority = 'CLEAN'

    return jsonify({
        'ip':                ip,
        'feed_match':        feed_result,
        'behaviour':         beh_result,
        'ml':                ml_dict,
        'combined_verdict':  combined_verdict,
        'combined_priority': combined_priority,
        'combined_score':    combined_score,
        'occurrences':       occurrences,
        'timestamp':         datetime.utcnow().isoformat() + 'Z',
    })


@app.route('/api/batch-analyze', methods=['POST'])
def batch_analyze():
    """
    Analyse a list of log entries in one call.

    Request JSON:
    {
      "log": [ {ip, method, path, status, port, hour}, ... ]
    }
    """
    data        = request.get_json(silent=True) or {}
    log_entries = data.get('log', [])
    if not log_entries:
        return jsonify({'error': 'log array is required'}), 400

    results = []
    seen    = set()

    # Occurrence map across whole log
    occ_map = {}
    for entry in log_entries:
        k = entry.get('ip','')
        occ_map[k] = occ_map.get(k, 0) + 1

    for entry in log_entries:
        ip = str(entry.get('ip','')).strip()
        if not ip or ip in seen:
            continue
        seen.add(ip)

        occurrences     = occ_map.get(ip, 1)
        feed_entry      = FEED_INDEX.get(ip)
        same_ip         = [e for e in log_entries if e.get('ip') == ip]
        feed_result     = compute_rule_score(entry, feed_entry, occurrences) if feed_entry else None
        beh_raw         = compute_behaviour_score(same_ip)
        beh_result      = beh_raw if beh_raw['score'] > 0 else None
        ml_features     = build_ml_features(entry, log_entries, feed_entry, occurrences)
        ml_result       = classifier.classify(ml_features)

        rule_score      = max(
            (feed_result['score'] if feed_result else 0),
            (beh_result['score']  if beh_result  else 0),
        )
        ml_boost        = 10 if ml_result.is_threat and ml_result.confidence > 0.75 else 0
        combined_score  = min(rule_score + ml_boost, 100)

        if combined_score >= 70 or (ml_result.is_threat and ml_result.confidence > 0.85):
            priority = 'HIGH'
        elif combined_score >= 40 or ml_result.is_threat:
            priority = 'MEDIUM'
        elif combined_score > 0:
            priority = 'LOW'
        else:
            priority = 'CLEAN'

        results.append({
            'ip':               ip,
            'combined_priority': priority,
            'combined_score':   combined_score,
            'ml_verdict':       ml_result.verdict,
            'ml_confidence':    ml_result.confidence_pct,
            'feed_match':       bool(feed_entry),
        })

    results.sort(key=lambda x: x['combined_score'], reverse=True)
    return jsonify({'count': len(results), 'results': results})


@app.route('/api/predict-only', methods=['POST'])
def predict_only():
    """
    ML classifier only — no rule engine.

    Request JSON: feature dict (see FEATURE_NAMES in classifier.py)
    Response JSON: { verdict, is_threat, confidence_pct, top_features }
    """
    features = request.get_json(silent=True) or {}
    result   = classifier.classify(features)
    return jsonify({
        'verdict':        result.verdict,
        'is_threat':      result.is_threat,
        'confidence_pct': result.confidence_pct,
        'top_features':   result.top_features,
        'feature_values': result.feature_values,
    })


# ══════════════════════════════════════════════════════════════════════════════
# Startup
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == '__main__':
    print("=" * 60)
    print("  CyberWatch ML Backend")
    print("  Aryan Nigam Dalal — 22103810 — 6COM2019")
    print("=" * 60)

    print("\n[1/2] Loading Abuse.ch threat feeds...")
    load_feed()

    print("\n[2/2] ML classifier ready:", classifier.is_loaded())
    print(f"\nFeed indicators loaded: {len(FEED_INDEX)}")
    print("\nStarting Flask server on http://localhost:5000")
    print("=" * 60)

    app.run(debug=True, host='0.0.0.0', port=5000)
