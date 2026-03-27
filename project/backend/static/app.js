/* CyberWatch ML Backend — app.js
   Talks to the Flask API at /api/* */

'use strict';

const API = window.location.origin;

// ── Alerts store ─────────────────────────────────────────────────────────────
let ALERTS = [];

// ── Navigation ───────────────────────────────────────────────────────────────
function showPage(id, el) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  const page = document.getElementById('page-' + id);
  if (page) page.classList.add('active');
  if (el) el.classList.add('active');

  // Lazy load per-page data
  if (id === 'feeds') loadFeedStatus();
}

// ── Clock ─────────────────────────────────────────────────────────────────────
function updateClock() {
  const el = document.getElementById('clock');
  if (el) el.textContent = new Date().toLocaleString('en-GB', {
    hour12: false, year:'numeric', month:'2-digit', day:'2-digit',
    hour:'2-digit', minute:'2-digit', second:'2-digit'
  });
}
setInterval(updateClock, 1000);
updateClock();

// ── Toast ─────────────────────────────────────────────────────────────────────
function toast(msg, type = 'info') {
  const el = document.createElement('div');
  el.className = 'toast';
  el.style.borderColor = type === 'error' ? 'var(--danger)'
                       : type === 'ok'    ? 'var(--ok)'
                       : 'var(--border2)';
  el.textContent = msg;
  document.body.appendChild(el);
  setTimeout(() => el.remove(), 3200);
}

// ── API helpers ───────────────────────────────────────────────────────────────
async function apiFetch(path, options = {}) {
  const resp = await fetch(API + path, {
    headers: { 'Content-Type': 'application/json' },
    ...options
  });
  if (!resp.ok) throw new Error(`HTTP ${resp.status}: ${resp.statusText}`);
  return resp.json();
}

// ── Result rendering helpers ──────────────────────────────────────────────────
function verdictBadge(v) {
  return `<span class="badge badge-${v}">${v}</span>`;
}

function confBar(pct) {
  const col = pct >= 80 ? 'var(--danger)'
            : pct >= 50 ? 'var(--warn)'
            : 'var(--ok)';
  return `<div class="conf-bar-wrap"><div class="conf-bar-fill"
    style="width:${pct}%;background:${col}"></div></div>`;
}

function renderAnalysisResult(data) {
  const feed = data.feed_match;
  const beh  = data.behaviour;
  const ml   = data.ml;

  let html = `<div class="result-grid">
    <div class="result-box">
      <div class="rb-label">COMBINED VERDICT</div>
      <div class="rb-value">${verdictBadge(data.combined_verdict)}</div>
    </div>
    <div class="result-box">
      <div class="rb-label">PRIORITY</div>
      <div class="rb-value verdict-${data.combined_priority}">${data.combined_priority}</div>
    </div>
    <div class="result-box">
      <div class="rb-label">COMBINED SCORE</div>
      <div class="rb-value" style="color:var(--accent)">${data.combined_score}/100</div>
    </div>
    <div class="result-box">
      <div class="rb-label">ML VERDICT</div>
      <div class="rb-value">${verdictBadge(ml.verdict)}</div>
    </div>
    <div class="result-box">
      <div class="rb-label">ML CONFIDENCE</div>
      <div class="rb-value" style="font-size:16px;margin-top:4px">
        ${ml.confidence_pct}%<br>${confBar(ml.confidence_pct)}
      </div>
    </div>
    <div class="result-box">
      <div class="rb-label">OCCURRENCES</div>
      <div class="rb-value" style="color:var(--warn)">${data.occurrences}×</div>
    </div>
  </div>`;

  // Feed match
  if (feed) {
    html += `<div style="margin-bottom:12px">
      <div class="section-title">FEED MATCH (Abuse.ch)</div>
      <ul class="breakdown-list">
        ${feed.breakdown.map(r =>
          `<li><span>${r.rule}</span><span class="pts">+${r.points}</span></li>`
        ).join('')}
        <li style="font-weight:700"><span>FEED SCORE</span><span class="pts">${feed.score}</span></li>
      </ul>
    </div>`;
  } else {
    html += `<div style="color:var(--dim);font-size:11px;margin-bottom:12px">
      ✓ No match in Abuse.ch feed
    </div>`;
  }

  // Behaviour
  if (beh && beh.rules_fired && beh.rules_fired.length > 0) {
    html += `<div style="margin-bottom:12px">
      <div class="section-title">BEHAVIOUR ENGINE</div>
      <ul class="breakdown-list">
        ${beh.rules_fired.map(r =>
          `<li><span>${r.rule}</span><span class="pts">+${r.points}</span></li>`
        ).join('')}
        <li style="font-weight:700"><span>BEHAVIOUR SCORE</span><span class="pts">${beh.score}</span></li>
      </ul>
    </div>`;
  }

  // ML top features
  if (ml.top_features && ml.top_features.length > 0) {
    html += `<div>
      <div class="section-title">ML TOP FEATURES</div>
      <ul class="breakdown-list">
        ${ml.top_features.map(f =>
          `<li>
            <span>${f.feature.replace(/_/g,' ')}: <span style="color:var(--accent)">${f.value}</span></span>
            <span class="pts">importance: ${f.importance}</span>
          </li>`
        ).join('')}
      </ul>
    </div>`;
  }

  return html;
}

// ── Update counters ───────────────────────────────────────────────────────────
function updateCounters() {
  const high = ALERTS.filter(a => a.priority === 'HIGH').length;
  const med  = ALERTS.filter(a => a.priority === 'MEDIUM').length;
  const low  = ALERTS.filter(a => ['LOW','CLEAN'].includes(a.priority)).length;
  const el = (id, v) => { const e = document.getElementById(id); if(e) e.textContent = v; };
  el('c-high', high); el('c-med', med); el('c-low', low);
}

function renderAlertsTable() {
  const wrap = document.getElementById('alerts-table-wrap');
  if (!wrap) return;
  if (!ALERTS.length) {
    wrap.innerHTML = '<p class="dim-text">No alerts yet. Analyse an entry above to get started.</p>';
    return;
  }
  const sorted = [...ALERTS].sort((a,b) => b.score - a.score);
  wrap.innerHTML = `
    <table class="alerts-table">
      <thead>
        <tr>
          <th>IP</th><th>VERDICT</th><th>PRIORITY</th>
          <th>SCORE</th><th>ML</th><th>CONFIDENCE</th><th>TIME</th>
        </tr>
      </thead>
      <tbody>
        ${sorted.map(a => `<tr>
          <td>${a.ip}</td>
          <td>${verdictBadge(a.verdict)}</td>
          <td class="verdict-${a.priority}">${a.priority}</td>
          <td style="color:var(--accent)">${a.score}</td>
          <td>${verdictBadge(a.ml_verdict)}</td>
          <td>${confBar(a.ml_conf)} ${a.ml_conf}%</td>
          <td style="color:var(--dim);font-size:10px">${a.time}</td>
        </tr>`).join('')}
      </tbody>
    </table>`;
}

function storeAlert(ip, data) {
  ALERTS = ALERTS.filter(a => a.ip !== ip);   // replace existing entry
  ALERTS.push({
    ip,
    verdict:    data.combined_verdict,
    priority:   data.combined_priority,
    score:      data.combined_score,
    ml_verdict: data.ml.verdict,
    ml_conf:    data.ml.confidence_pct,
    time:       new Date().toLocaleTimeString('en-GB', {hour12:false}),
  });
  updateCounters();
  renderAlertsTable();
}

// ── Quick analyse (dashboard page) ───────────────────────────────────────────
async function quickAnalyze() {
  const ip     = document.getElementById('q-ip').value.trim();
  const path   = document.getElementById('q-path').value.trim() || '/';
  const method = document.getElementById('q-method').value;
  const status = document.getElementById('q-status').value || '200';
  const port   = parseInt(document.getElementById('q-port').value) || 80;
  const hour   = parseInt(document.getElementById('q-hour').value) || 12;

  if (!ip) { toast('Enter an IP address', 'error'); return; }

  const resultEl = document.getElementById('quick-result');
  const inner    = document.getElementById('quick-result-inner');
  resultEl.style.display = 'block';
  inner.innerHTML = '<span class="spinner"></span> Analysing against Abuse.ch feed + ML model...';

  try {
    const data = await apiFetch('/api/analyze', {
      method: 'POST',
      body: JSON.stringify({ ip, path, method, status, port, hour })
    });
    inner.innerHTML = renderAnalysisResult(data);
    storeAlert(ip, data);
    toast(`${ip} → ${data.combined_verdict} (${data.combined_priority})`,
          data.combined_verdict === 'THREAT' ? 'error' : 'ok');
  } catch (e) {
    inner.innerHTML = `<p style="color:var(--danger)">Error: ${e.message}</p>`;
    toast('Analysis failed: ' + e.message, 'error');
  }
}

// ── Full analyse (analyze page) ───────────────────────────────────────────────
async function fullAnalyze() {
  const ip      = document.getElementById('a-ip').value.trim();
  const method  = document.getElementById('a-method').value;
  const path    = document.getElementById('a-path').value.trim() || '/';
  const status  = document.getElementById('a-status').value || '200';
  const port    = parseInt(document.getElementById('a-port').value) || 80;
  const hour    = parseInt(document.getElementById('a-hour').value) || 12;
  const conn    = parseInt(document.getElementById('a-conncount').value) || 1;
  const brute   = parseInt(document.getElementById('a-brute').value) || 0;
  const sens    = parseInt(document.getElementById('a-sensitive').value) || 0;
  const errs    = parseInt(document.getElementById('a-errors').value) || 0;

  if (!ip) { toast('Enter an IP address', 'error'); return; }

  const resultEl = document.getElementById('full-result');
  const inner    = document.getElementById('full-result-inner');
  resultEl.style.display = 'block';
  inner.innerHTML = '<span class="spinner"></span> Running full analysis...';

  // Build a synthetic log so the API can compute behaviour
  const logEntries = Array.from({length: conn}, (_, i) => ({
    ip, method: i < brute ? 'POST' : method,
    path: i < sens ? '/.env' : path,
    status: i < errs ? '403' : status,
    port, hour
  }));

  try {
    const data = await apiFetch('/api/analyze', {
      method: 'POST',
      body: JSON.stringify({ ip, method, path, status, port, hour, log: logEntries })
    });
    inner.innerHTML = renderAnalysisResult(data);
    storeAlert(ip, data);
  } catch (e) {
    inner.innerHTML = `<p style="color:var(--danger)">Error: ${e.message}</p>`;
    toast('Analysis failed: ' + e.message, 'error');
  }
}

function fillExample(type) {
  if (type === 'bad') {
    document.getElementById('a-ip').value       = '185.220.101.12';
    document.getElementById('a-path').value     = '/admin';
    document.getElementById('a-method').value   = 'POST';
    document.getElementById('a-status').value   = '403';
    document.getElementById('a-port').value     = '4444';
    document.getElementById('a-hour').value     = '3';
    document.getElementById('a-conncount').value= '7';
    document.getElementById('a-brute').value    = '4';
    document.getElementById('a-sensitive').value= '2';
    document.getElementById('a-errors').value   = '5';
  } else {
    document.getElementById('a-ip').value       = '192.168.1.100';
    document.getElementById('a-path').value     = '/index.html';
    document.getElementById('a-method').value   = 'GET';
    document.getElementById('a-status').value   = '200';
    document.getElementById('a-port').value     = '80';
    document.getElementById('a-hour').value     = '14';
    document.getElementById('a-conncount').value= '2';
    document.getElementById('a-brute').value    = '0';
    document.getElementById('a-sensitive').value= '0';
    document.getElementById('a-errors').value   = '0';
  }
}

// ── Batch analyse ─────────────────────────────────────────────────────────────
function loadSampleBatch() {
  const sample = {
    log: [
      {ip:'185.220.101.12', method:'POST', path:'/login', status:'403', port:4444, hour:3},
      {ip:'185.220.101.12', method:'POST', path:'/admin', status:'403', port:4444, hour:3},
      {ip:'185.220.101.12', method:'GET',  path:'/.env',  status:'404', port:4444, hour:3},
      {ip:'8.8.8.8',        method:'GET',  path:'/',      status:'200', port:80,   hour:14},
      {ip:'10.0.0.5',       method:'GET',  path:'/api',   status:'200', port:80,   hour:10},
      {ip:'45.148.10.82',   method:'GET',  path:'/login', status:'200', port:443,  hour:7},
      {ip:'192.168.1.50',   method:'GET',  path:'/page',  status:'200', port:80,   hour:9},
      {ip:'103.41.177.55',  method:'POST', path:'/login', status:'401', port:443,  hour:2},
      {ip:'1.1.1.1',        method:'HEAD', path:'/',      status:'200', port:80,   hour:11},
      {ip:'194.165.16.36',  method:'GET',  path:'/wp-login.php', status:'200', port:4444, hour:4},
    ]
  };
  document.getElementById('batch-input').value = JSON.stringify(sample, null, 2);
}

async function runBatch() {
  const raw = document.getElementById('batch-input').value.trim();
  if (!raw) { toast('Paste a JSON log first', 'error'); return; }

  let body;
  try { body = JSON.parse(raw); } catch(e) {
    toast('Invalid JSON: ' + e.message, 'error'); return;
  }

  const resultEl = document.getElementById('batch-result');
  resultEl.innerHTML = '<div class="panel"><span class="spinner"></span> Analysing batch...</div>';

  try {
    const data = await apiFetch('/api/batch-analyze', {
      method: 'POST',
      body: JSON.stringify(body)
    });

    const rows = data.results.map(r => `<tr>
      <td>${r.ip}</td>
      <td>${verdictBadge(r.ml_verdict)}</td>
      <td class="verdict-${r.combined_priority}">${r.combined_priority}</td>
      <td style="color:var(--accent)">${r.combined_score}</td>
      <td>${r.feed_match ? '✓ FEED MATCH' : '—'}</td>
      <td>${confBar(r.ml_confidence)} ${r.ml_confidence}%</td>
    </tr>`).join('');

    resultEl.innerHTML = `
      <div class="section-title">${data.count} UNIQUE IPs ANALYSED — RANKED BY SCORE</div>
      <table class="alerts-table">
        <thead>
          <tr><th>IP</th><th>ML VERDICT</th><th>PRIORITY</th>
              <th>SCORE</th><th>FEED</th><th>CONFIDENCE</th></tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>`;
    toast(`Batch complete: ${data.count} IPs analysed`, 'ok');
  } catch (e) {
    resultEl.innerHTML = `<p style="color:var(--danger)">Error: ${e.message}</p>`;
    toast('Batch failed: ' + e.message, 'error');
  }
}

// ── Feed status ───────────────────────────────────────────────────────────────
async function loadFeedStatus() {
  const setEl = (id, v) => { const e=document.getElementById(id); if(e) e.textContent=v; };

  try {
    const status = await apiFetch('/api/feed-status');
    setEl('feed-total', status.indicators_in_index ?? status.total_indicators ?? '—');
    setEl('feed-count-top', status.indicators_in_index ?? '—');
    setEl('c-feed', status.indicators_in_index ?? '—');

    const age = status.cache_age_seconds;
    setEl('feed-age', age != null ? Math.round(age) + 's' : '—');
    setEl('feed-last', status.last_fetch
      ? new Date(status.last_fetch * 1000).toLocaleTimeString('en-GB', {hour12:false})
      : '—');

    // Load indicators
    const indData = await apiFetch('/api/indicators');
    const listEl  = document.getElementById('indicator-list');
    if (listEl) {
      if (!indData.indicators || !indData.indicators.length) {
        listEl.innerHTML = '<p class="dim-text">No live indicators loaded. Is Abuse.ch reachable?</p>';
      } else {
        listEl.innerHTML = indData.indicators.map(ind => `
          <div class="indicator-row">
            <span class="ind-ip">${ind.indicator}</span>
            <span class="ind-type">${ind.type}</span>
            <span class="ind-src">${ind.source} · port ${ind.port} · ${ind.status}</span>
            <span style="color:var(--dim);font-size:10px">${ind.malware || ''}</span>
          </div>`).join('');
      }
    }
  } catch (e) {
    toast('Feed status error: ' + e.message, 'error');
  }
}

async function refreshFeed() {
  toast('Refreshing Abuse.ch feed...', 'info');
  try {
    const data = await apiFetch('/api/refresh-feed', { method: 'POST' });
    toast(data.message, 'ok');
    await loadFeedStatus();
  } catch (e) {
    toast('Refresh failed: ' + e.message, 'error');
  }
}

// ── ML predict only ───────────────────────────────────────────────────────────
async function mlPredict() {
  const features = {
    connection_count:    parseInt(document.getElementById('ml-conn').value)    || 0,
    brute_force_hits:    parseInt(document.getElementById('ml-brute').value)   || 0,
    sensitive_path_hits: parseInt(document.getElementById('ml-sens').value)    || 0,
    error_count:         parseInt(document.getElementById('ml-err').value)     || 0,
    unusual_port:        parseInt(document.getElementById('ml-uport').value)   || 0,
    off_hours:           parseInt(document.getElementById('ml-ofh').value)     || 0,
    upload_attempt:      parseInt(document.getElementById('ml-upl').value)     || 0,
    in_feed:             parseInt(document.getElementById('ml-infeed').value)  || 0,
    feed_count:          parseInt(document.getElementById('ml-feedcnt').value) || 0,
    threat_type_score:   parseInt(document.getElementById('ml-ttscore').value) || 0,
  };

  const resultEl = document.getElementById('ml-result');
  resultEl.innerHTML = '<div class="panel"><span class="spinner"></span> Running ML prediction...</div>';

  try {
    const data = await apiFetch('/api/predict-only', {
      method: 'POST',
      body: JSON.stringify(features)
    });

    resultEl.innerHTML = `<div class="panel result-panel">
      <div class="result-grid">
        <div class="result-box">
          <div class="rb-label">ML VERDICT</div>
          <div class="rb-value">${verdictBadge(data.verdict)}</div>
        </div>
        <div class="result-box">
          <div class="rb-label">CONFIDENCE</div>
          <div class="rb-value" style="font-size:18px;margin-top:4px">
            ${data.confidence_pct}%<br>${confBar(data.confidence_pct)}
          </div>
        </div>
      </div>
      <div class="section-title" style="margin-top:10px">TOP FEATURES DRIVING PREDICTION</div>
      <ul class="breakdown-list">
        ${data.top_features.map(f => `
          <li>
            <span>${f.feature.replace(/_/g,' ')}: <span style="color:var(--accent)">${f.value}</span></span>
            <span class="pts">importance: ${f.importance}</span>
          </li>`).join('')}
      </ul>
    </div>`;
    toast(`Prediction: ${data.verdict} (${data.confidence_pct}% confidence)`,
          data.verdict === 'THREAT' ? 'error' : 'ok');
  } catch (e) {
    resultEl.innerHTML = `<p style="color:var(--danger)">Error: ${e.message}</p>`;
    toast('Prediction failed: ' + e.message, 'error');
  }
}

function mlFillThreat() {
  document.getElementById('ml-conn').value    = 7;
  document.getElementById('ml-brute').value   = 4;
  document.getElementById('ml-sens').value    = 2;
  document.getElementById('ml-err').value     = 5;
  document.getElementById('ml-uport').value   = 1;
  document.getElementById('ml-ofh').value     = 1;
  document.getElementById('ml-upl').value     = 1;
  document.getElementById('ml-infeed').value  = 1;
  document.getElementById('ml-feedcnt').value = 2;
  document.getElementById('ml-ttscore').value = 50;
}

function mlFillClean() {
  document.getElementById('ml-conn').value    = 1;
  document.getElementById('ml-brute').value   = 0;
  document.getElementById('ml-sens').value    = 0;
  document.getElementById('ml-err').value     = 0;
  document.getElementById('ml-uport').value   = 0;
  document.getElementById('ml-ofh').value     = 0;
  document.getElementById('ml-upl').value     = 0;
  document.getElementById('ml-infeed').value  = 0;
  document.getElementById('ml-feedcnt').value = 0;
  document.getElementById('ml-ttscore').value = 0;
}
