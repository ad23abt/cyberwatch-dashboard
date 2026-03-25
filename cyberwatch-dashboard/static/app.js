// ═══════════════════════════════════════════════════════════
// THREAT FEED DATABASE
// ═══════════════════════════════════════════════════════════
let THREAT_FEED_DB = [
  {indicator:'185.220.101.12',type:'Malware C2',  feeds:['Abuse.ch','ThreatFox'],      port:4444,isDomain:false},
  {indicator:'45.148.10.82',  type:'Ransomware',  feeds:['Abuse.ch'],                  port:443, isDomain:false},
  {indicator:'91.108.4.27',   type:'Botnet',      feeds:['AlienVault OTX','ThreatFox'],port:80,  isDomain:false},
  {indicator:'103.41.177.55', type:'Phishing',    feeds:['AlienVault OTX'],            port:443, isDomain:false},
  {indicator:'5.188.206.22',  type:'Malware C2',  feeds:['Abuse.ch','AlienVault OTX'], port:8080,isDomain:false},
  {indicator:'178.62.81.99',  type:'DDoS',        feeds:['AlienVault OTX'],            port:80,  isDomain:false},
  {indicator:'194.165.16.36', type:'Ransomware',  feeds:['Abuse.ch','ThreatFox'],      port:4444,isDomain:false},
  {indicator:'79.134.225.87', type:'Botnet',      feeds:['Abuse.ch'],                  port:6667,isDomain:false},
  {indicator:'23.94.24.12',   type:'Phishing',    feeds:['AlienVault OTX'],            port:443, isDomain:false},
  {indicator:'37.120.233.22', type:'Malware C2',  feeds:['Abuse.ch'],                  port:4444,isDomain:false},
  {indicator:'malware-dropper.ru',type:'Malware C2',feeds:['Abuse.ch','AlienVault OTX'],port:80, isDomain:true},
  {indicator:'phish-login.net',   type:'Phishing',  feeds:['AlienVault OTX'],           port:443, isDomain:true},
  {indicator:'botnet-c2.xyz',     type:'Botnet',    feeds:['ThreatFox'],                port:80,  isDomain:true},
  {indicator:'ransomware-cdn.io', type:'Ransomware',feeds:['Abuse.ch'],                 port:443, isDomain:true},
  {indicator:'exploit-kit.pw',    type:'Malware C2',feeds:['Abuse.ch','ThreatFox'],     port:8080,isDomain:true},
];
let customIndicators = [];

function rebuildFeedIndex(){
  FEED_INDEX={};
  THREAT_FEED_DB.forEach(e=>FEED_INDEX[e.indicator]=e);
}
let FEED_INDEX={};
rebuildFeedIndex();

// ═══════════════════════════════════════════════════════════
// SERVER LOG DATA
// ═══════════════════════════════════════════════════════════
const CLEAN_IPS=['192.168.1.1','10.0.0.5','172.16.0.22','8.8.8.8','1.1.1.1','93.184.216.34','203.0.113.5','198.51.100.2'];
const HTTP_METHODS=['GET','POST','HEAD','PUT'];
const PATHS=['/login','/api/data','/admin','/upload','/index.php','/.env','/wp-login.php','/config','/backup','/phpinfo.php'];
const HTTP_CODES=['200','200','200','404','403','500','302'];
const SENSITIVE_PATHS=['/.env','/config','/backup','/phpinfo.php','/admin','/wp-login.php'];
const UNUSUAL_PORTS=[4444,6667,1337,31337,9090];
const AUTH_PATHS=['/login','/admin','/wp-login.php'];

let LOCAL_LOG=[];
let alerts=[];
let logs=[];
let autoRunning=false;
let autoTimer=null;
let lineHistory=[];
let lineChart,barChart,pieChart;
let chartsReady=false;

const rFrom=a=>a[Math.floor(Math.random()*a.length)];
const rInt=(a,b)=>a+Math.floor(Math.random()*(b-a+1));
function timeNow(){return new Date().toLocaleTimeString('en-GB',{hour12:false});}
function dateNow(hour){
  const d=new Date();
  const h=hour!==undefined?String(hour).padStart(2,'0'):String(d.getHours()).padStart(2,'0');
  return `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')} ${h}:${String(d.getMinutes()).padStart(2,'0')}:${String(d.getSeconds()).padStart(2,'0')}`;
}

function makeLogEntry(forceMalicious){
  const allBad=THREAT_FEED_DB.filter(f=>!f.isDomain).map(f=>f.indicator);
  let ip;
  if(forceMalicious||Math.random()<0.4) ip=rFrom(allBad);
  else ip=rFrom(CLEAN_IPS);
  return{ip,method:rFrom(HTTP_METHODS),path:rFrom(PATHS),status:rFrom(HTTP_CODES),port:rFrom([80,443,8080,4444,6667,22]),hour:rInt(0,23),time:dateNow(),bytes:rInt(200,9999)};
}

function buildInitialLog(){
  LOCAL_LOG=[];
  for(let i=0;i<6;i++) LOCAL_LOG.push(makeLogEntry(true));
  for(let i=0;i<16;i++) LOCAL_LOG.push(makeLogEntry(false));
  LOCAL_LOG.sort(()=>Math.random()-0.5);
  renderLogViewer();
}

function renderLogViewer(){
  ['log-viewer','log-viewer-2'].forEach(id=>{
    const el=document.getElementById(id);
    if(!el) return;
    el.innerHTML=LOCAL_LOG.map(e=>{
      const isBad=!!FEED_INDEX[e.ip];
      const isUnusualPort=UNUSUAL_PORTS.includes(parseInt(e.port));
      const isSensitive=SENSITIVE_PATHS.includes(e.path);
      const flags=[];
      if(isBad) flags.push('<span class="lflag">FEED MATCH</span>');
      if(isUnusualPort) flags.push('<span class="lflag">UNUSUAL PORT</span>');
      if(isSensitive) flags.push('<span class="lflag">SENSITIVE PATH</span>');
      return`<div class="log-line">
        <span class="ltime">[${e.time}]</span>
        <span class="lip">${e.ip}</span>
        <span class="lmethod">${e.method}</span>
        <span style="color:var(--text)">${e.path}</span>
        <span class="lstatus">HTTP ${e.status}</span>
        <span class="lport">port:${e.port}</span>
        ${flags.join('')}
      </div>`;
    }).join('');
    const cnt=document.getElementById('log-entry-count');
    if(cnt) cnt.textContent=LOCAL_LOG.length+' entries';
  });
}

// ═══════════════════════════════════════════════════════════
// FEED CHIPS
// ═══════════════════════════════════════════════════════════
function renderFeedChips(){
  const el=document.getElementById('feed-chips');
  const cnt=document.getElementById('feed-count');
  if(el) el.innerHTML=THREAT_FEED_DB.map(f=>`<span style="font-family:var(--font-mono);font-size:11px;padding:3px 8px;border:1px solid rgba(255,59,92,0.4);background:rgba(255,59,92,0.08);color:var(--danger);cursor:default" title="${f.type} | ${f.feeds.join(', ')}">${f.indicator}</span>`).join('');
  if(cnt) cnt.textContent=THREAT_FEED_DB.length+' indicators';
}

// ═══════════════════════════════════════════════════════════
// FEED-BASED CORRELATION ENGINE
// ═══════════════════════════════════════════════════════════
function computeFeedScore(logEntry,feedEntry,occurrences){
  let score=0;const breakdown=[];
  const typeScores={'Ransomware':50,'Malware C2':40,'Phishing':30,'Botnet':25,'DDoS':20};
  const base=typeScores[feedEntry.type]||20;
  score+=base;breakdown.push({rule:`Threat type: ${feedEntry.type}`,val:`+${base}`});
  if(feedEntry.feeds.length>=2){score+=20;breakdown.push({rule:`Found in ${feedEntry.feeds.length} feeds`,val:'+20'});}
  if(occurrences>=3){score+=15;breakdown.push({rule:`Repeated ${occurrences}× in log`,val:'+15'});}
  if(UNUSUAL_PORTS.includes(feedEntry.port)||UNUSUAL_PORTS.includes(parseInt(logEntry.port))){score+=10;breakdown.push({rule:`Unusual port (${feedEntry.port})`,val:'+10'});}
  if(feedEntry.isDomain){score+=5;breakdown.push({rule:'Domain indicator',val:'+5'});}
  score=Math.min(score,100);
  return{score,priority:score>=70?'HIGH':score>=40?'MEDIUM':'LOW',breakdown};
}

function runCorrelation(){
  syslog('Feed correlation engine started...','info');
  const occMap={};
  LOCAL_LOG.forEach(e=>{occMap[e.ip]=(occMap[e.ip]||0)+1;});
  const seen=new Set();
  const results=[];
  LOCAL_LOG.forEach(logEntry=>{
    if(seen.has(logEntry.ip))return;
    seen.add(logEntry.ip);
    const feedEntry=FEED_INDEX[logEntry.ip];
    if(feedEntry){
      const {score,priority,breakdown}=computeFeedScore(logEntry,feedEntry,occMap[logEntry.ip]);
      results.push({indicator:logEntry.ip,type:feedEntry.type,feeds:feedEntry.feeds,score,priority,breakdown,occurrences:occMap[logEntry.ip],matched:true,detectionType:'FEED',status:'NEW',time:timeNow(),isNew:true});
      syslog(`[FEED MATCH] ${logEntry.ip} → ${feedEntry.type} | Score:${score} → ${priority}`,priority==='HIGH'?'alert':'warn');
    }
  });
  results.sort((a,b)=>b.score-a.score);
  results.forEach(r=>{
    if(!alerts.find(a=>a.indicator===r.indicator&&a.detectionType==='FEED')) alerts.unshift(r);
    else{const ex=alerts.find(a=>a.indicator===r.indicator&&a.detectionType==='FEED');if(ex){ex.score=r.score;ex.priority=r.priority;ex.breakdown=r.breakdown;}}
  });
  alerts.sort((a,b)=>b.score-a.score);
  renderCorrResults(results);
  updateAll();
  recordLineHistory(results.length);
  syslog(`Feed correlation complete: ${results.length} threats found.`,results.length>0?'alert':'info');
  showToast(`✅ ${results.length} threat(s) found by feed correlation`,'info');
}

function renderCorrResults(results){
  const el=document.getElementById('corr-results');
  const sum=document.getElementById('corr-summary');
  if(!el)return;
  const matched=results.filter(r=>r.matched);
  if(sum) sum.textContent=`${matched.length} threat(s) matched`;
  el.innerHTML=results.map(r=>{
    const sc=r.score>=70?'var(--danger)':r.score>=40?'var(--warn)':'var(--ok)';
    return`<div class="corr-card matched">
      <div class="corr-card-top">
        <span class="corr-ip">⚠️ ${r.indicator}</span>
        <span class="badge ${r.priority}">${r.priority}</span>
      </div>
      <div class="corr-step"><span class="csi">📋</span><span class="cst">Appears <strong>${r.occurrences}×</strong> in server log</span></div>
      <div class="corr-step"><span class="csi">🌐</span><span class="cst">Found in: <strong>${r.feeds.join(', ')}</strong></span></div>
      <div class="corr-step"><span class="csi">🏷️</span><span class="cst">Classified as: <strong>${r.type}</strong></span></div>
      <div class="score-breakdown">
        ${r.breakdown.map(b=>`<div class="score-row"><span class="sr-l">${b.rule}</span><span class="sr-v">${b.val}</span></div>`).join('')}
        <div class="score-row total"><span class="sr-l">FINAL RISK SCORE</span><span class="sr-v ${r.priority}" style="color:${sc}">${r.score}/100</span></div>
      </div>
    </div>`;
  }).join('');
}

// ═══════════════════════════════════════════════════════════
// BEHAVIOUR-BASED DETECTION ENGINE
// ═══════════════════════════════════════════════════════════
function runBehaviourAnalysis(){
  syslog('Behaviour detection engine started...','info');
  const ipMap={};
  LOCAL_LOG.forEach(e=>{
    if(!ipMap[e.ip]) ipMap[e.ip]={ip:e.ip,count:0,paths:[],statuses:[],ports:[],hours:[]};
    const m=ipMap[e.ip];
    m.count++; m.paths.push(e.path); m.statuses.push(e.status); m.ports.push(parseInt(e.port)); m.hours.push(parseInt(e.hour));
  });
  const results=[];
  Object.values(ipMap).forEach(m=>{
    // Skip IPs already flagged by feed
    let score=0; const breakdown=[];
    // Rule 1: High frequency
    if(m.count>=5){score+=40;breakdown.push({rule:`High frequency: ${m.count} connections`,val:'+40'});}
    // Rule 2: Brute force (repeated auth paths)
    const authHits=m.paths.filter(p=>AUTH_PATHS.includes(p)).length;
    if(authHits>=3){score+=35;breakdown.push({rule:`Brute force pattern: ${authHits} auth attempts`,val:'+35'});}
    // Rule 3: Sensitive path
    const sensHit=m.paths.find(p=>SENSITIVE_PATHS.includes(p));
    if(sensHit){score+=30;breakdown.push({rule:`Sensitive path accessed: ${sensHit}`,val:'+30'});}
    // Rule 4: Excessive errors
    const errCount=m.statuses.filter(s=>['403','404','500'].includes(s)).length;
    if(errCount>=3){score+=25;breakdown.push({rule:`Excessive errors: ${errCount} (403/404/500)`,val:'+25'});}
    // Rule 5: Unusual port
    const unusualPort=m.ports.find(p=>UNUSUAL_PORTS.includes(p));
    if(unusualPort){score+=20;breakdown.push({rule:`Unusual port detected: ${unusualPort}`,val:'+20'});}
    // Rule 6: Off-hours
    const offHour=m.hours.find(h=>h>=1&&h<=5);
    if(offHour!==undefined){score+=15;breakdown.push({rule:`Off-hours activity at ${String(offHour).padStart(2,'0')}:00`,val:'+15'});}
    // Rule 7: POST upload
    const logEntries=LOCAL_LOG.filter(e=>e.ip===m.ip);
    const uploadAttempt=logEntries.find(e=>e.method==='POST'&&['/upload','/api/data'].includes(e.path));
    if(uploadAttempt){score+=10;breakdown.push({rule:`POST to ${uploadAttempt.path}`,val:'+10'});}

    if(score>0){
      score=Math.min(score,100);
      const priority=score>=70?'HIGH':score>=40?'MEDIUM':'LOW';
      results.push({indicator:m.ip,type:'Suspicious Behaviour',feeds:['Behaviour Engine'],score,priority,breakdown,occurrences:m.count,matched:true,detectionType:'BEHAVIOUR',status:'NEW',time:timeNow(),isNew:true});
      syslog(`[BEHAVIOUR] ${m.ip} → Score:${score} → ${priority} (${breakdown[0].rule})`,priority==='HIGH'?'alert':'warn');
    }
  });
  results.sort((a,b)=>b.score-a.score);
  results.forEach(r=>{
    if(!alerts.find(a=>a.indicator===r.indicator&&a.detectionType==='BEHAVIOUR')) alerts.unshift(r);
  });
  alerts.sort((a,b)=>b.score-a.score);
  renderBehResults(results);
  updateAll();
  syslog(`Behaviour analysis complete: ${results.length} suspicious IPs found.`,results.length>0?'warn':'info');
  showToast(`🔬 ${results.length} suspicious IP(s) found by behaviour analysis`,'warn');
}

function renderBehResults(results){
  const el=document.getElementById('beh-results');
  const sum=document.getElementById('beh-summary');
  if(!el)return;
  if(sum) sum.textContent=`${results.length} suspicious IP(s) detected`;
  if(results.length===0){el.innerHTML=`<div style="color:var(--dim);font-family:var(--font-mono);font-size:12px;padding:20px">No suspicious behaviour detected in current log. Add more log entries with high frequency, unusual ports, or sensitive path access.</div>`;return;}
  el.innerHTML=results.map(r=>{
    const sc=r.score>=70?'var(--danger)':r.score>=40?'var(--warn)':'var(--ok)';
    return`<div class="corr-card behaviour">
      <div class="corr-card-top">
        <span class="corr-ip">🔬 ${r.indicator}</span>
        <span class="badge ${r.priority}">${r.priority}</span>
        <span class="badge BEHAVIOUR">BEHAVIOUR</span>
      </div>
      <div class="corr-step"><span class="csi">📋</span><span class="cst">Appears <strong>${r.occurrences}×</strong> in server log</span></div>
      <div class="corr-step"><span class="csi">⚠️</span><span class="cst">Detected by: <strong>Pattern Analysis (no feed needed)</strong></span></div>
      <div class="score-breakdown">
        ${r.breakdown.map(b=>`<div class="score-row"><span class="sr-l">${b.rule}</span><span class="sr-v">${b.val}</span></div>`).join('')}
        <div class="score-row total"><span class="sr-l">BEHAVIOUR RISK SCORE</span><span class="sr-v ${r.priority}" style="color:${sc}">${r.score}/100</span></div>
      </div>
    </div>`;
  }).join('');
}

// ═══════════════════════════════════════════════════════════
// USER INPUT FUNCTIONS
// ═══════════════════════════════════════════════════════════
function submitManualEntry(){
  const ip=document.getElementById('in-ip').value.trim();
  if(!ip){showToast('Please enter an IP address or domain','danger');return;}
  const entry={
    ip,
    method:document.getElementById('in-method').value,
    path:document.getElementById('in-path').value,
    port:document.getElementById('in-port').value,
    status:document.getElementById('in-status').value,
    hour:parseInt(document.getElementById('in-hour').value)||14,
    time:dateNow(document.getElementById('in-hour').value),
    bytes:rInt(200,9999)
  };
  LOCAL_LOG.unshift(entry);
  renderLogViewer();
  syslog(`Manual entry added: ${ip} → ${entry.method} ${entry.path} port:${entry.port}`,'info');
  showToast(`Entry added: ${ip} — running analysis...`,'info');
  runCorrelation();
  runBehaviourAnalysis();
  document.getElementById('in-ip').value='';
}

function addRandomEntry(){
  const entry=makeLogEntry(Math.random()<0.5);
  LOCAL_LOG.unshift(entry);
  renderLogViewer();
  syslog(`Random entry added: ${entry.ip}`,'info');
  showToast(`Random entry added: ${entry.ip}`,'info');
}

function clearLog(){
  LOCAL_LOG=[];
  renderLogViewer();
  syslog('Server log cleared.','info');
  showToast('Log cleared','warn');
}

function addCustomIndicator(){
  const ind=document.getElementById('cf-indicator').value.trim();
  if(!ind){showToast('Please enter an IP or domain','danger');return;}
  if(FEED_INDEX[ind]){showToast(`${ind} already in feed database`,'warn');return;}
  const type=document.getElementById('cf-type').value;
  const feed=document.getElementById('cf-feed').value;
  const isDomain=!/^\d/.test(ind);
  const newEntry={indicator:ind,type,feeds:[feed],port:80,isDomain,custom:true};
  THREAT_FEED_DB.push(newEntry);
  customIndicators.push(newEntry);
  rebuildFeedIndex();
  renderFeedChips();
  renderCustomChips();
  document.getElementById('cf-indicator').value='';
  syslog(`Custom indicator added: ${ind} (${type} via ${feed})`,'info');
  showToast(`✅ ${ind} added to threat feed!`,'info');
  runCorrelation();
}

function renderCustomChips(){
  const el=document.getElementById('custom-chips');
  const cnt=document.getElementById('custom-count');
  if(el) el.innerHTML=customIndicators.length===0
    ?`<span style="color:var(--dim);font-family:var(--font-mono);font-size:12px">No custom indicators added yet.</span>`
    :customIndicators.map(f=>`<span style="font-family:var(--font-mono);font-size:11px;padding:4px 10px;border:1px solid rgba(255,179,0,0.4);background:rgba(255,179,0,0.08);color:var(--warn)">${f.indicator} <span style="color:var(--dim)">(${f.type})</span></span>`).join('');
  if(cnt) cnt.textContent=customIndicators.length+' added';
}

// ═══════════════════════════════════════════════════════════
// ALERTS TABLE
// ═══════════════════════════════════════════════════════════
function renderAlertsTable(){
  const fp=document.getElementById('fp')?.value||'ALL';
  const fdet=document.getElementById('fdet')?.value||'ALL';
  const fs=document.getElementById('fs')?.value||'ALL';
  const srch=(document.getElementById('srch')?.value||'').toLowerCase();
  let list=alerts.filter(a=>{
    if(fp!=='ALL'&&a.priority!==fp)return false;
    if(fdet!=='ALL'&&a.detectionType!==fdet)return false;
    if(fs!=='ALL'&&a.status!==fs)return false;
    if(srch&&!a.indicator.toLowerCase().includes(srch))return false;
    return true;
  });
  const tbody=document.getElementById('alerts-tbody');
  if(!tbody)return;
  tbody.innerHTML=list.map((a,i)=>{
    const sc=a.score>=70?'#ff3b5c':a.score>=40?'#ffb300':'#00e676';
    const ri=alerts.indexOf(a);
    const reason=a.breakdown[0]?a.breakdown[0].rule:'Detected';
    return`<tr class="${a.isNew?'nr':''}">
      <td style="color:var(--dim)">${i+1}</td>
      <td style="color:var(--accent);font-size:11px">${a.indicator}</td>
      <td style="font-size:11px">${a.type}</td>
      <td><span class="badge ${a.detectionType}">${a.detectionType}</span></td>
      <td><span class="badge ${a.priority}">${a.priority}</span></td>
      <td><div class="sbar"><div class="strk"><div class="sfil" style="width:${a.score}%;background:${sc}"></div></div><span class="snum" style="color:${sc}">${a.score}</span></div></td>
      <td style="font-size:11px;color:var(--dim)">${reason}</td>
      <td><span class="badge ${a.status}">${a.status}</span></td>
      <td style="color:var(--dim);font-size:10px">${a.time}</td>
      <td style="white-space:nowrap">
        <button class="btn" style="padding:2px 7px;font-size:10px" onclick="setStatus(${ri},'INVESTIGATED')">✓</button>
        <button class="btn danger" style="padding:2px 7px;font-size:10px" onclick="setStatus(${ri},'BLOCKED')">🚫</button>
      </td>
    </tr>`;
  }).join('');
  setTimeout(()=>alerts.forEach(a=>a.isNew=false),1300);
}

function setStatus(idx,status){
  if(alerts[idx]){alerts[idx].status=status;syslog(`${alerts[idx].indicator} → ${status}`,'info');renderAlertsTable();}
}
function clearAlerts(){alerts=[];syslog('All alerts cleared.','info');renderAlertsTable();updateCards();updateCharts();}

// ═══════════════════════════════════════════════════════════
// CARDS & CHARTS
// ═══════════════════════════════════════════════════════════
function updateAll(){updateCards();renderAlertsTable();updateCharts();}

function updateCards(){
  const h=alerts.filter(a=>a.priority==='HIGH').length;
  const m=alerts.filter(a=>a.priority==='MEDIUM').length;
  const l=alerts.filter(a=>a.priority==='LOW').length;
  const t=alerts.length;
  [['d-high',h],['d-med',m],['d-low',l],['d-total',t],['a-high',h],['a-med',m],['a-low',l],['a-total',t]]
    .forEach(([id,v])=>{const e=document.getElementById(id);if(e)e.textContent=v;});
}

function initCharts(){
  Chart.defaults.color='#3a6080';
  const grid={color:'rgba(15,48,80,0.5)'};
  const font={family:'Share Tech Mono',size:10};
  const leg={labels:{color:'#3a6080',font}};
  barChart=new Chart(document.getElementById('barChart'),{
    type:'bar',
    data:{labels:['Ransomware','Malware C2','Phishing','Botnet','DDoS','Behaviour','Other'],
      datasets:[
        {label:'HIGH',  data:Array(7).fill(0),backgroundColor:'rgba(255,59,92,0.75)', borderColor:'#ff3b5c',borderWidth:1},
        {label:'MEDIUM',data:Array(7).fill(0),backgroundColor:'rgba(255,179,0,0.65)',borderColor:'#ffb300',borderWidth:1},
        {label:'LOW',   data:Array(7).fill(0),backgroundColor:'rgba(0,230,118,0.55)',borderColor:'#00e676',borderWidth:1},
      ]},
    options:{responsive:true,maintainAspectRatio:true,plugins:{legend:leg},scales:{x:{grid,stacked:true,ticks:{color:'#3a6080',font}},y:{grid,stacked:true,beginAtZero:true,ticks:{stepSize:1,color:'#3a6080',font}}}}
  });
  pieChart=new Chart(document.getElementById('pieChart'),{
    type:'doughnut',
    data:{labels:['HIGH','MEDIUM','LOW'],datasets:[{data:[1,1,1],backgroundColor:['rgba(255,59,92,0.8)','rgba(255,179,0,0.8)','rgba(0,230,118,0.8)'],borderColor:'#0a1520',borderWidth:2}]},
    options:{responsive:true,maintainAspectRatio:true,plugins:{legend:leg}}
  });
  lineChart=new Chart(document.getElementById('lineChart'),{
    type:'line',
    data:{labels:[],datasets:[{label:'Threats per run',data:[],borderColor:'#00e5ff',backgroundColor:'rgba(0,229,255,0.07)',fill:true,tension:0.4,pointBackgroundColor:'#00e5ff',pointRadius:4}]},
    options:{responsive:true,maintainAspectRatio:true,plugins:{legend:leg},scales:{x:{grid,ticks:{color:'#3a6080',font}},y:{grid,beginAtZero:true,ticks:{stepSize:1,color:'#3a6080',font}}}}
  });
  chartsReady=true;
}

function recordLineHistory(count){
  lineHistory.push({label:`R${lineHistory.length+1}`,count});
  if(lineHistory.length>12)lineHistory.shift();
  lineChart.data.labels=lineHistory.map(h=>h.label);
  lineChart.data.datasets[0].data=lineHistory.map(h=>h.count);
  lineChart.update();
}

function updateCharts(){
  if(!chartsReady)return;
  const TYPES=['Ransomware','Malware C2','Phishing','Botnet','DDoS','Behaviour','Other'];
  const hc=Object.fromEntries(TYPES.map(t=>[t,0]));
  const mc=Object.fromEntries(TYPES.map(t=>[t,0]));
  const lc=Object.fromEntries(TYPES.map(t=>[t,0]));
  alerts.forEach(a=>{
    const k=a.detectionType==='BEHAVIOUR'?'Behaviour':(TYPES.includes(a.type)?a.type:'Other');
    if(a.priority==='HIGH')hc[k]++;else if(a.priority==='MEDIUM')mc[k]++;else lc[k]++;
  });
  barChart.data.datasets[0].data=TYPES.map(t=>hc[t]);
  barChart.data.datasets[1].data=TYPES.map(t=>mc[t]);
  barChart.data.datasets[2].data=TYPES.map(t=>lc[t]);
  barChart.update();
  const h=alerts.filter(a=>a.priority==='HIGH').length;
  const m=alerts.filter(a=>a.priority==='MEDIUM').length;
  const l=alerts.filter(a=>a.priority==='LOW').length;
  pieChart.data.datasets[0].data=[h,m,l].some(v=>v>0)?[h,m,l]:[1,1,1];
  pieChart.update();
}

// ═══════════════════════════════════════════════════════════
// FEEDS PAGE
// ═══════════════════════════════════════════════════════════
const FEED_DATA=[
  {name:'Abuse.ch',status:'active',updated:'2 mins ago',count:1247,pct:88,desc:'Malware botnet C2 tracker'},
  {name:'AlienVault OTX',status:'active',updated:'5 mins ago',count:3821,pct:75,desc:'Community threat intelligence'},
  {name:'ThreatFox',status:'active',updated:'12 mins ago',count:892,pct:65,desc:'IOC sharing platform'},
  {name:'URLhaus',status:'inactive',updated:'1 hour ago',count:5634,pct:50,desc:'Malicious URL database'},
];
function renderFeeds(){
  const el=document.getElementById('feeds-grid');
  if(!el)return;
  el.innerHTML=FEED_DATA.map(f=>`<div class="fcard">
    <div class="fcard-top"><div class="fname">🌐 ${f.name}</div><div class="fstatus ${f.status}"><div class="fdot ${f.status}"></div>${f.status.toUpperCase()}</div></div>
    <div style="font-size:12px;color:var(--dim);margin-bottom:10px">${f.desc}</div>
    <div class="fmeta">
      <div><div class="fml">Last Updated</div><div class="fmv">${f.updated}</div></div>
      <div><div class="fml">Indicators</div><div class="fmv">${f.count.toLocaleString()}</div></div>
      <div><div class="fml">Confidence</div><div class="fmv" style="color:var(--accent)">${f.pct}%</div></div>
      <div><div class="fml">Status</div><div class="fmv" style="color:${f.status==='active'?'var(--ok)':'var(--dim)'}">${f.status}</div></div>
    </div>
    <div class="fbar"><div class="fbarf" style="width:${f.pct}%;background:${f.status==='active'?'var(--accent)':'var(--dim)'}"></div></div>
  </div>`).join('');
}

// ═══════════════════════════════════════════════════════════
// SYSLOG
// ═══════════════════════════════════════════════════════════
function syslog(msg,lvl='info'){
  logs.unshift({t:timeNow(),msg,lvl});
  if(logs.length>60)logs.pop();
  const el=document.getElementById('syslog-body');
  if(el)el.innerHTML=logs.map(e=>`<div class="log-entry"><span class="lt">[${e.t}]</span><span class="lm ${e.lvl}">${e.msg}</span></div>`).join('');
  const lc=document.getElementById('log-count');
  if(lc)lc.textContent=logs.length+' entries';
}

// ═══════════════════════════════════════════════════════════
// TOAST NOTIFICATION (BUG FIX: replaces page-navigation on events)
// ═══════════════════════════════════════════════════════════
let toastTimer=null;
function showToast(msg,type='info'){
  const el=document.getElementById('toast');
  el.textContent=msg;
  el.className='toast '+(type==='danger'?'danger':type==='warn'?'warn':'');
  el.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer=setTimeout(()=>el.classList.remove('show'),3000);
}

// ═══════════════════════════════════════════════════════════
// AUTO SIMULATE
// ═══════════════════════════════════════════════════════════
function toggleAuto(){
  const btn=document.getElementById('auto-btn');
  if(autoRunning){
    clearInterval(autoTimer);autoRunning=false;
    btn.textContent='⟳ Auto Simulate';
    syslog('Auto simulation paused.','info');
  }else{
    autoRunning=true;btn.textContent='⏸ Pause';
    syslog('Auto simulation active.','info');
    autoTimer=setInterval(()=>{
      makeLogEntry(Math.random()<0.5);
      LOCAL_LOG.unshift(makeLogEntry(Math.random()<0.5));
      renderLogViewer();
      runCorrelation();
      runBehaviourAnalysis();
    },5000);
  }
}

function resetEngine(){
  document.getElementById('corr-results').innerHTML='';
  document.getElementById('corr-summary').textContent='Run the engine above to see results';
  syslog('Engine results cleared.','info');
}
function resetBehaviour(){
  const el=document.getElementById('beh-results');
  if(el)el.innerHTML='';
  const sum=document.getElementById('beh-summary');
  if(sum)sum.textContent='Run analysis above to see results';
  syslog('Behaviour results cleared.','info');
}

// ═══════════════════════════════════════════════════════════
// NAV (BUG FIX: no longer navigates on run buttons)
// ═══════════════════════════════════════════════════════════
const PAGE_TITLES={dashboard:'📊 DASHBOARD',engine:'⚙️ CORRELATION ENGINE',behaviour:'🔬 BEHAVIOUR DETECTION',alerts:'⚠️ ALERTS TABLE',input:'✏️ ADD LOG ENTRY',customfeed:'➕ ADD THREAT INDICATOR',feeds:'🌐 THREAT FEEDS',howworks:'🧠 HOW IT WORKS',settings:'⚙️ SETTINGS'};
function showPage(id,el){
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n=>n.classList.remove('active'));
  const pg=document.getElementById('page-'+id);
  if(pg)pg.classList.add('active');
  if(el)el.classList.add('active');
  const title=document.getElementById('page-title');
  if(title)title.textContent=PAGE_TITLES[id]||id.toUpperCase();
}

// ═══════════════════════════════════════════════════════════
// CLOCK
// ═══════════════════════════════════════════════════════════
function updateClock(){const el=document.getElementById('clock');if(el)el.textContent=new Date().toLocaleString('en-GB',{hour12:false,year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit'});}
setInterval(updateClock,1000);updateClock();

// ═══════════════════════════════════════════════════════════
// INIT
// ═══════════════════════════════════════════════════════════
initCharts();
buildInitialLog();
renderFeedChips();
renderFeeds();
renderCustomChips();
syslog('CyberWatch v3.0 initialised — Feed + Behaviour engines ready.','info');
syslog('Threat feed loaded: '+THREAT_FEED_DB.length+' indicators.','info');
syslog('Server log loaded: '+LOCAL_LOG.length+' entries.','info');
syslog('Click "Run Correlation" or "Run Behaviour" to begin.','info');