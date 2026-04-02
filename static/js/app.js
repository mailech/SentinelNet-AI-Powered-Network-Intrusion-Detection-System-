/* ═══════════════════════════════════════════════════════
   SentinelNet – Frontend App (with CSV Analyzer)
   ═══════════════════════════════════════════════════════ */

const API = 'http://localhost:5000';

let liveInterval  = null;
let statsInterval = null;
let allLogs       = [];
let allAlerts     = [];
let charts        = {};
let backendOnline = false;
let localStats    = { total: 0, attacks: 0, normal: 0, critical: 0, detection_rate: 0 };

// CSV Analyzer state
let csvResults  = [];
let csvFiltered = [];
let csvCharts   = {};

const timelineData = { labels: [], attacks: [], normals: [] };
const protCounts   = { TCP: 0, UDP: 0, ICMP: 0 };
const sevCounts    = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, NONE: 0 };
const confBins     = new Array(10).fill(0);

// ═══════════════════════════════════════════════════════
// PAGES
// ═══════════════════════════════════════════════════════
function showPage(name) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  document.getElementById(`page-${name}`).classList.add('active');
  document.querySelector(`[data-page="${name}"]`).classList.add('active');
  document.getElementById('page-title').textContent =
    { dashboard:'Dashboard', live:'Live Feed', upload:'CSV Analyzer',
      alerts:'Alerts', predict:'Predict', logs:'Logs', model:'Model Info' }[name];
  if (name === 'alerts') renderAlerts();
  if (name === 'logs')   loadLogs();
  if (name === 'model')  loadModelInfo();
}
function toggleSidebar() { document.getElementById('sidebar').classList.toggle('collapsed'); }

// ═══════════════════════════════════════════════════════
// CLOCK
// ═══════════════════════════════════════════════════════
function updateClock() {
  document.getElementById('clock').textContent =
    new Date().toLocaleTimeString('en-IN', { hour12: false });
}
setInterval(updateClock, 1000);
updateClock();

// ═══════════════════════════════════════════════════════
// STATUS CHECK
// ═══════════════════════════════════════════════════════
async function checkStatus() {
  const dot = document.getElementById('status-dot');
  const lbl = document.getElementById('status-label');
  try {
    const r = await fetch(`${API}/api/status`, { signal: AbortSignal.timeout(3000) });
    if (r.ok) { dot.className = 'status-dot online'; lbl.textContent = 'Backend Online'; backendOnline = true; }
    else throw new Error();
  } catch {
    dot.className = 'status-dot offline'; lbl.textContent = 'Demo Mode (Offline)'; backendOnline = false;
  }
}
checkStatus();
setInterval(checkStatus, 10000);

// ═══════════════════════════════════════════════════════
// DASHBOARD CHARTS
// ═══════════════════════════════════════════════════════
function initCharts() {
  Chart.defaults.color = '#8b949e';
  Chart.defaults.borderColor = '#30363d';

  charts.timeline = new Chart(document.getElementById('timelineChart'), {
    type: 'line',
    data: { labels: timelineData.labels, datasets: [
      { label:'Attacks', data:timelineData.attacks, borderColor:'#e74c3c', backgroundColor:'rgba(231,76,60,0.15)', fill:true, tension:0.4, pointRadius:3 },
      { label:'Normal',  data:timelineData.normals, borderColor:'#2ecc71', backgroundColor:'rgba(46,204,113,0.1)', fill:true, tension:0.4, pointRadius:3 }
    ]},
    options: { responsive:true, interaction:{ mode:'index' }, scales:{ x:{ ticks:{ maxTicksLimit:8 } } } }
  });
  charts.split = new Chart(document.getElementById('splitChart'), {
    type:'doughnut', data:{ labels:['Normal','Attack'], datasets:[{ data:[1,0], backgroundColor:['#2ecc71','#e74c3c'], borderWidth:0 }]},
    options:{ responsive:true, cutout:'65%', plugins:{ legend:{ position:'bottom' } } }
  });
  charts.severity = new Chart(document.getElementById('severityChart'), {
    type:'bar', data:{ labels:['CRITICAL','HIGH','MEDIUM','NONE'], datasets:[{ data:[0,0,0,0], backgroundColor:['#c0392b','#e74c3c','#f39c12','#2ecc71'], borderRadius:6 }]},
    options:{ responsive:true, plugins:{ legend:{ display:false } } }
  });
  charts.protocol = new Chart(document.getElementById('protocolChart'), {
    type:'polarArea', data:{ labels:['TCP','UDP','ICMP'], datasets:[{ data:[0,0,0], backgroundColor:['rgba(52,152,219,0.7)','rgba(155,89,182,0.7)','rgba(230,126,34,0.7)'] }]},
    options:{ responsive:true, plugins:{ legend:{ position:'bottom' } } }
  });
  charts.conf = new Chart(document.getElementById('confChart'), {
    type:'bar', data:{ labels:['0.0','0.1','0.2','0.3','0.4','0.5','0.6','0.7','0.8','0.9'], datasets:[{ data:confBins, backgroundColor:'#00d4ff', borderRadius:4 }]},
    options:{ responsive:true, plugins:{ legend:{ display:false } } }
  });
}

function updateChartsWithPacket(packet) {
  const t = packet.timestamp.slice(11, 19);
  if (!timelineData.labels.length || timelineData.labels[timelineData.labels.length-1] !== t) {
    timelineData.labels.push(t); timelineData.attacks.push(0); timelineData.normals.push(0);
    if (timelineData.labels.length > 20) { timelineData.labels.shift(); timelineData.attacks.shift(); timelineData.normals.shift(); }
  }
  if (packet.status === 'ATTACK') timelineData.attacks[timelineData.attacks.length-1]++;
  else timelineData.normals[timelineData.normals.length-1]++;
  charts.timeline.update('none');

  const total = allLogs.length, atks = allLogs.filter(p => p.status==='ATTACK').length;
  charts.split.data.datasets[0].data = [total-atks, atks]; charts.split.update('none');

  if (packet.severity in sevCounts) sevCounts[packet.severity]++;
  charts.severity.data.datasets[0].data = [sevCounts.CRITICAL,sevCounts.HIGH,sevCounts.MEDIUM,sevCounts.NONE]; charts.severity.update('none');

  if (packet.protocol in protCounts) protCounts[packet.protocol]++;
  charts.protocol.data.datasets[0].data = [protCounts.TCP,protCounts.UDP,protCounts.ICMP]; charts.protocol.update('none');

  confBins[Math.min(Math.floor(packet.confidence*10),9)]++;
  charts.conf.data.datasets[0].data = [...confBins]; charts.conf.update('none');
}

// ═══════════════════════════════════════════════════════
// LOCAL STATS
// ═══════════════════════════════════════════════════════
function updateLocalStats(packet) {
  localStats.total++;
  if (packet.status === 'ATTACK') { localStats.attacks++; if (packet.severity==='CRITICAL') localStats.critical++; }
  else localStats.normal++;
  if (localStats.total > 0) localStats.detection_rate = parseFloat((localStats.attacks/localStats.total*100).toFixed(1));
}

async function refreshStats() {
  if (backendOnline) {
    try {
      const r = await fetch(`${API}/api/stats`); if (!r.ok) throw new Error();
      const d = await r.json();
      applyStats(d.total,d.attacks,d.normal,d.critical,d.detection_rate,d.recent_alerts||[]); return;
    } catch {}
  }
  applyStats(localStats.total,localStats.attacks,localStats.normal,localStats.critical,localStats.detection_rate,allAlerts.slice(0,10));
}

function applyStats(total,attacks,normal,critical,rate,recentAlerts) {
  animateNumber('s-total',total); animateNumber('s-attacks',attacks);
  animateNumber('s-normal',normal); animateNumber('s-critical',critical);
  document.getElementById('s-rate').textContent = rate+'%';
  document.getElementById('alert-count').textContent = attacks;
  renderRecentAlerts(recentAlerts);
}

function animateNumber(id, target) {
  const el = document.getElementById(id);
  const current = parseInt(el.textContent)||0;
  if (current===target) return;
  const step=Math.ceil(Math.abs(target-current)/8), dir=target>current?1:-1;
  let cur=current;
  const timer=setInterval(()=>{
    cur+=dir*step;
    if((dir===1&&cur>=target)||(dir===-1&&cur<=target)){cur=target;clearInterval(timer);}
    el.textContent=cur;
  },40);
}

function renderRecentAlerts(alerts) {
  const el = document.getElementById('recent-alerts-list');
  if (!alerts.length) { el.innerHTML='<p style="color:var(--text-muted);font-size:13px;">No alerts yet. Run simulation or upload CSV.</p>'; return; }
  el.innerHTML = alerts.slice(0,6).map(a=>`
    <div class="alert-mini-item fade-in">
      <span class="sev-tag sev-${a.severity}">${a.severity}</span>
      <span>${a.prediction}</span>
      <span style="color:var(--text-muted)">${a.src_ip}</span>
      <span style="color:var(--text-muted);margin-left:auto;font-size:11px">${a.timestamp.slice(11)}</span>
    </div>`).join('');
}

// ═══════════════════════════════════════════════════════
// CSV ANALYZER
// ═══════════════════════════════════════════════════════
function handleDragOver(e) { e.preventDefault(); document.getElementById('upload-zone').classList.add('drag-over'); }
function handleDragLeave()  { document.getElementById('upload-zone').classList.remove('drag-over'); }
function handleDrop(e) {
  e.preventDefault(); document.getElementById('upload-zone').classList.remove('drag-over');
  const file = e.dataTransfer.files[0];
  if (file && file.name.endsWith('.csv')) processCSVFile(file);
  else alert('Please upload a .csv file');
}
function handleFileSelect(e) { if (e.target.files[0]) processCSVFile(e.target.files[0]); }

function processCSVFile(file) {
  document.getElementById('upload-zone').style.display = 'none';
  document.getElementById('csv-results-section').style.display = 'none';
  const wrap = document.getElementById('upload-progress-wrap');
  wrap.style.display = 'block';
  document.getElementById('upload-filename').textContent = file.name;
  document.getElementById('upload-pct').textContent = '0%';
  document.getElementById('progress-bar-fill').style.width = '0%';
  document.getElementById('upload-status-text').textContent = 'Reading CSV file…';

  Papa.parse(file, {
    header: true, skipEmptyLines: true,
    complete: function(result) {
      if (!result.data.length) { alert('CSV file is empty or invalid.'); resetCsvAnalysis(); return; }
      analyseRows(result.data);
    },
    error: function(err) { alert('Error reading CSV: ' + err.message); resetCsvAnalysis(); }
  });
}

async function analyseRows(rows) {
  const total = rows.length;
  csvResults = [];

  // Test if backend can handle predictions
  let useBackend = false;
  if (backendOnline) {
    try {
      const r = await fetch(`${API}/api/predict`, {
        method:'POST', headers:{'Content-Type':'application/json'},
        body:JSON.stringify(buildPayload(rows[0])), signal:AbortSignal.timeout(2000)
      });
      if (r.ok) useBackend = true;
    } catch {}
  }
  document.getElementById('upload-status-text').textContent =
    useBackend ? '🤖 Using ML model (backend online)…' : '⚡ Using local heuristic engine…';

  const CHUNK = 100;
  for (let i = 0; i < total; i += CHUNK) {
    const chunk = rows.slice(i, i+CHUNK);
    for (const row of chunk) {
      let result;
      if (useBackend) {
        try {
          const r = await fetch(`${API}/api/predict`, { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(buildPayload(row)) });
          result = await r.json();
        } catch { result = localPredict(buildPayload(row)); }
      } else {
        result = localPredict(buildPayload(row));
      }
      const pkt = buildCsvPacket(row, result);
      csvResults.push(pkt);
      allLogs.unshift(pkt);
      if (pkt.status === 'ATTACK') allAlerts.unshift(pkt);
      updateLocalStats(pkt);
    }
    const done = Math.min(i+CHUNK, total);
    const pct  = Math.round(done/total*100);
    document.getElementById('progress-bar-fill').style.width = pct+'%';
    document.getElementById('upload-pct').textContent = pct+'%';
    document.getElementById('upload-status-text').textContent = `Analysed ${done.toLocaleString()} / ${total.toLocaleString()} packets…`;
    await new Promise(r => setTimeout(r, 0));
  }

  if (allLogs.length>500)   allLogs   = allLogs.slice(0,500);
  if (allAlerts.length>200) allAlerts = allAlerts.slice(0,200);
  document.getElementById('upload-progress-wrap').style.display = 'none';
  showCsvResults();
  refreshStats();
}

function buildPayload(row) {
  const get = (keys, def=0) => {
    for (const k of keys) { const v=row[k]; if (v!==undefined&&v!=='') return isNaN(+v)?v:+v; }
    return def;
  };
  return {
    duration      : get(['duration','Duration']),
    protocol_type : protoIndex(get(['protocol_type','Protocol','protocol'],'tcp')),
    src_bytes     : get(['src_bytes','Source Bytes','SrcBytes','src bytes']),
    dst_bytes     : get(['dst_bytes','Destination Bytes','DstBytes','dst bytes']),
    count         : get(['count','Count'],1),
    srv_count     : get(['srv_count','SrvCount','srv count'],1),
    logged_in     : get(['logged_in','LoggedIn','logged in']),
    same_srv_rate : get(['same_srv_rate','SameSrvRate','same srv rate']),
  };
}
function protoIndex(v) {
  if (typeof v === 'number') return v;
  const s = String(v).toLowerCase();
  if (s==='udp') return 1; if (s==='icmp') return 2; return 0;
}
function buildCsvPacket(row, result) {
  const PROTOS = ['TCP','UDP','ICMP'];
  const pi = protoIndex(row['protocol_type']||row['Protocol']||row['protocol']||'tcp');
  return {
    timestamp  : new Date().toISOString().replace('T',' ').slice(0,19),
    src_ip     : row['src_ip']||row['SrcIP']||rip(result.status!=='ATTACK'),
    dst_ip     : row['dst_ip']||row['DstIP']||`10.0.0.${ri(1,20)}`,
    protocol   : PROTOS[pi]||'TCP',
    port       : parseInt(row['port']||row['dst_port']||row['DstPort'])||ri(20,65535),
    prediction : result.prediction,
    severity   : result.severity||'NONE',
    confidence : result.confidence||0,
    status     : result.status,
  };
}

function showCsvResults() {
  document.getElementById('csv-results-section').style.display = 'block';
  const total    = csvResults.length;
  const attacks  = csvResults.filter(p=>p.status==='ATTACK').length;
  const normals  = total-attacks;
  const critical = csvResults.filter(p=>p.severity==='CRITICAL').length;
  const rate     = total ? parseFloat((attacks/total*100).toFixed(1)) : 0;

  document.getElementById('csv-total').textContent    = total.toLocaleString();
  document.getElementById('csv-attacks').textContent  = attacks.toLocaleString();
  document.getElementById('csv-normals').textContent  = normals.toLocaleString();
  document.getElementById('csv-critical').textContent = critical.toLocaleString();
  document.getElementById('csv-rate').textContent     = rate+'%';

  // Destroy old charts
  ['csvAttackChart','csvSplitChart','csvSeverityChart','csvProtoChart','csvConfChart'].forEach(id=>{
    if(csvCharts[id]){csvCharts[id].destroy();delete csvCharts[id];}
  });

  // Attack type distribution
  const atkTypes={};
  csvResults.filter(p=>p.status==='ATTACK').forEach(p=>{ atkTypes[p.prediction]=(atkTypes[p.prediction]||0)+1; });
  const aLabels=Object.keys(atkTypes), aData=Object.values(atkTypes);
  csvCharts.csvAttackChart = new Chart(document.getElementById('csvAttackChart'),{
    type:'bar', data:{labels:aLabels.length?aLabels:['No Attacks Found'], datasets:[{data:aData.length?aData:[0],
      backgroundColor:['#c0392b','#e74c3c','#f39c12','#e67e22','#9b59b6'], borderRadius:6}]},
    options:{responsive:true, plugins:{legend:{display:false}}, scales:{y:{beginAtZero:true}}}
  });

  // Normal vs Attack donut
  csvCharts.csvSplitChart = new Chart(document.getElementById('csvSplitChart'),{
    type:'doughnut', data:{labels:['Normal','Attack'], datasets:[{data:[normals,attacks], backgroundColor:['#2ecc71','#e74c3c'], borderWidth:0}]},
    options:{responsive:true, cutout:'65%', plugins:{legend:{position:'bottom'}}}
  });

  // Severity bar
  const sev={CRITICAL:0,HIGH:0,MEDIUM:0,NONE:0};
  csvResults.forEach(p=>{ if(p.severity in sev) sev[p.severity]++; });
  csvCharts.csvSeverityChart = new Chart(document.getElementById('csvSeverityChart'),{
    type:'bar', data:{labels:['CRITICAL','HIGH','MEDIUM','NONE'], datasets:[{data:[sev.CRITICAL,sev.HIGH,sev.MEDIUM,sev.NONE],
      backgroundColor:['#c0392b','#e74c3c','#f39c12','#2ecc71'], borderRadius:6}]},
    options:{responsive:true, plugins:{legend:{display:false}}}
  });

  // Protocol polar
  const proto={TCP:0,UDP:0,ICMP:0};
  csvResults.forEach(p=>{ if(p.protocol in proto) proto[p.protocol]++; });
  csvCharts.csvProtoChart = new Chart(document.getElementById('csvProtoChart'),{
    type:'polarArea', data:{labels:['TCP','UDP','ICMP'], datasets:[{data:[proto.TCP,proto.UDP,proto.ICMP],
      backgroundColor:['rgba(52,152,219,0.7)','rgba(155,89,182,0.7)','rgba(230,126,34,0.7)']}]},
    options:{responsive:true, plugins:{legend:{position:'bottom'}}}
  });

  // Confidence histogram
  const bins=new Array(10).fill(0);
  csvResults.forEach(p=>{ bins[Math.min(Math.floor(p.confidence*10),9)]++; });
  csvCharts.csvConfChart = new Chart(document.getElementById('csvConfChart'),{
    type:'bar', data:{labels:['0.0','0.1','0.2','0.3','0.4','0.5','0.6','0.7','0.8','0.9'],
      datasets:[{data:bins, backgroundColor:'#00d4ff', borderRadius:4}]},
    options:{responsive:true, plugins:{legend:{display:false}}}
  });

  csvFiltered = [...csvResults];
  renderCsvTable(csvFiltered);
  document.getElementById('csv-table-info').textContent =
    `Showing ${Math.min(csvFiltered.length,500).toLocaleString()} of ${csvFiltered.length.toLocaleString()} packets`;
}

function renderCsvTable(data) {
  const tbody = document.getElementById('csv-result-tbody');
  tbody.innerHTML = data.slice(0,500).map((p,i)=>`
    <tr class="${p.status==='ATTACK'?'row-attack':''} fade-in">
      <td style="color:var(--text-muted)">${i+1}</td>
      <td>${p.src_ip}</td><td>${p.dst_ip}</td><td>${p.protocol}</td>
      <td>${p.prediction}</td>
      <td><span class="sev-tag sev-${p.severity}">${p.severity}</span></td>
      <td>${(p.confidence*100).toFixed(1)}%</td>
      <td><span class="status-pill ${p.status==='ATTACK'?'pill-attack':'pill-normal'}">${p.status}</span></td>
    </tr>`).join('');
}

function filterCsvTable() {
  const q      = (document.getElementById('csv-table-search').value||'').toLowerCase();
  const status = document.getElementById('csv-filter-status').value;
  csvFiltered = csvResults.filter(p => {
    const ms = !status || p.status===status;
    const mq = !q || p.src_ip.includes(q)||p.dst_ip.includes(q)||p.prediction.toLowerCase().includes(q)||p.severity.toLowerCase().includes(q)||p.protocol.toLowerCase().includes(q);
    return ms && mq;
  });
  renderCsvTable(csvFiltered);
  document.getElementById('csv-table-info').textContent =
    `Showing ${Math.min(csvFiltered.length,500).toLocaleString()} of ${csvFiltered.length.toLocaleString()} packets`;
}

function exportCsvResults() {
  const headers=['#','src_ip','dst_ip','protocol','prediction','severity','confidence','status'];
  const rows = csvFiltered.map((p,i)=>[i+1,p.src_ip,p.dst_ip,p.protocol,p.prediction,p.severity,(p.confidence*100).toFixed(1)+'%',p.status].join(','));
  const blob = new Blob([[headers.join(','),...rows].join('\n')],{type:'text/csv'});
  const a=document.createElement('a'); a.href=URL.createObjectURL(blob);
  a.download='sentinelnet_analysis.csv'; a.click();
}

function resetCsvAnalysis() {
  csvResults=[]; csvFiltered=[];
  document.getElementById('upload-zone').style.display='';
  document.getElementById('upload-progress-wrap').style.display='none';
  document.getElementById('csv-results-section').style.display='none';
  document.getElementById('csv-file-input').value='';
  ['csvAttackChart','csvSplitChart','csvSeverityChart','csvProtoChart','csvConfChart'].forEach(id=>{
    if(csvCharts[id]){csvCharts[id].destroy();delete csvCharts[id];}
  });
}

// ═══════════════════════════════════════════════════════
// SIMULATE
// ═══════════════════════════════════════════════════════
async function runSimulation() {
  const packets=[];
  if(backendOnline){try{for(let i=0;i<20;i++){const r=await fetch(`${API}/api/live`);packets.push(await r.json());}}catch{}}
  if(!packets.length) for(let i=0;i<20;i++) packets.push(demoPacket());
  packets.forEach(p=>{allLogs.unshift(p);if(p.status==='ATTACK')allAlerts.unshift(p);updateLocalStats(p);updateChartsWithPacket(p);});
  if(allLogs.length>500) allLogs=allLogs.slice(0,500);
  if(allAlerts.length>200) allAlerts=allAlerts.slice(0,200);
  refreshStats();
}

// ═══════════════════════════════════════════════════════
// LIVE FEED
// ═══════════════════════════════════════════════════════
function startLive(){
  document.getElementById('btn-start').disabled=true; document.getElementById('btn-stop').disabled=false;
  document.getElementById('live-info').textContent='🔴 LIVE – fetching every 1.5s…';
  liveInterval=setInterval(fetchLivePacket,1500);
}
function stopLive(){
  clearInterval(liveInterval);liveInterval=null;
  document.getElementById('btn-start').disabled=false; document.getElementById('btn-stop').disabled=true;
  document.getElementById('live-info').textContent='Feed stopped';
}
async function fetchLivePacket(){
  let packet;
  if(backendOnline){try{const r=await fetch(`${API}/api/live`);packet=await r.json();}catch{packet=demoPacket();}}
  else packet=demoPacket();
  allLogs.unshift(packet); if(packet.status==='ATTACK')allAlerts.unshift(packet);
  if(allLogs.length>500)allLogs=allLogs.slice(0,500); if(allAlerts.length>200)allAlerts=allAlerts.slice(0,200);
  updateLocalStats(packet); updateChartsWithPacket(packet); prependLiveRow(packet); refreshStats();
}
function prependLiveRow(p){
  const tbody=document.getElementById('live-tbody');
  const tr=document.createElement('tr'); tr.className=p.status==='ATTACK'?'row-attack flash-attack':'flash-normal';
  tr.innerHTML=`<td>${p.timestamp.slice(11)}</td><td>${p.src_ip}</td><td>${p.dst_ip}</td><td>${p.protocol}</td><td>${p.port}</td>
    <td>${p.prediction}</td><td><span class="sev-tag sev-${p.severity}">${p.severity}</span></td>
    <td>${(p.confidence*100).toFixed(1)}%</td>
    <td><span class="status-pill ${p.status==='ATTACK'?'pill-attack':'pill-normal'}">${p.status}</span></td>`;
  tbody.prepend(tr); while(tbody.children.length>100)tbody.removeChild(tbody.lastChild);
}

// ═══════════════════════════════════════════════════════
// ALERTS PAGE
// ═══════════════════════════════════════════════════════
async function renderAlerts(){
  let alerts=allAlerts;
  if(backendOnline){try{const r=await fetch(`${API}/api/alerts?limit=100`);const d=await r.json();if(d.alerts&&d.alerts.length){alerts=d.alerts;allAlerts=alerts;}}catch{}}
  const container=document.getElementById('alerts-container');
  if(!alerts.length){container.innerHTML='<p style="color:var(--text-muted);padding:20px">No alerts yet. Start Live Feed, Simulate, or upload a CSV.</p>';return;}
  container.innerHTML=alerts.slice(0,60).map(a=>`
    <div class="alert-card ${a.severity||''} fade-in">
      <div class="alert-card-title">🚨 <span class="sev-tag sev-${a.severity}">${a.severity}</span> ${a.prediction}</div>
      <div class="alert-card-meta">
        <span><strong>Time:</strong> ${a.timestamp.slice(11)}</span>
        <span><strong>Confidence:</strong> ${(a.confidence*100).toFixed(1)}%</span>
        <span><strong>Src:</strong> ${a.src_ip}</span><span><strong>Dst:</strong> ${a.dst_ip}</span>
        <span><strong>Protocol:</strong> ${a.protocol}</span><span><strong>Port:</strong> ${a.port}</span>
      </div>
    </div>`).join('');
}
async function downloadAlerts(){
  if(backendOnline){window.open(`${API}/api/download/alerts`,'_blank');return;}
  const blob=new Blob([JSON.stringify(allAlerts,null,2)],{type:'application/json'});
  const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='sentinelnet_alerts.json';a.click();
}

// ═══════════════════════════════════════════════════════
// PREDICT PAGE
// ═══════════════════════════════════════════════════════
async function runPrediction(){
  const payload={
    duration:parseFloat(document.getElementById('p-duration').value)||0,
    protocol_type:parseInt(document.getElementById('p-protocol').value),
    src_bytes:parseInt(document.getElementById('p-srcbytes').value)||0,
    dst_bytes:parseInt(document.getElementById('p-dstbytes').value)||0,
    count:parseInt(document.getElementById('p-count').value)||1,
    srv_count:parseInt(document.getElementById('p-srvcount').value)||1,
    logged_in:parseInt(document.getElementById('p-logged').value),
    same_srv_rate:parseFloat(document.getElementById('p-samesrv').value)||0
  };
  const card=document.getElementById('result-card');
  card.innerHTML='<div class="result-content"><div style="font-size:32px">⏳</div><p>Analyzing…</p></div>';
  let result;
  if(backendOnline){try{const r=await fetch(`${API}/api/predict`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});result=await r.json();}catch{result=null;}}
  if(!result) result=localPredict(payload);
  const isAttack=result.status==='ATTACK', pct=(result.confidence*100).toFixed(1);
  card.innerHTML=`
    <div class="result-content fade-in">
      <div class="result-verdict ${isAttack?'attack':'normal'}">${isAttack?'🚨 ATTACK':'✅ NORMAL'}</div>
      <div class="result-type">${result.prediction}</div>
      <div style="margin:8px 0"><span class="sev-tag sev-${result.severity}">${result.severity}</span></div>
      <div class="result-conf">Confidence: <span>${pct}%</span></div>
      <div class="conf-bar-wrap"><div class="conf-bar" style="width:${pct}%;background:${isAttack?'#e74c3c':'#2ecc71'}"></div></div>
      <div style="margin-top:16px;font-size:12px;color:var(--text-muted)">
        SrcBytes:${payload.src_bytes} | DstBytes:${payload.dst_bytes} | Count:${payload.count} | Proto:${['TCP','UDP','ICMP'][payload.protocol_type]}
      </div>
      ${!backendOnline?'<p style="font-size:11px;color:#f39c12;margin-top:8px">⚠ Heuristic mode – start Flask for ML model</p>':''}
    </div>`;
}
function fillRandom(){
  document.getElementById('p-duration').value=Math.floor(Math.random()*50000);
  document.getElementById('p-protocol').value=Math.floor(Math.random()*3);
  document.getElementById('p-srcbytes').value=Math.floor(Math.random()*100000);
  document.getElementById('p-dstbytes').value=Math.floor(Math.random()*100000);
  document.getElementById('p-count').value=Math.floor(Math.random()*512)+1;
  document.getElementById('p-srvcount').value=Math.floor(Math.random()*512)+1;
  document.getElementById('p-logged').value=Math.round(Math.random());
  document.getElementById('p-samesrv').value=Math.random().toFixed(2);
}

// ═══════════════════════════════════════════════════════
// LOCAL HEURISTIC PREDICTOR
// ═══════════════════════════════════════════════════════
function localPredict(p){
  const ATYPES=['DoS Attack','DDoS Attack','Probe Attack','R2L Attack','U2R Attack'];
  const SEVMAP={'DoS Attack':'HIGH','DDoS Attack':'CRITICAL','Probe Attack':'MEDIUM','R2L Attack':'HIGH','U2R Attack':'CRITICAL','Normal Traffic':'NONE'};
  let score=0;
  if(p.src_bytes>50000&&p.dst_bytes===0)      score+=0.35;
  if(p.src_bytes>100000)                       score+=0.20;
  if(p.count>200)                              score+=0.25;
  if(p.count>400)                              score+=0.15;
  if(p.same_srv_rate<0.1&&p.count>5)          score+=0.20;
  if(p.duration>10000&&p.logged_in===0)        score+=0.15;
  if(p.protocol_type===2&&p.src_bytes>1000)   score+=0.20;
  if(p.count>50&&p.srv_count<5)               score+=0.20;
  if(p.logged_in===1&&p.same_srv_rate>0.7)    score-=0.20;
  if(p.src_bytes<5000&&p.dst_bytes<5000&&p.count<50) score-=0.15;
  score=Math.max(0,Math.min(1,score));
  const isAttack=score>=0.30;
  const confidence=isAttack?parseFloat((0.65+score*0.30).toFixed(4)):parseFloat((0.70+(0.30-score)*0.90).toFixed(4));
  let prediction='Normal Traffic';
  if(isAttack){
    if(p.count>300||p.src_bytes>100000)          prediction='DDoS Attack';
    else if(p.same_srv_rate<0.1)                  prediction='Probe Attack';
    else if(p.logged_in===0&&p.duration>5000)     prediction='R2L Attack';
    else if(p.protocol_type===2&&p.src_bytes>1000)prediction='DoS Attack';
    else prediction=ATYPES[Math.floor(score*ATYPES.length)]||'DoS Attack';
  }
  return{prediction,status:isAttack?'ATTACK':'NORMAL',severity:SEVMAP[prediction],confidence:Math.min(confidence,0.99)};
}

// ═══════════════════════════════════════════════════════
// LOGS PAGE
// ═══════════════════════════════════════════════════════
async function loadLogs(){
  let logs=allLogs;
  if(backendOnline){try{const r=await fetch(`${API}/api/logs?limit=200`);const d=await r.json();if(d.logs&&d.logs.length){logs=d.logs;allLogs=logs;}}catch{}}
  renderLogTable(logs);
}
function renderLogTable(logs){
  const tbody=document.getElementById('log-tbody');
  if(!logs.length){tbody.innerHTML='<tr><td colspan="8" style="text-align:center;color:var(--text-muted);padding:20px">No logs yet.</td></tr>';return;}
  tbody.innerHTML=logs.slice(0,150).map(p=>`
    <tr class="${p.status==='ATTACK'?'row-attack':''}">
      <td>${p.timestamp.slice(11)}</td><td>${p.src_ip}</td><td>${p.dst_ip}</td><td>${p.protocol}</td>
      <td>${p.prediction}</td><td><span class="sev-tag sev-${p.severity}">${p.severity}</span></td>
      <td>${(p.confidence*100).toFixed(1)}%</td>
      <td><span class="status-pill ${p.status==='ATTACK'?'pill-attack':'pill-normal'}">${p.status}</span></td>
    </tr>`).join('');
}
function filterLogs(){
  const q=document.getElementById('log-search').value.toLowerCase();
  renderLogTable(allLogs.filter(p=>p.src_ip.includes(q)||p.dst_ip.includes(q)||p.prediction.toLowerCase().includes(q)||p.status.toLowerCase().includes(q)));
}
async function downloadLogs(){
  if(backendOnline){window.open(`${API}/api/download/logs`,'_blank');return;}
  const headers=['timestamp','src_ip','dst_ip','protocol','port','prediction','severity','confidence','status'];
  const rows=allLogs.map(l=>headers.map(h=>l[h]||'').join(','));
  const blob=new Blob([[headers.join(','),...rows].join('\n')],{type:'text/csv'});
  const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='sentinelnet_logs.csv';a.click();
}

// ═══════════════════════════════════════════════════════
// MODEL INFO
// ═══════════════════════════════════════════════════════
async function loadModelInfo(){
  let info={model_type:'XGBoost (Demo Mode)',features_count:41,mode:'NSL-KDD Heuristic',accuracy:'80.7%',
    features:['duration','src_bytes','dst_bytes','count','srv_count','serror_rate','rerror_rate','same_srv_rate','dst_host_count','logged_in','protocol_type','flag','land','wrong_fragment','urgent']};
  if(backendOnline){try{const r=await fetch(`${API}/api/model_info`);info=await r.json();}catch{}}
  document.getElementById('model-info-content').innerHTML=`
    <div class="model-info-row"><span class="key">Model Type</span><span class="val">${info.model_type}</span></div>
    <div class="model-info-row"><span class="key">Features Used</span><span class="val">${info.features_count}</span></div>
    <div class="model-info-row"><span class="key">Mode</span><span class="val">${info.mode}</span></div>
    <div class="model-info-row"><span class="key">Accuracy</span><span class="val">${info.accuracy||'80.7%'}</span></div>
    <div class="model-info-row"><span class="key">Algorithms</span><span class="val">XGBoost, RF, SVM, DT</span></div>
    <div class="model-info-row"><span class="key">Anomaly Detection</span><span class="val">Isolation Forest, K-Means</span></div>
    <div class="model-info-row"><span class="key">Datasets</span><span class="val">NSL-KDD / CICIDS2017</span></div>
    <div style="margin-top:14px"><p style="font-size:12px;color:var(--text-muted);margin-bottom:8px">Top Features:</p>
      <div style="display:flex;flex-wrap:wrap;gap:6px">
        ${(info.features||[]).slice(0,15).map(f=>`<span style="background:rgba(0,212,255,0.1);border:1px solid rgba(0,212,255,0.3);color:#00d4ff;padding:3px 9px;border-radius:4px;font-size:11px">${f}</span>`).join('')}
      </div>
    </div>`;
}

// ═══════════════════════════════════════════════════════
// DEMO PACKET GENERATOR
// ═══════════════════════════════════════════════════════
const ATYPES=['DoS Attack','DDoS Attack','Probe Attack','R2L Attack','U2R Attack'];
const PROTOS=['TCP','UDP','ICMP'];
const SEVMAP={'DoS Attack':'HIGH','DDoS Attack':'CRITICAL','Probe Attack':'MEDIUM','R2L Attack':'HIGH','U2R Attack':'CRITICAL','Normal Traffic':'NONE'};
function rip(priv=true){return priv?`192.168.${ri(1,254)}.${ri(1,254)}`:`${ri(1,222)}.${ri(0,255)}.${ri(0,255)}.${ri(1,254)}`;}
function ri(a,b){return Math.floor(Math.random()*(b-a+1))+a;}
function demoPacket(){
  const isAtk=Math.random()<0.40, type=isAtk?ATYPES[ri(0,4)]:'Normal Traffic';
  const conf=isAtk?parseFloat((Math.random()*0.35+0.60).toFixed(4)):parseFloat((Math.random()*0.25+0.72).toFixed(4));
  return{timestamp:new Date().toISOString().replace('T',' ').slice(0,19),src_ip:rip(!isAtk),dst_ip:`10.0.0.${ri(1,20)}`,
    protocol:PROTOS[ri(0,2)],port:ri(20,65535),prediction:type,severity:SEVMAP[type],confidence:conf,status:isAtk?'ATTACK':'NORMAL'};
}

// ═══════════════════════════════════════════════════════
// INIT
// ═══════════════════════════════════════════════════════
document.addEventListener('DOMContentLoaded', () => {
  initCharts();
  statsInterval = setInterval(refreshStats, 3000);
  for(let i=0;i<20;i++){
    const p=demoPacket(); allLogs.unshift(p);
    if(p.status==='ATTACK')allAlerts.unshift(p);
    updateLocalStats(p); updateChartsWithPacket(p);
  }
  refreshStats();
});
