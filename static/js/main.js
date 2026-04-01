/* ============================================================
   SentinelNet — main.js
   All dashboard logic: charts, API calls, upload, analyzer
   ============================================================ */

// ── Chart instances (kept to allow destroy on refresh) ──────
let attackChartInst = null;
let protoChartInst = null;
let liveChartInst = null;

// ── Alert store ─────────────────────────────────────────────
let allAlerts = [];
let currentFilter = 'All';

/* ============================================================
   TOAST NOTIFICATION
   ============================================================ */
function toast(msg, type = 'success') {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.className = 'show ' + type;
  clearTimeout(t._timer);
  t._timer = setTimeout(() => { t.className = ''; }, 3200);
}

/* ============================================================
   SIDEBAR NAVIGATION AND ROUTING
   ============================================================ */
function navigate(page, btn) {
  document.querySelectorAll('.nav-item').forEach(b => b.classList.remove('active'));
  if (btn) btn.classList.add('active');
  
  document.querySelectorAll('.page-view').forEach(p => p.style.display = 'none');
  const target = document.getElementById('page-' + page);
  if (target) target.style.display = 'block';
  
  history.pushState(null, null, '/' + page);
  window.scrollTo(0, 0);
}

window.addEventListener('popstate', () => {
  const page = window.location.pathname.replace('/', '') || 'dashboard';
  const btn = document.getElementById('nav-' + page);
  navigate(page, btn);
});

document.addEventListener('DOMContentLoaded', () => {
  const page = window.location.pathname.replace('/', '') || 'dashboard';
  const btn = document.getElementById('nav-' + page);
  if (btn) btn.click();
});

/* ============================================================
   SIMULATION AND QUARANTINE CONTROLS
   ============================================================ */
let simStatus = 'active';
let quarantinedList = [];

async function toggleSimulation() {
  const action = simStatus === 'active' ? 'stop' : 'start';
  try {
    const res = await fetch('/api/sim/toggle', { method: 'POST', body: JSON.stringify({action}) });
    const data = await res.json();
    simStatus = data.status;
    updateSimUI();
    toast(simStatus === 'active' ? '▶️ Live traffic resumed' : '⏸️ Simulation paused');
  } catch (e) {
    toast('Error toggling simulation', 'error');
  }
}

function updateSimUI() {
  const btn = document.getElementById('btn-toggle-sim');
  const ind = document.getElementById('live-indicator-pill');
  if (simStatus === 'active') {
    btn.textContent = '⏸️ Pause IDS Traffic';
    ind.innerHTML = '<span class="live-dot"></span>LIVE';
    ind.style.background = 'rgba(248,113,113,0.15)';
    ind.style.color = '#f87171';
  } else {
    btn.textContent = '▶️ Resume Traffic';
    ind.innerHTML = '<span class="live-dot" style="background:#fb923c;animation:none"></span>PAUSED';
    ind.style.background = 'rgba(251,146,60,0.15)';
    ind.style.color = '#fb923c';
  }
}

async function quarantineIP(ip) {
  try {
    const res = await fetch('/api/quarantine', { method: 'POST', body: JSON.stringify({ip}) });
    const data = await res.json();
    quarantinedList = data.quarantined || [];
    toast(`🛡️ IP ${ip} blocked via firewall.`);
    filterAlerts(currentFilter, null); // Re-render table
  } catch (e) {
    toast('Quarantine failed', 'error');
  }
}

/* ============================================================
   LIVE TRAFFIC DATA  →  GET /api/live_data
   ============================================================ */
async function fetchLiveData() {
  try {
    const res = await fetch('/api/live_data');
    const data = await res.json();
    if (data.error) throw new Error(data.error);

    const stats = data.stats;
    const rate = stats.total > 0 ? (stats.attack / stats.total * 100).toFixed(1) : 0;

    // Badge
    document.getElementById('ds-badge').textContent =
      `${stats.total.toLocaleString()} pkts processed · ${rate}% attacks`;

    // Stat cards
    document.getElementById('stats-row').innerHTML =
      statCard('blue', '🗃️', 'Total Packets', stats.total.toLocaleString(), 'Processed in real-time') +
      statCard('red', '🚨', 'Attacks Detected', stats.attack.toLocaleString(), 'Malicious connections') +
      statCard('green', '✅', 'Normal Traffic', stats.normal.toLocaleString(), 'Benign connections') +
      statCard('purple', '🛡️', 'Blocked by IDS', (stats.blocked || 0).toLocaleString(), 'Quarantined IP traffic');

    buildAttackChart(stats.attack_types);
    buildProtoChart(stats.protocols);
    buildLiveChart(data.timeseries);
    
    // Update State
    allAlerts = data.alerts;
    simStatus = data.status || 'active';
    quarantinedList = data.quarantined || [];
    updateSimUI();

    document.getElementById('alert-count-badge').textContent =
      `${allAlerts.length} recent intrusions`;
    filterAlerts(currentFilter, null);

  } catch (e) {
    console.warn('Live data fetch failed:', e);
  }
}

function statCard(cls, emoji, label, val, sub) {
  return `<div class="stat ${cls}">
    <div class="stat-emoji">${emoji}</div>
    <div class="stat-label">${label}</div>
    <div class="stat-num ${cls}">${val}</div>
    <div class="stat-sub">${sub}</div>
  </div>`;
}

/* ── Attack-type doughnut chart ─────────────────────────────── */
function buildAttackChart(types) {
  const keys = Object.keys(types).sort();
  const labels = keys;
  const dataVals = keys.map(k => types[k]);

  if (attackChartInst) {
    attackChartInst.data.labels = labels;
    attackChartInst.data.datasets[0].data = dataVals;
    attackChartInst.update('none');
  } else {
    const ctx = document.getElementById('attackChart').getContext('2d');
    attackChartInst = new Chart(ctx, {
      type: 'doughnut',
      data: {
        labels: labels,
        datasets: [{
          data: dataVals,
          backgroundColor: ['#f87171', '#34d399', '#38bdf8', '#818cf8', '#fb923c', '#facc15'],
          borderWidth: 2,
          borderColor: '#0d1526'
        }]
      },
      options: {
        cutout: '62%',
        responsive: true,
        maintainAspectRatio: true,
        animation: { duration: 0 },
        plugins: {
          legend: { position: 'bottom', labels: { color: '#64748b', padding: 10, font: { size: 11 } } }
        }
      }
    });
  }
}

/* ── Protocol bar chart ─────────────────────────────────────── */
function buildProtoChart(protos) {
  const keys = Object.keys(protos).sort();
  const labels = keys.map(k => k.toUpperCase());
  const dataVals = keys.map(k => protos[k]);

  if (protoChartInst) {
    protoChartInst.data.labels = labels;
    protoChartInst.data.datasets[0].data = dataVals;
    protoChartInst.update('none');
  } else {
    const ctx = document.getElementById('protoChart').getContext('2d');
    protoChartInst = new Chart(ctx, {
      type: 'bar',
      data: {
        labels: labels,
        datasets: [{
          data: dataVals,
          backgroundColor: ['rgba(56,189,248,.75)', 'rgba(52,211,153,.75)', 'rgba(129,140,248,.75)'],
          borderRadius: 6
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: true,
        animation: { duration: 0 },
        plugins: { legend: { display: false } },
        scales: {
          x: { grid: { color: 'rgba(99,179,237,.06)' }, ticks: { color: '#64748b', font: { size: 10 } }, border: { color: 'transparent' } },
          y: { grid: { color: 'rgba(99,179,237,.06)' }, ticks: { color: '#64748b', font: { size: 10 } }, border: { color: 'transparent' } }
        }
      }
    });
  }
}

/* ============================================================
   MODEL METRICS  →  GET /api/metrics
   ============================================================ */
async function loadMetrics() {
  try {
    const res = await fetch('/api/metrics');
    const data = await res.json();
    document.getElementById('metrics-row').innerHTML = [
      ['Accuracy', data.accuracy + '%'],
      ['Precision', data.precision + '%'],
      ['Recall', data.recall + '%'],
      ['F1-Score', data.f1 + '%'],
      ['ROC-AUC', data.roc_auc + '%']
    ].map(([label, val]) =>
      `<div class="metric">
         <div class="metric-label">${label}</div>
         <div class="metric-val">${val}</div>
       </div>`
    ).join('');
  } catch (e) {
    console.error('Metrics load failed:', e);
  }
}

/* ── Live Traffic Line Chart ─────────────────────────────────────── */
function buildLiveChart(tsData) {
  const ctx = document.getElementById('liveChart').getContext('2d');
  const labels = tsData.map(d => d.timestamp);
  const totalVals = tsData.map(d => d.total);
  const attackVals = tsData.map(d => d.attacks);

  if (!liveChartInst) {
    liveChartInst = new Chart(ctx, {
      type: 'line',
      data: {
        labels: labels,
        datasets: [
          {
            label: 'Total Packets',
            data: totalVals,
            borderColor: '#38bdf8',
            backgroundColor: 'rgba(56,189,248,0.1)',
            fill: true,
            tension: 0.4,
            borderWidth: 2,
            pointRadius: 0
          },
          {
            label: 'Attacks',
            data: attackVals,
            borderColor: '#f87171',
            backgroundColor: 'rgba(248,113,113,0.1)',
            fill: true,
            tension: 0.4,
            borderWidth: 2,
            pointRadius: 0
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        animation: { duration: 0 },
        plugins: { legend: { display: true, position: 'top', labels: { color: '#64748b', boxWidth: 12 } } },
        scales: {
          x: { grid: { color: 'rgba(99,179,237,.06)' }, ticks: { color: '#64748b' } },
          y: { grid: { color: 'rgba(99,179,237,.06)' }, ticks: { color: '#64748b' }, beginAtZero: true }
        }
      }
    });
  } else {
    liveChartInst.data.labels = labels;
    liveChartInst.data.datasets[0].data = totalVals;
    liveChartInst.data.datasets[1].data = attackVals;
    liveChartInst.update();
  }
}

/* ============================================================
   ALERTS RENDERER
   ============================================================ */

function renderAlerts(list) {
  const area = document.getElementById('alerts-area');
  if (!list.length) {
    area.innerHTML = '<div class="empty-msg">No alerts found for this filter.</div>';
    return;
  }
  area.innerHTML = `<table>
    <thead><tr>
      <th>#</th><th>Timestamp</th><th>Source IP</th><th>Dest IP</th>
      <th>Protocol</th><th>Service</th><th>Type</th><th>Confidence</th><th>Severity</th><th>Action</th>
    </tr></thead>
    <tbody>
      ${list.map((a, i) => `
      <tr>
        <td class="mono" style="color:var(--muted)">${String(i + 1).padStart(2, '0')}</td>
        <td class="mono" style="color:var(--muted);font-size:10px">${a.timestamp}</td>
        <td class="mono" style="${quarantinedList.includes(a.src_ip) ? 'text-decoration:line-through;color:var(--red)' : 'color:var(--accent)'}">${a.src_ip}</td>
        <td class="mono" style="color:var(--muted)">${a.dst_ip}</td>
        <td><span class="badge b-probe">${a.protocol}</span></td>
        <td style="color:var(--muted)">${a.service}</td>
        <td><span class="badge b-${a.actual.toLowerCase()}">${a.actual}</span></td>
        <td>
          <div class="conf-wrap">
            <span style="font-size:11px;font-weight:700;color:var(--text);width:38px;flex-shrink:0">${a.confidence}%</span>
            <div class="conf-bar"><div class="conf-fill" style="width:${a.confidence}%"></div></div>
          </div>
        </td>
        <td><span class="badge b-${a.severity.toLowerCase()}">${a.severity}</span></td>
        <td>
          ${quarantinedList.includes(a.src_ip) 
            ? '<span class="badge" style="background:#450a0a;color:#fca5a5;border:1px solid #7f1d1d">Blocked</span>'
            : `<button class="btn btn-primary" style="padding:4px 8px;font-size:11px" onclick="quarantineIP('${a.src_ip}')">Block IP</button>`}
        </td>
      </tr>`).join('')}
    </tbody>
  </table>`;
}

function filterAlerts(level, btn) {
  if (btn) {
    document.querySelectorAll('.fbtn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
  }
  currentFilter = level;
  renderAlerts(currentFilter === 'All' ? allAlerts : allAlerts.filter(a => a.severity === currentFilter));
}

/* ============================================================
   FILE UPLOAD  →  POST /api/upload
   ============================================================ */
function onDragOver(e) { e.preventDefault(); document.getElementById('drop-zone').classList.add('dragging'); }
function onDragLeave() { document.getElementById('drop-zone').classList.remove('dragging'); }
function onDrop(e) {
  e.preventDefault();
  onDragLeave();
  const f = e.dataTransfer.files[0];
  if (f) handleFile(f);
}

async function handleFile(file) {
  if (!file) return;
  const btn = document.getElementById('upload-btn');
  btn.textContent = '⏳ Processing…';
  btn.disabled = true;

  const formData = new FormData();
  formData.append('file', file);

  try {
    const res = await fetch('/api/upload', { method: 'POST', body: formData });
    const data = await res.json();
    if (data.error) throw new Error(data.error);
    renderUploadResult(data);
    toast(`✅ Processed ${data.total} records — ${data.attacks} attacks found!`);
  } catch (e) {
    toast('Upload failed: ' + e.message, 'error');
  }
  btn.textContent = '📂 Choose File';
  btn.disabled = false;
}

async function loadSampleFile() {
  const btn = document.getElementById('upload-btn');
  btn.textContent = '⏳ Loading sample…';
  btn.disabled = true;
  try {
    toast('✅ Checking live predictions below ↓');
    navigate('dashboard');
    setTimeout(() => document.getElementById('alerts-sec').scrollIntoView({ behavior: 'smooth' }), 50);
  } catch (e) {
    toast('Failed: ' + e.message, 'error');
  }
  btn.textContent = '📂 Choose File';
  btn.disabled = false;
}

function renderUploadResult(data) {
  document.getElementById('upload-result').style.display = 'block';
  document.getElementById('upload-fname').textContent =
    `📄 ${data.filename}  ·  ${data.total.toLocaleString()} records analysed`;

  // Summary stat cards
  document.getElementById('upload-stat-row').innerHTML =
    rStat('blue', 'Total Records', data.total.toLocaleString()) +
    rStat('red', 'Attacks Found', data.attacks.toLocaleString()) +
    rStat('green', 'Normal Traffic', data.normal.toLocaleString()) +
    rStat('orange', 'Attack Rate', data.attack_rate + '%');

  // Severity breakdown bars
  const sev = data.severity_breakdown;
  const maxSev = Math.max(...Object.values(sev), 1);
  const sevColors = { Critical: '#f87171', High: '#fb923c', Medium: '#facc15', Low: '#34d399' };
  document.getElementById('sev-bars').innerHTML = Object.entries(sev).map(([k, v]) =>
    `<div class="sev-row">
       <span class="sev-label">${k}</span>
       <div class="sev-bar-bg">
         <div class="sev-bar-fill" style="width:${Math.round(v / maxSev * 100)}%;background:${sevColors[k]}"></div>
       </div>
       <span class="sev-count" style="color:${sevColors[k]}">${v}</span>
     </div>`
  ).join('');

  // Predictions table
  document.getElementById('upload-tbody').innerHTML = data.rows.map(row =>
    `<tr>
      <td class="mono" style="color:var(--muted)">${row.row_num}</td>
      <td><span class="badge b-probe">${row.protocol}</span></td>
      <td style="color:var(--muted)">${row.service}</td>
      <td><span class="badge b-${row.prediction.toLowerCase()}">${row.prediction}</span></td>
      <td>${row.prediction === 'Attack'
      ? `<span class="badge b-${row.severity.toLowerCase()}">${row.severity}</span>`
      : '—'}</td>
      <td>
        <div class="conf-wrap">
          <span style="font-size:11px;font-weight:700;color:var(--text);width:38px;flex-shrink:0">${row.confidence}%</span>
          <div class="conf-bar"><div class="conf-fill" style="width:${row.confidence}%"></div></div>
        </div>
      </td>
    </tr>`
  ).join('');

  document.getElementById('upload-sec').scrollIntoView({ behavior: 'smooth' });
}

function rStat(cls, label, val) {
  return `<div class="r-stat">
    <div class="r-stat-label">${label}</div>
    <div class="r-stat-val ${cls}">${val}</div>
  </div>`;
}

/* ============================================================
   SINGLE CONNECTION ANALYZER  →  POST /api/predict
   ============================================================ */
async function runAnalyzer() {
  const btn = document.getElementById('analyze-btn');
  const res = document.getElementById('analyze-result');
  btn.textContent = '⏳ Analyzing…';
  btn.disabled = true;

  // Build full 41-feature payload, filling unset fields with safe defaults
  const payload = {
    duration: +document.getElementById('p-dur').value,
    protocol_type: document.getElementById('p-proto').value,
    service: document.getElementById('p-svc').value,
    flag: document.getElementById('p-flag').value,
    src_bytes: +document.getElementById('p-src').value,
    dst_bytes: +document.getElementById('p-dst').value,
    land: 0, wrong_fragment: 0, urgent: 0, hot: 0,
    num_failed_logins: 0, logged_in: 1, num_compromised: 0,
    root_shell: 0, su_attempted: 0, num_root: 0,
    num_file_creations: 0, num_shells: 0, num_access_files: 0,
    num_outbound_cmds: 0, is_host_login: 0, is_guest_login: 0,
    count: +document.getElementById('p-cnt').value,
    srv_count: +document.getElementById('p-srvcnt').value,
    serror_rate: 0, srv_serror_rate: 0, rerror_rate: 0, srv_rerror_rate: 0,
    same_srv_rate: 1, diff_srv_rate: 0, srv_diff_host_rate: 0,
    dst_host_count: 255, dst_host_srv_count: 255,
    dst_host_same_srv_rate: 1, dst_host_diff_srv_rate: 0,
    dst_host_same_src_port_rate: 0.01, dst_host_srv_diff_host_rate: 0,
    dst_host_serror_rate: 0, dst_host_srv_serror_rate: 0,
    dst_host_rerror_rate: 0, dst_host_srv_rerror_rate: 0
  };

  try {
    const r = await fetch('/api/predict', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const data = await r.json();
    if (data.error) throw new Error(data.error);

    res.style.display = 'block';
    const isAttack = data.prediction === 'Attack';
    res.className = 'analyze-result ' + (isAttack ? 'ar-attack' : 'ar-normal');
    res.innerHTML = isAttack
      ? `🚨 <strong>INTRUSION DETECTED</strong> · ${data.severity} severity · ${data.confidence}% confidence`
      : `✅ <strong>NORMAL TRAFFIC</strong> · No threat detected · ${data.confidence}% confidence`;
    toast(isAttack ? '🚨 Alert: Attack detected!' : '✅ Normal traffic', isAttack ? 'error' : 'success');
  } catch (e) {
    res.style.display = 'block';
    res.className = 'analyze-result ar-attack';
    res.innerHTML = `⚠️ Error: ${e.message}`;
  }

  btn.textContent = '⚡ Analyze';
  btn.disabled = false;
}

function loadAttackExample() {
  document.getElementById('p-dur').value = 0;
  document.getElementById('p-proto').value = 'tcp';
  document.getElementById('p-svc').value = 'private';
  document.getElementById('p-flag').value = 'S0';
  document.getElementById('p-src').value = 0;
  document.getElementById('p-dst').value = 0;
  document.getElementById('p-cnt').value = 123;
  document.getElementById('p-srvcnt').value = 6;
  toast('⚠️ Loaded DoS (Neptune) attack example');
}

function loadNormalExample() {
  document.getElementById('p-dur').value = 0;
  document.getElementById('p-proto').value = 'tcp';
  document.getElementById('p-svc').value = 'http';
  document.getElementById('p-flag').value = 'SF';
  document.getElementById('p-src').value = 491;
  document.getElementById('p-dst').value = 0;
  document.getElementById('p-cnt').value = 2;
  document.getElementById('p-srvcnt').value = 2;
  toast('✅ Loaded normal HTTP connection example');
}

/* ============================================================
   BOOTSTRAP — load everything on page ready
   ============================================================ */
async function refreshAll() {
  document.getElementById('last-refresh').textContent = 'Refreshing…';
  await Promise.all([fetchLiveData(), loadMetrics()]);
  document.getElementById('last-refresh').textContent =
    'Last updated: ' + new Date().toLocaleTimeString();
}

// Initial load
refreshAll();

// Auto-refresh real-time data every 2 seconds
setInterval(fetchLiveData, 2000);
