// ════════════════════════════════════════════════
// CONFIG — change BACKEND_URL to your HF Space URL
// e.g. 'https://hitan2004-sentinelnet.hf.space'
// ════════════════════════════════════════════════
const BACKEND_URL = 'https://hitan2004-sentinelnet.hf.space';
const BATCH_SIZE  = 50;
const PAGE_SIZE   = 100;

// ════════════════════════════════════════════════
// CONSTANTS
// ════════════════════════════════════════════════
const NSL_KDD_COLUMNS = [
  'duration','protocol_type','service','flag','src_bytes','dst_bytes',
  'land','wrong_fragment','urgent','hot','num_failed_logins','logged_in',
  'num_compromised','root_shell','su_attempted','num_root','num_file_creations',
  'num_shells','num_access_files','num_outbound_cmds','is_host_login','is_guest_login',
  'count','srv_count','serror_rate','srv_serror_rate','rerror_rate','srv_rerror_rate',
  'same_srv_rate','diff_srv_rate','srv_diff_host_rate','dst_host_count','dst_host_srv_count',
  'dst_host_same_srv_rate','dst_host_diff_srv_rate','dst_host_same_src_port_rate',
  'dst_host_srv_diff_host_rate','dst_host_serror_rate','dst_host_srv_serror_rate',
  'dst_host_rerror_rate','dst_host_srv_rerror_rate','label','difficulty_level'
];

const STRING_COLS = new Set(['protocol_type','service','flag','label']);

const ATTACK_MAP = {
  normal:'normal',
  back:'DoS',land:'DoS',neptune:'DoS',pod:'DoS',smurf:'DoS',teardrop:'DoS',
  mailbomb:'DoS',apache2:'DoS',processtable:'DoS',udpstorm:'DoS',
  satan:'Probe',ipsweep:'Probe',nmap:'Probe',portsweep:'Probe',mscan:'Probe',saint:'Probe',
  guess_passwd:'R2L',ftp_write:'R2L',imap:'R2L',phf:'R2L',multihop:'R2L',
  warezmaster:'R2L',warezclient:'R2L',spy:'R2L',xlock:'R2L',xsnoop:'R2L',
  snmpguess:'R2L',snmpgetattack:'R2L',httptunnel:'R2L',sendmail:'R2L',named:'R2L',
  buffer_overflow:'U2R',loadmodule:'U2R',perl:'U2R',rootkit:'U2R',
  ps:'U2R',xterm:'U2R',sqlattack:'U2R'
};

const SEV_MAP     = { normal:'None', DoS:'Critical', Probe:'Medium', R2L:'High', U2R:'Critical' };
const SEV_COLOR   = { None:'#00e87a', Medium:'#00c8e8', High:'#ffaa00', Critical:'#ff3d5a' };
const CLASS_COLOR = { normal:'#00e87a', DoS:'#ff3d5a', Probe:'#00c8e8', R2L:'#ffaa00', U2R:'#b06fff' };
const PROTOCOLS   = ['tcp','udp','icmp'];
const SERVICES    = ['http','ftp','smtp','ssh','dns','telnet','pop3','imap4','finger','auth'];
const LABEL_POOL  = [
  ...Array(60).fill('normal'),
  ...Array(12).fill('neptune'), ...Array(6).fill('smurf'),   ...Array(4).fill('back'),
  ...Array(5).fill('ipsweep'),  ...Array(4).fill('satan'),   ...Array(3).fill('portsweep'),
  ...Array(2).fill('guess_passwd'), ...Array(1).fill('buffer_overflow'), ...Array(1).fill('rootkit')
];

// ════════════════════════════════════════════════
// LIVE MONITOR STATE
// ════════════════════════════════════════════════
let monitorInterval = null, sessionInterval = null;
let sessionSeconds = 0, isRunning = false, usingRealModel = false, packetId = 0;
const counts = { normal:0, DoS:0, Probe:0, R2L:0, U2R:0 };
let totalPackets = 0, totalIntrusions = 0, confSum = 0, peakClass = null;
let confBuckets = { 90:0, 80:0, 70:0, low:0 };
let timelineBuckets = Array(60).fill(0), heatmapCells = Array(60).fill(null);
let tlDirty = false;

// ════════════════════════════════════════════════
// CSV STATE
// ════════════════════════════════════════════════
let csvRows = [], csvResults = [], csvIndex = 0, csvRunning = false, csvStartTime = null;
let csvCounts    = { normal:0, DoS:0, Probe:0, R2L:0, U2R:0 };
let csvSevCounts = { Critical:0, High:0, Medium:0, None:0 };
let csvConfSum = 0, csvIntrusionCount = 0, csvConfHistory = [];
let csvUsingReal = false, csvFormatInfo = '';
let batchNum = 0, totalBatches = 0, reportPage = 0;

// ════════════════════════════════════════════════
// TAB SWITCHER
// ════════════════════════════════════════════════
function switchTab(name, btn) {
  document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.getElementById('tab-' + name).classList.add('active');
  btn.classList.add('active');
}

// ════════════════════════════════════════════════
// CSV PARSER — auto header detection
// ════════════════════════════════════════════════
function parseCSV(text) {
  const lines = text.trim().split('\n').filter(l => l.trim());
  if (!lines.length) return { rows:[], hasHeader:false, cols:0 };

  function splitLine(line) {
    const vals = []; let cur = '', inQ = false;
    for (const c of line) {
      if (c === '"') inQ = !inQ;
      else if (c === ',' && !inQ) { vals.push(cur.trim()); cur = ''; }
      else cur += c;
    }
    vals.push(cur.trim());
    return vals;
  }

  const firstVals = splitLine(lines[0]);
  const knownCols = new Set(NSL_KDD_COLUMNS);
  const looksLikeHeader = firstVals.some(v => knownCols.has(v.toLowerCase().replace(/^"|"$/g, '')));
  let headers, dataLines;

  if (looksLikeHeader) {
    headers   = firstVals.map(h => h.toLowerCase().replace(/^"|"$/g, '').trim());
    dataLines = lines.slice(1);
  } else {
    headers   = NSL_KDD_COLUMNS.slice(0, firstVals.length);
    dataLines = lines;
  }

  const rows = [];
  for (const line of dataLines) {
    const vals = splitLine(line);
    if (vals.length < 2) continue;
    const obj = {};
    headers.forEach((h, i) => {
      let v = (vals[i] || '').trim().replace(/^"|"$/g, '');
      obj[h] = STRING_COLS.has(h) ? v : (v === '' ? 0 : (isNaN(v) ? v : parseFloat(v)));
    });
    rows.push(obj);
  }
  return { rows, hasHeader: looksLikeHeader, cols: headers.length };
}

// ════════════════════════════════════════════════
// LOCAL CLASSIFIER — uses label col + feature heuristics
// ════════════════════════════════════════════════
function classifyLocal(row) {
  const rawLabel = (row.label || '').toString().toLowerCase().trim().replace(/\.$/, '');
  if (rawLabel && rawLabel !== 'unknown') {
    const mc = ATTACK_MAP[rawLabel];
    if (mc) {
      const base = { normal:0.88, DoS:0.91, Probe:0.84, R2L:0.79, U2R:0.82 }[mc] || 0.80;
      const conf = Math.min(0.99, base + (Math.random() * 0.08 - 0.04));
      return { predicted_class:mc, severity:SEV_MAP[mc], confidence:+conf.toFixed(4), is_intrusion:mc !== 'normal' };
    }
  }
  const srcBytes   = parseFloat(row.src_bytes)   || 0;
  const flag       = (row.flag || '').toUpperCase();
  const serrorRate = parseFloat(row.serror_rate)  || 0;
  const rerrorRate = parseFloat(row.rerror_rate)  || 0;
  const srvCount   = parseFloat(row.srv_count)    || 0;
  const count      = parseFloat(row.count)        || 0;
  const loggedIn   = parseFloat(row.logged_in)    || 0;
  const numRoot    = parseFloat(row.num_root)      || 0;
  const rootShell  = parseFloat(row.root_shell)   || 0;

  let cls = 'normal', conf = 0.75 + Math.random() * 0.15;
  if (['S0','S1','S2','S3','REJ','RSTO','RSTR'].includes(flag) && count > 100) { cls = 'DoS';   conf = 0.85 + Math.random() * 0.1; }
  else if (srcBytes > 50000 && (parseFloat(row.duration) || 0) < 5)            { cls = 'DoS';   conf = 0.80 + Math.random() * 0.12; }
  else if (serrorRate > 0.7 || rerrorRate > 0.7)                                { cls = 'DoS';   conf = 0.78 + Math.random() * 0.1; }
  else if (srvCount > 100 && srcBytes < 500 && loggedIn === 0)                  { cls = 'Probe'; conf = 0.80 + Math.random() * 0.12; }
  else if (loggedIn === 1 && (row.num_failed_logins || 0) > 0 && srcBytes < 10000) { cls = 'R2L'; conf = 0.75 + Math.random() * 0.12; }
  else if (rootShell > 0 || numRoot > 0)                                        { cls = 'U2R';   conf = 0.82 + Math.random() * 0.12; }

  return { predicted_class:cls, severity:SEV_MAP[cls], confidence:+Math.min(0.99, conf).toFixed(4), is_intrusion:cls !== 'normal' };
}

// ════════════════════════════════════════════════
// API CALLS
// ════════════════════════════════════════════════
async function predictBatch(rows) {
  try {
    const r = await fetch(BACKEND_URL + '/predict', {
      method: 'POST',
      headers: { 'Content-Type':'application/json', 'ngrok-skip-browser-warning':'true' },
      body: JSON.stringify({ rows }),
      signal: AbortSignal.timeout(30000)
    });
    if (!r.ok) return null;
    const d = await r.json();
    return (d.status === 'ok' && Array.isArray(d.results)) ? d.results : null;
  } catch { return null; }
}

async function predictSingle(row) {
  try {
    const r = await fetch(BACKEND_URL + '/predict', {
      method: 'POST',
      headers: { 'Content-Type':'application/json', 'ngrok-skip-browser-warning':'true' },
      body: JSON.stringify({ rows:[row] }),
      signal: AbortSignal.timeout(15000)
    });
    if (!r.ok) return null;
    const d = await r.json();
    return (d.status === 'ok' && d.results?.[0]) ? d.results[0] : null;
  } catch { return null; }
}

// ════════════════════════════════════════════════
// FILE UPLOAD
// ════════════════════════════════════════════════
const uploadZone = document.getElementById('uploadZone');
uploadZone.addEventListener('dragover', e => { e.preventDefault(); uploadZone.classList.add('drag-over'); });
uploadZone.addEventListener('dragleave', () => uploadZone.classList.remove('drag-over'));
uploadZone.addEventListener('drop', e => {
  e.preventDefault(); uploadZone.classList.remove('drag-over');
  const f = e.dataTransfer.files[0];
  if (f && f.name.endsWith('.csv')) processFileUpload(f);
});

function handleFileSelect(e) { const f = e.target.files[0]; if (f) processFileUpload(f); }

function processFileUpload(file) {
  const reader = new FileReader();
  reader.onload = e => {
    const { rows, hasHeader, cols } = parseCSV(e.target.result);
    if (!rows.length) { alert('Could not parse CSV.'); return; }
    csvRows = rows;
    csvFormatInfo = hasHeader ? `With headers · ${cols} columns` : `Headerless — auto-mapped · ${cols} columns`;
    totalBatches  = Math.ceil(rows.length / BATCH_SIZE);

    const banner = document.getElementById('formatBanner');
    banner.style.display = 'flex'; banner.className = 'format-banner ok';
    banner.innerHTML = `✓ ${hasHeader ? 'Headers detected' : 'Headerless — NSL-KDD auto-mapped'} · ${cols} columns · ${rows.length.toLocaleString()} rows · ${totalBatches} batches`;

    document.getElementById('csvUploadSection').style.display = 'none';
    document.getElementById('csvProcessingArea').classList.add('visible');
    setText('csvFileName', file.name);
    setText('csvFileMeta', `${rows.length.toLocaleString()} rows · ${(file.size/1024).toFixed(1)} KB · ${csvFormatInfo}`);

    csvResults = []; csvIndex = 0; csvConfSum = 0; csvIntrusionCount = 0;
    csvConfHistory = []; batchNum = 0;
    Object.keys(csvCounts).forEach(k => csvCounts[k] = 0);
    Object.keys(csvSevCounts).forEach(k => csvSevCounts[k] = 0);
    csvUsingReal = false; csvStartTime = null;
  };
  reader.readAsText(file);
}

// ════════════════════════════════════════════════
// CSV BATCH ENGINE
// ════════════════════════════════════════════════
async function startCsvAnalysis() {
  if (csvRunning || csvIndex >= csvRows.length) return;
  csvRunning = true; csvStartTime = csvStartTime || Date.now();
  document.getElementById('csvStartBtn').disabled = true;
  document.getElementById('csvStopBtn').disabled  = false;
  document.getElementById('csvProgressBlock').style.display = 'block';
  document.getElementById('csvLiveGrid').style.display = 'grid';
  document.getElementById('reportSection').classList.remove('visible');
  document.getElementById('liveDot').className = 'dot amber';
  setText('liveStatus', 'SCANNING');
  await processBatches();
}

async function processBatches() {
  while (csvRunning && csvIndex < csvRows.length) {
    const bStart = csvIndex, bEnd = Math.min(csvIndex + BATCH_SIZE, csvRows.length);
    const batch  = csvRows.slice(bStart, bEnd);
    batchNum++;

    if (batchNum === 1 || batchNum % 5 === 0 || batchNum === totalBatches)
      updateBatchChips(batchNum, totalBatches);
    setText('csvCurrentRow', `Batch ${batchNum}/${totalBatches} — rows ${(bStart+1).toLocaleString()}–${bEnd.toLocaleString()}`);

    let results = await predictBatch(batch);
    if (results) {
      if (!csvUsingReal) { csvUsingReal = true; setConnBadge('real'); }
    } else {
      if (csvUsingReal || batchNum === 1) { csvUsingReal = false; setConnBadge('local'); }
      results = batch.map(r => classifyLocal(r));
    }

    for (let i = 0; i < batch.length; i++) {
      const { predicted_class:cls, confidence:conf, severity:sev, is_intrusion:isI } = results[i];
      csvResults.push({ rowNum:bStart+i+1, row:batch[i], cls, conf, sev, isI });
      if (csvResults.length % 5 === 0) csvConfHistory.push(conf);
      csvCounts[cls]   = (csvCounts[cls]   || 0) + 1;
      csvSevCounts[sev]= (csvSevCounts[sev]|| 0) + 1;
      csvConfSum += conf;
      if (isI) csvIntrusionCount++;
    }

    // Show last 5 rows in feed
    const feedSlice = batch.slice(-2);
    feedSlice.forEach((row, i) => {
      const ri = bEnd - feedSlice.length + i;
      addCsvFeedRow(ri+1, row, results[batch.length-feedSlice.length+i].predicted_class,
                    results[batch.length-feedSlice.length+i].confidence,
                    results[batch.length-feedSlice.length+i].severity);
    });

    csvIndex = bEnd;
    const pct      = (csvIndex / csvRows.length * 100).toFixed(1);
    const elapsed  = (Date.now() - csvStartTime) / 1000;
    const rate     = csvIndex / Math.max(elapsed, 0.01);
    const remaining= (csvRows.length - csvIndex) / Math.max(rate, 0.1);

    setText('csvProgressStats', `${csvIndex.toLocaleString()} / ${csvRows.length.toLocaleString()} rows`);
    setText('csvProgressPct',   pct + '%');
    setText('csvThreatRate',    `Threats: ${csvIntrusionCount.toLocaleString()}`);
    setText('csvProgressEta',   csvIndex < csvRows.length ? `ETA: ${formatETA(remaining)}` : 'Done!');
    setText('csvSpeedStat',     Math.round(rate) + ' rows/s');
    document.getElementById('csvProgressFill').style.width = pct + '%';
    if (csvIntrusionCount / Math.max(csvIndex,1) > 0.5)
      document.getElementById('csvProgressFill').classList.add('warning');

    if (batchNum % 5 === 0 || batchNum === totalBatches) updateCsvSidebar(rate);
    setText('csvAlertCount', csvIntrusionCount.toLocaleString() + ' THREATS');
    await new Promise(r => setTimeout(r, 100));
  }
  if (csvIndex >= csvRows.length) finishCsvAnalysis();
}

function setConnBadge(type) {
  const el = document.getElementById('connBadge');
  if (type === 'real') { el.textContent = '✓ REAL MODEL'; el.className = 'real'; }
  else                 { el.textContent = '⚠ LOCAL SIM';  el.className = 'local'; }
}

function updateBatchChips(current, total) {
  const el = document.getElementById('batchStatus'); el.innerHTML = '';
  const show = Math.min(total, 12);
  for (let i = 1; i <= show; i++) {
    const chip = document.createElement('div');
    chip.className = 'batch-chip' + (i < current ? ' done' : i === current ? ' active' : '');
    chip.textContent = i < current ? `✓${i}` : i === current ? `⟳${i}` : `${i}`;
    el.appendChild(chip);
  }
  if (total > show) {
    const chip = document.createElement('div');
    chip.className = 'batch-chip';
    chip.textContent = `+${total-show} more`;
    el.appendChild(chip);
  }
}

function addCsvFeedRow(rowNum, row, cls, conf, sev) {
  const tbody = document.getElementById('csvFeedBody');
  const tr = document.createElement('tr'); tr.className = 'csv-new-row';
  if (cls !== 'normal') tr.style.background = 'rgba(255,61,90,0.025)';
  tr.innerHTML = `
    <td style="color:var(--muted)">${rowNum}</td>
    <td style="color:var(--cyan)">${row.protocol_type||'—'}</td>
    <td>${row.service||'—'}</td>
    <td>${(row.src_bytes||0).toLocaleString()}</td>
    <td><span class="cls-badge cls-${cls}">${cls}</span></td>
    <td style="color:${conf>0.9?'var(--accent)':conf>0.8?'var(--cyan)':'var(--amber)'}">${(conf*100).toFixed(1)}%</td>
    <td style="color:${SEV_COLOR[sev]}">● ${sev}</td>`;
  tbody.insertBefore(tr, tbody.firstChild);
  while (tbody.children.length > 50) tbody.removeChild(tbody.lastChild);
}

function updateCsvSidebar(rate) {
  const classes = ['normal','DoS','Probe','R2L','U2R'];
  const mx = Math.max(...classes.map(c => csvCounts[c]||0), 1);
  classes.forEach(c => { setWidth('csvbar-'+c, (csvCounts[c]||0)/mx*100); setText('csvbc-'+c, (csvCounts[c]||0).toLocaleString()); });
  setText('csvAvgConf', csvIndex > 0 ? (csvConfSum/csvIndex*100).toFixed(1)+'%' : '—');
  const sevs = ['Critical','High','Medium','None'];
  const smx  = Math.max(...sevs.map(s => csvSevCounts[s]||0), 1);
  sevs.forEach(s => { setWidth('sevbar-'+s, (csvSevCounts[s]||0)/smx*100); setText('sevbc-'+s, (csvSevCounts[s]||0).toLocaleString()); });
  setText('csvProcRate', Math.round(rate).toLocaleString());
}

function stopCsvAnalysis() {
  csvRunning = false;
  document.getElementById('csvStartBtn').disabled = false;
  document.getElementById('csvStopBtn').disabled  = true;
  document.getElementById('liveDot').className = 'dot red';
  setText('liveStatus', 'PAUSED');
}

function finishCsvAnalysis() {
  csvRunning = false;
  document.getElementById('csvStartBtn').disabled = true;
  document.getElementById('csvStopBtn').disabled  = true;
  document.getElementById('liveDot').className = 'dot green';
  setText('liveStatus', 'DONE');
  setText('csvProgressEta', 'Done!');
  setText('csvCurrentRow', `✓ All ${csvRows.length.toLocaleString()} rows processed. Building report…`);
  setTimeout(() => { exportAnnotatedCSV(); buildReport(); }, 300);
}

// ════════════════════════════════════════════════
// REPORT BUILDER
// ════════════════════════════════════════════════
function buildReport() {
  document.getElementById('reportSection').classList.add('visible');
  const elapsed   = (Date.now() - csvStartTime) / 1000;
  const fileName  = document.getElementById('csvFileName').textContent;
  const total     = csvResults.length, threats = csvIntrusionCount;
  const avgConf   = (csvConfSum/total*100).toFixed(1) + '%';
  const rate      = (threats/total*100).toFixed(1) + '%';
  const riskScore = Math.min(100, Math.round(
    ((csvCounts.DoS||0)*0.4 + (csvCounts.U2R||0)*0.35 + (csvCounts.R2L||0)*0.15 + (csvCounts.Probe||0)*0.1)
    / Math.max(total,1) * 100 * 6
  ));

  setText('bannerSub',      `${total.toLocaleString()} rows · ${formatETA(elapsed)} · ${threats.toLocaleString()} threats`);
  setText('rmFile',         fileName);
  setText('rmRows',         total.toLocaleString());
  setText('rmDate',         new Date().toLocaleString());
  setText('rmModel',        csvUsingReal ? 'Real Random Forest' : 'Local Simulation');
  setText('rmDuration',     formatETA(elapsed));
  setText('rmFormat',       csvFormatInfo);
  setText('reportSubtitle', `Generated ${new Date().toUTCString()}`);
  setText('rs-total',   total.toLocaleString());
  setText('rs-threats', threats.toLocaleString());
  setText('rs-rate',    rate);
  setText('rs-conf',    avgConf);
  setText('rs-risk',    riskScore + '/100');

  const sevs = ['Critical','High','Medium','None'];
  const smx  = Math.max(...sevs.map(s => csvSevCounts[s]||0), 1);
  sevs.forEach(s => { setWidth('rsevbar-'+s, (csvSevCounts[s]||0)/smx*100); setText('rsevbc-'+s, (csvSevCounts[s]||0).toLocaleString()); });

  requestAnimationFrame(() => {
    drawBarChart(); drawConfWave(); drawIntensity();
    drawProto(); drawServices(); drawGauge(riskScore);
    buildClusters(); reportPage = 0; renderReportPage();
  });
  setTimeout(() => document.getElementById('reportSection').scrollIntoView({ behavior:'smooth', block:'start' }), 300);
}

// ── Paginated table ──
function renderReportPage() {
  const tbody = document.getElementById('reportTableBody');
  const total = csvResults.length, totalPages = Math.ceil(total / PAGE_SIZE);
  const start = reportPage * PAGE_SIZE, end = Math.min(start + PAGE_SIZE, total);
  const frag  = document.createDocumentFragment();

  for (let i = start; i < end; i++) {
    const { rowNum, row, cls, conf, sev, isI } = csvResults[i];
    const tr = document.createElement('tr');
    if (isI) tr.className = 'row-intrusion';
    tr.innerHTML = `
      <td style="color:var(--muted)">${rowNum}</td>
      <td style="color:var(--cyan)">${row.protocol_type||'—'}</td>
      <td>${row.service||'—'}</td>
      <td>${(row.src_bytes||0).toLocaleString()}</td>
      <td>${(row.dst_bytes||0).toLocaleString()}</td>
      <td><span class="cls-badge cls-${cls}">${cls}</span></td>
      <td style="color:${conf>0.9?'var(--accent)':conf>0.8?'var(--cyan)':'var(--amber)'}">${(conf*100).toFixed(1)}%</td>
      <td style="color:${SEV_COLOR[sev]}">● ${sev}</td>
      <td style="color:var(--muted);font-size:10px">${row.label||'—'}</td>`;
    frag.appendChild(tr);
  }
  tbody.innerHTML = '';
  tbody.appendChild(frag);
  setText('reportRowCount', `${total.toLocaleString()} rows`);
  setText('pgInfo', `Page ${reportPage+1} of ${totalPages} · rows ${start+1}–${end}`);
  document.getElementById('pgPrev').disabled = reportPage === 0;
  document.getElementById('pgNext').disabled = reportPage >= totalPages - 1;
}

function changePage(dir) {
  reportPage += dir; renderReportPage();
  document.getElementById('reportSection').scrollIntoView({ behavior:'smooth', block:'start' });
}

// ── Charts ──
function drawBarChart() {
  const c = document.getElementById('reportBarCanvas'), ctx = c.getContext('2d');
  const W = c.offsetWidth||300, H = 160;
  c.width = W*devicePixelRatio; c.height = H*devicePixelRatio;
  ctx.scale(devicePixelRatio, devicePixelRatio); ctx.clearRect(0,0,W,H);
  const classes = ['normal','DoS','Probe','R2L','U2R'];
  const colors  = ['#00e87a','#ff3d5a','#00c8e8','#ffaa00','#b06fff'];
  const vals    = classes.map(c => csvCounts[c]||0), mx = Math.max(...vals, 1);
  const bw = (W-40)/classes.length, pad = bw*0.18;
  classes.forEach((cls, i) => {
    const x = 20+i*bw+pad, bW = bw-pad*2, bH = (vals[i]/mx)*(H-30), y = H-10-bH;
    const g = ctx.createLinearGradient(0,y,0,H-10);
    g.addColorStop(0, colors[i]); g.addColorStop(1, colors[i]+'33');
    ctx.fillStyle = g; ctx.beginPath(); ctx.roundRect(x,y,bW,Math.max(bH,1),4); ctx.fill();
    ctx.fillStyle = 'rgba(90,122,153,.9)'; ctx.font = '9px IBM Plex Mono'; ctx.textAlign = 'center';
    ctx.fillText(cls, x+bW/2, H-1);
    if (vals[i] > 0) { ctx.fillStyle = colors[i]; ctx.fillText(vals[i].toLocaleString(), x+bW/2, y-4); }
  });
}

function drawConfWave() {
  const c = document.getElementById('reportConfCanvas'), ctx = c.getContext('2d');
  const W = c.offsetWidth||300, H = 160;
  c.width = W*devicePixelRatio; c.height = H*devicePixelRatio;
  ctx.scale(devicePixelRatio, devicePixelRatio); ctx.clearRect(0,0,W,H);
  const data = csvConfHistory; if (data.length < 2) return;
  const xStep = (W-20)/Math.max(data.length-1,1), mn = 0.5, mx = 1;
  ctx.strokeStyle = 'rgba(0,200,120,.06)'; ctx.lineWidth = 1;
  [.25,.5,.75,1].forEach(f => { const y=10+(1-f)*(H-20); ctx.beginPath(); ctx.moveTo(10,y); ctx.lineTo(W-10,y); ctx.stroke(); });
  ctx.beginPath();
  data.forEach((v,i) => { const x=10+i*xStep, y=10+(1-(v-mn)/(mx-mn))*(H-20); i===0?ctx.moveTo(x,y):ctx.lineTo(x,y); });
  ctx.lineTo(10+(data.length-1)*xStep, H-10); ctx.lineTo(10, H-10); ctx.closePath();
  const g = ctx.createLinearGradient(0,0,0,H); g.addColorStop(0,'rgba(0,200,232,.15)'); g.addColorStop(1,'rgba(0,200,232,.01)');
  ctx.fillStyle = g; ctx.fill();
  ctx.beginPath(); ctx.strokeStyle = '#00c8e8'; ctx.lineWidth = 1.5;
  data.forEach((v,i) => { const x=10+i*xStep, y=10+(1-(v-mn)/(mx-mn))*(H-20); i===0?ctx.moveTo(x,y):ctx.lineTo(x,y); });
  ctx.stroke();
  const avg = csvConfSum/csvResults.length, avgY = 10+(1-(avg-mn)/(mx-mn))*(H-20);
  ctx.beginPath(); ctx.setLineDash([4,3]); ctx.strokeStyle='rgba(0,232,122,.6)'; ctx.lineWidth=1;
  ctx.moveTo(10,avgY); ctx.lineTo(W-10,avgY); ctx.stroke(); ctx.setLineDash([]);
  ctx.fillStyle='rgba(0,232,122,.8)'; ctx.font='9px IBM Plex Mono'; ctx.textAlign='left';
  ctx.fillText(`avg ${(avg*100).toFixed(1)}%`, 14, avgY-5);
}

function drawIntensity() {
  const c = document.getElementById('reportIntensityCanvas'), ctx = c.getContext('2d');
  const W = c.offsetWidth||300, H = 160;
  c.width = W*devicePixelRatio; c.height = H*devicePixelRatio;
  ctx.scale(devicePixelRatio, devicePixelRatio); ctx.clearRect(0,0,W,H);
  const wSize   = Math.max(5, Math.floor(csvResults.length/60));
  const windows = [];
  for (let i = 0; i < csvResults.length; i += wSize) {
    const sl = csvResults.slice(i, i+wSize);
    windows.push(sl.filter(r => r.isI).length / sl.length);
  }
  if (windows.length < 2) { ctx.fillStyle='#4a6a88'; ctx.font='11px IBM Plex Mono'; ctx.textAlign='center'; ctx.fillText('Not enough data',W/2,H/2); return; }
  const mx = Math.max(...windows, .01), xStep = (W-20)/Math.max(windows.length-1,1);
  ctx.strokeStyle='rgba(255,61,90,.05)'; ctx.lineWidth=1;
  [.25,.5,.75,1].forEach(f => { const y=10+(1-f)*(H-20); ctx.beginPath(); ctx.moveTo(10,y); ctx.lineTo(W-10,y); ctx.stroke(); });
  ctx.beginPath();
  windows.forEach((v,i) => { const x=10+i*xStep, y=10+(1-v/mx)*(H-20); i===0?ctx.moveTo(x,y):ctx.lineTo(x,y); });
  ctx.lineTo(10+(windows.length-1)*xStep, H-10); ctx.lineTo(10,H-10); ctx.closePath();
  const g = ctx.createLinearGradient(0,0,0,H); g.addColorStop(0,'rgba(255,61,90,.28)'); g.addColorStop(1,'rgba(255,61,90,.02)');
  ctx.fillStyle=g; ctx.fill();
  ctx.beginPath(); ctx.strokeStyle='#ff3d5a'; ctx.lineWidth=2;
  windows.forEach((v,i) => { const x=10+i*xStep, y=10+(1-v/mx)*(H-20); i===0?ctx.moveTo(x,y):ctx.lineTo(x,y); });
  ctx.stroke();
}

function drawProto() {
  const el = document.getElementById('protoBreakdown'); el.innerHTML = '';
  const pc = {}, pt = {};
  csvResults.forEach(({ row, isI }) => { const p=row.protocol_type||'unknown'; pc[p]=(pc[p]||0)+1; if(isI)pt[p]=(pt[p]||0)+1; });
  const sorted = Object.entries(pc).sort((a,b) => b[1]-a[1]);
  const mx     = Math.max(...sorted.map(([,v]) => v), 1);
  const frag   = document.createDocumentFragment();
  sorted.forEach(([proto, cnt]) => {
    const tc=pt[proto]||0, tp=cnt>0?Math.round(tc/cnt*100):0;
    const div = document.createElement('div'); div.className = 'proto-row';
    div.innerHTML = `<div class="proto-lbl">${proto}</div><div class="proto-track"><div class="proto-fill" style="width:${cnt/mx*100}%;background:${tc>0?'var(--red)':'var(--accent)'}"></div></div><div class="proto-cnt">${cnt.toLocaleString()} <span style="color:${tc>0?'var(--red)':'var(--muted)'}">${tp}% threat</span></div>`;
    frag.appendChild(div);
  });
  el.appendChild(frag);
}

function drawServices() {
  const el = document.getElementById('servicesList'); el.innerHTML = '';
  const sc = {}, st = {};
  csvResults.forEach(({ row, isI }) => { const s=row.service||'unknown'; sc[s]=(sc[s]||0)+1; if(isI)st[s]=(st[s]||0)+1; });
  const sorted = Object.entries(sc).sort((a,b) => b[1]-a[1]).slice(0, 8);
  const mx     = Math.max(...sorted.map(([,v]) => v), 1);
  const frag   = document.createDocumentFragment();
  sorted.forEach(([svc, cnt]) => {
    const hot = (st[svc]||0) > cnt*0.3;
    const div = document.createElement('div'); div.className = 'svc-row';
    div.innerHTML = `<span class="svc-name" style="color:${hot?'var(--red)':'var(--cyan)'}">${svc}</span><span style="flex:1;margin:0 8px;background:var(--surface);border-radius:2px;height:4px;display:block;overflow:hidden"><span style="display:block;height:100%;width:${Math.round(cnt/mx*100)}%;background:${hot?'var(--red)':'var(--cyan)'};border-radius:2px"></span></span><span style="font-family:var(--mono);font-size:10px;color:var(--muted2)">${cnt.toLocaleString()}</span>`;
    frag.appendChild(div);
  });
  el.appendChild(frag);
}

function drawGauge(score) {
  const c = document.getElementById('riskGaugeCanvas'), ctx = c.getContext('2d');
  const W = 160, H = 90;
  c.width = W*devicePixelRatio; c.height = H*devicePixelRatio;
  ctx.scale(devicePixelRatio, devicePixelRatio); ctx.clearRect(0,0,W,H);
  const cx=W/2, cy=H-8, r=66;
  ctx.beginPath(); ctx.arc(cx,cy,r,Math.PI,2*Math.PI); ctx.strokeStyle='rgba(255,255,255,.05)'; ctx.lineWidth=14; ctx.lineCap='round'; ctx.stroke();
  [[0,.33,'#00e87a'],[.33,.66,'#ffaa00'],[.66,1,'#ff3d5a']].forEach(([from,to,col]) => {
    ctx.beginPath(); ctx.arc(cx,cy,r,Math.PI+from*Math.PI,Math.PI+to*Math.PI); ctx.strokeStyle=col+'55'; ctx.lineWidth=14; ctx.stroke();
  });
  const sc = score<33?'#00e87a':score<66?'#ffaa00':'#ff3d5a';
  ctx.beginPath(); ctx.arc(cx,cy,r,Math.PI,Math.PI+(score/100)*Math.PI); ctx.strokeStyle=sc; ctx.lineWidth=14; ctx.lineCap='round'; ctx.stroke();
  ctx.fillStyle=sc; ctx.font='bold 22px IBM Plex Mono'; ctx.textAlign='center'; ctx.textBaseline='middle'; ctx.fillText(score,cx,cy-16);
  ctx.fillStyle='rgba(90,122,153,.8)'; ctx.font='9px IBM Plex Mono'; ctx.fillText('/100',cx,cy-2);
  const lbl = score<20?'LOW':score<40?'MODERATE':score<60?'ELEVATED':score<80?'HIGH':'CRITICAL';
  setText('riskLabel', `${lbl} RISK · Score ${score}/100`);
}

function buildClusters() {
  const grid = document.getElementById('clusterGrid'); grid.innerHTML = '';
  let cnt = 0; const frag = document.createDocumentFragment();
  ['DoS','Probe','R2L','U2R','normal'].forEach(cls => {
    const c = csvCounts[cls]||0; if (!c) return; cnt++;
    const col = CLASS_COLOR[cls], res = csvResults.filter(r => r.cls === cls);
    const avgConf = res.reduce((s,r) => s+r.conf, 0) / c;
    const div = document.createElement('div'); div.className = `cluster-card ${cls}`;
    div.innerHTML = `<div class="cluster-title" style="color:${col}">${cls} Traffic</div><div class="cluster-count" style="color:${col}">${c.toLocaleString()}</div><div class="cluster-sub">Severity: ${SEV_MAP[cls]}<br>Avg confidence: ${(avgConf*100).toFixed(1)}%<br>${(c/csvResults.length*100).toFixed(1)}% of dataset</div>`;
    frag.appendChild(div);
  });
  grid.appendChild(frag);
  if (!cnt) grid.innerHTML = '<div style="padding:20px;font-family:var(--mono);font-size:11px;color:var(--accent);grid-column:span 4">✓ No attack clusters — clean dataset</div>';
  setText('clusterCount', cnt + ' clusters');
}

// ════════════════════════════════════════════════
// EXPORTS
// ════════════════════════════════════════════════
function exportAnnotatedCSV() {
  if (!csvResults.length) return;
  const headers = Object.keys(csvResults[0].row).concat(['predicted_class','severity','confidence','is_intrusion']);
  const lines   = [headers.join(',')];
  csvResults.forEach(({ row, cls, sev, conf, isI }) => {
    const vals = Object.values(row).map(v => typeof v==='string' && v.includes(',') ? `"${v}"` : v);
    vals.push(cls, sev, conf, isI?1:0); lines.push(vals.join(','));
  });
  downloadFile('sentinelnet_annotated.csv', lines.join('\n'), 'text/csv');
}

function exportJSON() {
  if (!csvResults.length) { alert('No results.'); return; }
  const data = {
    meta: { file:document.getElementById('csvFileName').textContent, date:new Date().toISOString(), total:csvResults.length, threats:csvIntrusionCount, threatRate:(csvIntrusionCount/csvResults.length*100).toFixed(1)+'%', model:csvUsingReal?'Real RF':'Local Sim', batchSize:BATCH_SIZE },
    distribution:csvCounts, severity:csvSevCounts,
    avgConf:(csvConfSum/csvResults.length*100).toFixed(2)+'%',
    results:csvResults.map(({ rowNum, cls, conf, sev, isI }) => ({ rowNum, cls, conf, sev, isI }))
  };
  downloadFile('sentinelnet_results.json', JSON.stringify(data,null,2), 'application/json');
}

function exportPDFReport() {
  if (!csvResults.length) { alert('No results.'); return; }
  const total=csvResults.length, threats=csvIntrusionCount;
  const rate=(threats/total*100).toFixed(1), avgConf=(csvConfSum/total*100).toFixed(1);
  const fileName=document.getElementById('csvFileName').textContent;
  const dateStr=new Date().toLocaleString(), elapsed=(Date.now()-csvStartTime)/1000;
  const modelSrc=csvUsingReal?'Real Random Forest':'Local Simulation';
  const riskScore=Math.min(100,Math.round(((csvCounts.DoS||0)*0.4+(csvCounts.U2R||0)*0.35+(csvCounts.R2L||0)*0.15+(csvCounts.Probe||0)*0.1)/Math.max(total,1)*100*6));
  const riskLbl=riskScore<20?'LOW':riskScore<40?'MODERATE':riskScore<60?'ELEVATED':riskScore<80?'HIGH':'CRITICAL';
  const colors={normal:'#00e87a',DoS:'#ff3d5a',Probe:'#00c8e8',R2L:'#ffaa00',U2R:'#b06fff'};
  const sevColors={None:'#00e87a',Medium:'#00c8e8',High:'#ffaa00',Critical:'#ff3d5a'};
  const distRows=['normal','DoS','Probe','R2L','U2R'].map(c=>`<tr><td style="color:${colors[c]}">${c}</td><td>${(csvCounts[c]||0).toLocaleString()}</td><td>${total>0?((csvCounts[c]||0)/total*100).toFixed(1):'0'}%</td><td style="color:${sevColors[SEV_MAP[c]]}">${SEV_MAP[c]}</td></tr>`).join('');
  const pc={}; csvResults.forEach(({row})=>{const p=row.protocol_type||'unknown';pc[p]=(pc[p]||0)+1;});
  const protoRows=Object.entries(pc).sort((a,b)=>b[1]-a[1]).map(([p,c])=>`<tr><td>${p}</td><td>${c.toLocaleString()}</td><td>${(c/total*100).toFixed(1)}%</td></tr>`).join('');
  const topThreats=csvResults.filter(r=>r.isI).slice(0,100);
  const threatRows=topThreats.map(({rowNum,row,cls,conf,sev})=>`<tr><td>${rowNum}</td><td>${row.protocol_type||'—'}</td><td>${row.service||'—'}</td><td>${(row.src_bytes||0).toLocaleString()}</td><td style="color:${colors[cls]};font-weight:bold">${cls}</td><td>${(conf*100).toFixed(1)}%</td><td style="color:${sevColors[sev]}">${sev}</td></tr>`).join('');
  const html=`<!DOCTYPE html><html><head><meta charset="UTF-8"/><title>SentinelNet Report</title>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600;700&display=swap" rel="stylesheet">
<style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:'IBM Plex Mono',monospace;background:#04080d;color:#d8eeff;padding:40px;font-size:11px}h1{color:#00e87a;font-size:22px;border-bottom:2px solid #00e87a;padding-bottom:12px;margin-bottom:8px}h2{color:#00c8e8;font-size:13px;margin:28px 0 12px;letter-spacing:2px;text-transform:uppercase}.meta{color:#4a6a88;font-size:10px;margin-bottom:32px;line-height:2.2}.grid{display:grid;grid-template-columns:repeat(5,1fr);gap:14px;margin-bottom:32px}.stat{background:#080e16;border:1px solid rgba(0,210,130,0.15);border-radius:10px;padding:16px;text-align:center}.stat-val{font-size:24px;font-weight:700;margin-bottom:5px}.stat-lbl{font-size:8px;color:#4a6a88;letter-spacing:2px;text-transform:uppercase}table{width:100%;border-collapse:collapse;margin-bottom:28px}th{background:#0d1520;padding:9px 12px;text-align:left;color:#4a6a88;font-size:8px;letter-spacing:1.5px;border-bottom:1px solid rgba(0,210,130,0.2)}td{padding:7px 12px;border-top:1px solid rgba(0,210,130,0.06)}.risk-box{background:#0d1520;border:1px solid rgba(0,210,130,0.2);border-radius:12px;padding:20px;text-align:center;margin-bottom:28px}.risk-num{font-size:40px;font-weight:700;color:${riskScore<33?'#00e87a':riskScore<66?'#ffaa00':'#ff3d5a'}}.footer{margin-top:40px;padding-top:14px;border-top:1px solid rgba(0,210,130,0.12);color:#4a6a88;font-size:9px;text-align:center}@media print{body{background:#04080d!important;-webkit-print-color-adjust:exact;print-color-adjust:exact}}</style></head><body>
<h1>🛡 SentinelNet — Threat Analysis Report</h1>
<div class="meta">File: <strong style="color:#d8eeff">${fileName}</strong> | Date: ${dateStr} | Model: ${modelSrc} | Duration: ${formatETA(elapsed)}</div>
<div class="grid"><div class="stat"><div class="stat-val" style="color:#00c8e8">${total.toLocaleString()}</div><div class="stat-lbl">Total Rows</div></div><div class="stat"><div class="stat-val" style="color:#ff3d5a">${threats.toLocaleString()}</div><div class="stat-lbl">Threats Found</div></div><div class="stat"><div class="stat-val" style="color:#ffaa00">${rate}%</div><div class="stat-lbl">Threat Rate</div></div><div class="stat"><div class="stat-val" style="color:#00e87a">${avgConf}%</div><div class="stat-lbl">Avg Confidence</div></div><div class="stat"><div class="stat-val" style="color:${riskScore<33?'#00e87a':riskScore<66?'#ffaa00':'#ff3d5a'}">${riskScore}/100</div><div class="stat-lbl">Risk Score</div></div></div>
<div class="risk-box"><div class="risk-num">${riskScore}</div><div style="font-size:13px;color:${riskScore<33?'#00e87a':riskScore<66?'#ffaa00':'#ff3d5a'};margin-top:4px">${riskLbl} RISK</div><div style="color:#4a6a88;font-size:10px;margin-top:8px">Weighted: DoS×0.4 · U2R×0.35 · R2L×0.15 · Probe×0.1</div></div>
<h2>Attack Class Distribution</h2><table><thead><tr><th>CLASS</th><th>COUNT</th><th>PERCENTAGE</th><th>SEVERITY</th></tr></thead><tbody>${distRows}</tbody></table>
<h2>Protocol Breakdown</h2><table><thead><tr><th>PROTOCOL</th><th>COUNT</th><th>PERCENTAGE</th></tr></thead><tbody>${protoRows}</tbody></table>
<h2>Severity Summary</h2><table><thead><tr><th>SEVERITY</th><th>COUNT</th><th>PERCENTAGE</th></tr></thead><tbody>${['Critical','High','Medium','None'].map(s=>`<tr><td style="color:${sevColors[s]}">${s}</td><td>${(csvSevCounts[s]||0).toLocaleString()}</td><td>${((csvSevCounts[s]||0)/total*100).toFixed(1)}%</td></tr>`).join('')}</tbody></table>
<h2>Detected Threats — Top 100</h2><table><thead><tr><th>ROW</th><th>PROTOCOL</th><th>SERVICE</th><th>SRC BYTES</th><th>CLASS</th><th>CONFIDENCE</th><th>SEVERITY</th></tr></thead><tbody>${threatRows||'<tr><td colspan="7" style="color:#00e87a;text-align:center;padding:20px">No threats detected</td></tr>'}</tbody></table>
<div class="footer">Generated by SentinelNet · ${dateStr} · NSL-KDD Intrusion Detection</div>
</body></html>`;
  const win = window.open('','_blank','width=1100,height=900');
  if (!win) { alert('Pop-up blocked.'); return; }
  win.document.write(html); win.document.close(); setTimeout(()=>win.print(), 900);
}

function downloadFile(filename, content, type) {
  const blob = new Blob([content], {type});
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href = url; a.download = filename; a.click();
  URL.revokeObjectURL(url);
}

function resetCsvTab() {
  csvRunning = false; csvRows=[]; csvResults=[]; csvIndex=0; csvConfSum=0;
  csvIntrusionCount=0; csvConfHistory=[]; batchNum=0; reportPage=0;
  Object.keys(csvCounts).forEach(k=>csvCounts[k]=0);
  Object.keys(csvSevCounts).forEach(k=>csvSevCounts[k]=0);
  csvStartTime=null; csvUsingReal=false; csvFormatInfo=''; totalBatches=0;
  document.getElementById('csvUploadSection').style.display='';
  document.getElementById('csvProcessingArea').classList.remove('visible');
  document.getElementById('csvProgressBlock').style.display='none';
  document.getElementById('csvLiveGrid').style.display='none';
  document.getElementById('reportSection').classList.remove('visible');
  document.getElementById('csvFeedBody').innerHTML='';
  document.getElementById('reportTableBody').innerHTML='';
  document.getElementById('csvFileInput').value='';
  document.getElementById('formatBanner').style.display='none';
  document.getElementById('liveDot').className='dot'; setText('liveStatus','IDLE');
  document.getElementById('csvStartBtn').disabled=false;
  document.getElementById('csvStopBtn').disabled=true;
  document.getElementById('batchStatus').innerHTML='';
  document.getElementById('csvProgressFill').style.width='0%';
  document.getElementById('csvProgressFill').classList.remove('warning');
}

// ════════════════════════════════════════════════
// LIVE MONITOR
// ════════════════════════════════════════════════
function generatePacket() {
  const label=LABEL_POOL[Math.floor(Math.random()*LABEL_POOL.length)];
  const isAtk=label!=='normal';
  const protocol=PROTOCOLS[Math.floor(Math.random()*3)];
  const service=SERVICES[Math.floor(Math.random()*SERVICES.length)];
  const flag=isAtk&&Math.random()>0.5?['S0','REJ','RSTO'][Math.floor(Math.random()*3)]:'SF';
  const srcBytes=isAtk?Math.floor(Math.random()*200000):Math.floor(Math.random()*4000);
  return {
    duration:Math.floor(Math.random()*3600),protocol_type:protocol,service,flag,
    src_bytes:srcBytes,dst_bytes:Math.floor(Math.random()*8000),land:0,
    wrong_fragment:Math.floor(Math.random()*2),urgent:0,hot:Math.floor(Math.random()*8),
    num_failed_logins:isAtk?Math.floor(Math.random()*3):0,logged_in:Math.random()>0.4?1:0,
    num_compromised:isAtk?Math.floor(Math.random()*5):0,root_shell:0,su_attempted:0,
    num_root:0,num_file_creations:0,num_shells:0,num_access_files:0,num_outbound_cmds:0,
    is_host_login:0,is_guest_login:Math.random()>0.95?1:0,
    count:Math.floor(Math.random()*511),srv_count:Math.floor(Math.random()*511),
    serror_rate:+(Math.random()).toFixed(2),srv_serror_rate:+(Math.random()).toFixed(2),
    rerror_rate:+(Math.random()).toFixed(2),srv_rerror_rate:+(Math.random()).toFixed(2),
    same_srv_rate:+(Math.random()).toFixed(2),diff_srv_rate:+(Math.random()).toFixed(2),
    srv_diff_host_rate:+(Math.random()).toFixed(2),
    dst_host_count:Math.floor(Math.random()*255),dst_host_srv_count:Math.floor(Math.random()*255),
    dst_host_same_srv_rate:+(Math.random()).toFixed(2),dst_host_diff_srv_rate:+(Math.random()).toFixed(2),
    dst_host_same_src_port_rate:+(Math.random()).toFixed(2),dst_host_srv_diff_host_rate:+(Math.random()).toFixed(2),
    dst_host_serror_rate:+(Math.random()).toFixed(2),dst_host_srv_serror_rate:+(Math.random()).toFixed(2),
    dst_host_rerror_rate:+(Math.random()).toFixed(2),dst_host_srv_rerror_rate:+(Math.random()).toFixed(2),
    label,difficulty_level:Math.floor(Math.random()*21)
  };
}

async function tick() {
  const packet = generatePacket();
  let result;
  const api = await predictSingle(packet);
  if (api) {
    result = api;
    if (!usingRealModel) { usingRealModel=true; document.getElementById('connBadge').textContent='✓ REAL MODEL'; document.getElementById('connBadge').className='real'; document.getElementById('sum-model').textContent='REAL RF'; termLog('info','Connected to model at '+BACKEND_URL); }
  } else {
    result = classifyLocal(packet);
    if (usingRealModel) { usingRealModel=false; document.getElementById('connBadge').textContent='⚠ LOCAL SIM'; document.getElementById('connBadge').className='local'; document.getElementById('sum-model').textContent='LOCAL'; }
  }
  packetId++; totalPackets++;
  const cls=result.predicted_class, conf=result.confidence, sev=result.severity, isI=result.is_intrusion;
  counts[cls]=(counts[cls]||0)+1;
  if (isI) { totalIntrusions++; if (!peakClass||counts[cls]>(counts[peakClass]||0)) peakClass=cls; }
  confSum+=conf;
  const cp=conf*100;
  if (cp>=90) confBuckets[90]++; else if (cp>=80) confBuckets[80]++; else if (cp>=70) confBuckets[70]++; else confBuckets.low++;
  timelineBuckets[sessionSeconds%60]+=(isI?1:0);
  heatmapCells.shift(); heatmapCells.push(cls);
  addFeedRow(packet, cls, sev, conf);
  if (cls==='U2R') termLog('crit',`U2R ALERT — Privilege escalation! Conf: ${(conf*100).toFixed(1)}%`);
  else if (cls==='DoS'&&Math.random()<0.15) termLog('warn',`DoS — ${packet.service} flood`);
  else if (cls==='normal'&&totalPackets%50===0) termLog('ok',`${totalPackets} packets. Rate: ${(totalIntrusions/totalPackets*100).toFixed(1)}%`);
  updateMetrics(); updateBars(); updateConfBars();
  tlDirty=true;
  updateHeatmap(); updateSummary(); flashMetric(cls);
}

// Throttled timeline redraw
setInterval(() => { if (tlDirty) { updateTimeline(); tlDirty=false; } }, 500);

function addFeedRow(packet, cls, sev, conf) {
  const tbody=document.getElementById('feedBody');
  const now=new Date(), ts=`${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}`;
  const tr=document.createElement('tr'); tr.className='new-row';
  tr.innerHTML=`<td style="color:var(--muted)">${packetId}</td><td style="color:var(--muted)">${ts}</td><td style="color:var(--cyan)">${packet.protocol_type}</td><td>${packet.src_bytes.toLocaleString()}</td><td><span class="cls-badge cls-${cls}">${cls}</span></td><td style="color:${conf>0.9?'var(--accent)':conf>0.8?'var(--cyan)':'var(--amber)'}">${(conf*100).toFixed(1)}%</td><td style="color:${SEV_COLOR[sev]}">● ${sev}</td>`;
  tbody.insertBefore(tr,tbody.firstChild);
  while (tbody.children.length>100) tbody.removeChild(tbody.lastChild);
  document.getElementById('emptyState').style.display='none';
  document.getElementById('feedTable').style.display='';
  document.getElementById('alertCount').textContent=totalIntrusions+' ALERTS';
}

function updateMetrics() {
  const pct=n=>totalPackets>0?(n/totalPackets*100).toFixed(1)+'%':'—';
  setText('m-total',totalPackets.toLocaleString()); setText('m-normal',counts.normal||0); setText('m-normal-pct',pct(counts.normal||0));
  setText('m-intrusions',totalIntrusions); setText('m-intrusions-pct',pct(totalIntrusions));
  setText('m-dos',counts.DoS||0); setText('m-probe',counts.Probe||0); setText('m-u2r',counts.U2R||0);
  setText('m-rate',(totalPackets/Math.max(sessionSeconds,1)).toFixed(1)+' /sec');
  setWidth('mb-total',Math.min(totalPackets/500*100,100)); setWidth('mb-normal',pctW(counts.normal));
  setWidth('mb-intrusions',pctW(totalIntrusions)); setWidth('mb-dos',pctW(counts.DoS)); setWidth('mb-probe',pctW(counts.Probe)); setWidth('mb-u2r',pctW(counts.U2R));
}
function pctW(n) { return totalPackets>0?(n/totalPackets*100):0; }
function updateBars() {
  const cls=['normal','DoS','Probe','R2L','U2R'], mx=Math.max(...cls.map(c=>counts[c]||0),1);
  cls.forEach(c=>{setWidth('bar-'+c,(counts[c]||0)/mx*100); setText('bc-'+c,counts[c]||0);});
  setText('distTotal',totalPackets+' total');
}
function updateConfBars() {
  const mx=Math.max(...Object.values(confBuckets),1);
  setWidth('conf-90',confBuckets[90]/mx*100); setWidth('conf-80',confBuckets[80]/mx*100);
  setWidth('conf-70',confBuckets[70]/mx*100); setWidth('conf-low',confBuckets.low/mx*100);
  setText('cbc-90',confBuckets[90]); setText('cbc-80',confBuckets[80]); setText('cbc-70',confBuckets[70]); setText('cbc-low',confBuckets.low);
  setText('avgConf','avg: '+(totalPackets>0?(confSum/totalPackets*100).toFixed(1)+'%':'—'));
}
function updateTimeline() {
  const canvas=document.getElementById('tlCanvas'); if (!canvas) return;
  const ctx=canvas.getContext('2d'), W=canvas.offsetWidth, H=80;
  if (!W) return;
  canvas.width=W*devicePixelRatio; canvas.height=H*devicePixelRatio;
  ctx.scale(devicePixelRatio,devicePixelRatio); ctx.clearRect(0,0,W,H);
  const data=timelineBuckets, mx=Math.max(...data,1), step=W/data.length;
  ctx.strokeStyle='rgba(0,200,120,.06)'; ctx.lineWidth=1;
  [.25,.5,.75,1].forEach(f=>{ctx.beginPath();ctx.moveTo(0,H*f);ctx.lineTo(W,H*f);ctx.stroke();});
  ctx.beginPath(); ctx.moveTo(0,H);
  data.forEach((v,i)=>{const x=i*step,y=H-(v/mx*(H-10));ctx.lineTo(x,y);});
  ctx.lineTo(W,H); ctx.closePath(); ctx.fillStyle='rgba(255,61,90,.12)'; ctx.fill();
  ctx.beginPath(); ctx.strokeStyle='#ff3d5a'; ctx.lineWidth=1.5;
  data.forEach((v,i)=>{const x=i*step,y=H-(v/mx*(H-10));i===0?ctx.moveTo(x,y):ctx.lineTo(x,y);});
  ctx.stroke();
}
const HM = { normal:'rgba(0,232,122,0.4)',DoS:'rgba(255,61,90,0.65)',Probe:'rgba(0,200,232,0.5)',R2L:'rgba(255,170,0,0.55)',U2R:'rgba(176,111,255,0.75)',null:'rgba(255,255,255,0.04)' };
function updateHeatmap() {
  const grid=document.getElementById('heatmap');
  if (!grid.children.length) {
    const f=document.createDocumentFragment();
    for (let i=0;i<60;i++){const d=document.createElement('div');d.className='hm-cell';f.appendChild(d);}
    grid.appendChild(f);
  }
  heatmapCells.forEach((cls,i)=>{grid.children[i].style.background=HM[cls]||HM[null];});
}
function updateSummary() {
  setText('sum-rate',totalPackets>0?(totalIntrusions/totalPackets*100).toFixed(1)+'%':'—');
  setText('sum-conf',totalPackets>0?(confSum/totalPackets*100).toFixed(1)+'%':'—');
  setText('sum-peak',peakClass||'—');
}
function termLog(type, msg) {
  const wrap=document.getElementById('termWrap'), now=new Date();
  const ts=`${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}`;
  const div=document.createElement('div'); div.className='term-line';
  div.innerHTML=`<span class="ts">[${ts}]</span> <span class="${type}">${msg}</span>`;
  wrap.appendChild(div); wrap.scrollTop=wrap.scrollHeight;
  while (wrap.children.length>50) wrap.removeChild(wrap.firstChild);
}
const CLS_TO_MC={DoS:'mc-intrusions',Probe:'mc-probe',R2L:'mc-intrusions',U2R:'mc-u2r',normal:'mc-normal'};
function flashMetric(cls){const el=document.getElementById(CLS_TO_MC[cls]||'mc-total');if(!el)return;el.classList.remove('flash');void el.offsetWidth;el.classList.add('flash');}

function startMonitor() {
  if (isRunning) return; isRunning=true;
  const speed=parseInt(document.getElementById('speedSel').value);
  document.getElementById('startBtn').disabled=true; document.getElementById('stopBtn').disabled=false;
  setText('liveStatus','LIVE'); document.getElementById('liveDot').className='dot';
  document.getElementById('connBadge').textContent='⟳ CONNECTING'; document.getElementById('connBadge').className='idle';
  termLog('info','Monitor started');
  monitorInterval=setInterval(tick, speed);
  sessionInterval=setInterval(()=>{
    sessionSeconds++;
    const m=Math.floor(sessionSeconds/60), s=sessionSeconds%60;
    setText('sessionClock',`Session: ${pad(m)}:${pad(s)}`);
    timelineBuckets[sessionSeconds%60]=0;
  },1000);
}

function stopMonitor() {
  if (!isRunning) return; isRunning=false;
  clearInterval(monitorInterval); clearInterval(sessionInterval);
  document.getElementById('startBtn').disabled=false; document.getElementById('stopBtn').disabled=true;
  setText('liveStatus','PAUSED'); document.getElementById('liveDot').className='dot red';
  document.getElementById('connBadge').textContent='■ STOPPED'; document.getElementById('connBadge').className='idle';
  termLog('warn',`Stopped. ${totalPackets} packets analyzed.`);
}

function clearAll() {
  stopMonitor(); Object.keys(counts).forEach(k=>counts[k]=0);
  totalPackets=0; totalIntrusions=0; confSum=0; packetId=0;
  confBuckets={90:0,80:0,70:0,low:0};
  timelineBuckets=Array(60).fill(0); heatmapCells=Array(60).fill(null);
  peakClass=null; sessionSeconds=0; usingRealModel=false;
  setText('sessionClock','Session: 00:00'); setText('liveStatus','IDLE');
  document.getElementById('liveDot').className='dot';
  document.getElementById('feedBody').innerHTML='';
  document.getElementById('feedTable').style.display='none';
  document.getElementById('emptyState').style.display='';
  document.getElementById('alertCount').textContent='0 ALERTS';
  document.getElementById('connBadge').className='idle';
  document.getElementById('connBadge').textContent='— IDLE';
  document.getElementById('termWrap').innerHTML=`<div class="term-line"><span class="ts">[--:--:--]</span> <span class="info">Reset.</span></div>`;
  updateMetrics(); updateBars(); updateConfBars(); updateHeatmap();
  ['sum-rate','sum-conf','sum-peak'].forEach(id=>setText(id,'—'));
  setText('sum-model','LOCAL');
}

// ════════════════════════════════════════════════
// UTILS
// ════════════════════════════════════════════════
function setText(id, v) { const el=document.getElementById(id); if(el) el.textContent=v; }
function setWidth(id, pct){ const el=document.getElementById(id); if(el) el.style.width=pct+'%'; }
function pad(n) { return String(n).padStart(2,'0'); }
function formatETA(secs) { if(secs<60) return secs.toFixed(0)+'s'; return `${Math.floor(secs/60)}m ${pad(Math.floor(secs%60))}s`; }

// Init
window.addEventListener('load', () => { updateHeatmap(); updateTimeline(); });
