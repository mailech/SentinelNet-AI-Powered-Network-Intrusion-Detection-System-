const PRESETS = {
  normal: {
    protocol_type: 'tcp',
    service: 'http',
    flag: 'SF',
    duration: 0,
    src_bytes: 491,
    dst_bytes: 0,
    logged_in: 0,
    land: 0,
    count: 2,
    srv_count: 2,
    serror_rate: 0.0,
    dst_host_count: 255,
    dst_host_srv_count: 255,
    same_srv_rate: 1.0,
    wrong_fragment: 0,
    urgent: 0,
    hot: 0,
    num_failed_logins: 0,
    num_compromised: 0,
    root_shell: 0,
    su_attempted: 0,
    num_root: 0,
    num_file_creations: 0,
    num_shells: 0,
    num_access_files: 0,
    num_outbound_cmds: 0,
    is_host_login: 0,
    is_guest_login: 0,
    srv_serror_rate: 0.0,
    rerror_rate: 0.0,
    srv_rerror_rate: 0.0,
    diff_srv_rate: 0.0,
    srv_diff_host_rate: 0.0,
    dst_host_same_srv_rate: 1.0,
    dst_host_diff_srv_rate: 0.0,
    dst_host_same_src_port_rate: 0.1,
    dst_host_srv_diff_host_rate: 0.0,
    dst_host_serror_rate: 0.0,
    dst_host_srv_serror_rate: 0.0,
    dst_host_rerror_rate: 0.0,
    dst_host_srv_rerror_rate: 0.0
  },
  dos: {
    protocol_type: 'tcp',
    service: 'private',
    flag: 'S0',
    duration: 0,
    src_bytes: 0,
    dst_bytes: 0,
    logged_in: 0,
    land: 0,
    count: 511,
    srv_count: 511,
    serror_rate: 1.0,
    dst_host_count: 255,
    dst_host_srv_count: 255,
    same_srv_rate: 1.0,
    wrong_fragment: 0,
    urgent: 0,
    hot: 0,
    num_failed_logins: 0,
    num_compromised: 0,
    root_shell: 0,
    su_attempted: 0,
    num_root: 0,
    num_file_creations: 0,
    num_shells: 0,
    num_access_files: 0,
    num_outbound_cmds: 0,
    is_host_login: 0,
    is_guest_login: 0,
    srv_serror_rate: 1.0,
    rerror_rate: 0.0,
    srv_rerror_rate: 0.0,
    diff_srv_rate: 0.0,
    srv_diff_host_rate: 0.0,
    dst_host_same_srv_rate: 1.0,
    dst_host_diff_srv_rate: 0.0,
    dst_host_same_src_port_rate: 0.0,
    dst_host_srv_diff_host_rate: 0.0,
    dst_host_serror_rate: 1.0,
    dst_host_srv_serror_rate: 1.0,
    dst_host_rerror_rate: 0.0,
    dst_host_srv_rerror_rate: 0.0
  },
  probe: {
    protocol_type: 'icmp',
    service: 'ecr_i',
    flag: 'SF',
    duration: 0,
    src_bytes: 1032,
    dst_bytes: 0,
    logged_in: 0,
    land: 0,
    count: 511,
    srv_count: 511,
    serror_rate: 0.0,
    dst_host_count: 255,
    dst_host_srv_count: 255,
    same_srv_rate: 0.06,
    wrong_fragment: 0,
    urgent: 0,
    hot: 0,
    num_failed_logins: 0,
    num_compromised: 0,
    root_shell: 0,
    su_attempted: 0,
    num_root: 0,
    num_file_creations: 0,
    num_shells: 0,
    num_access_files: 0,
    num_outbound_cmds: 0,
    is_host_login: 0,
    is_guest_login: 0,
    srv_serror_rate: 0.0,
    rerror_rate: 0.0,
    srv_rerror_rate: 0.0,
    diff_srv_rate: 0.0,
    srv_diff_host_rate: 0.0,
    dst_host_same_srv_rate: 1.0,
    dst_host_diff_srv_rate: 0.0,
    dst_host_same_src_port_rate: 0.0,
    dst_host_srv_diff_host_rate: 0.0,
    dst_host_serror_rate: 0.0,
    dst_host_srv_serror_rate: 0.0,
    dst_host_rerror_rate: 0.0,
    dst_host_srv_rerror_rate: 0.0
  },
  r2l: {
    protocol_type: 'tcp',
    service: 'ftp',
    flag: 'SF',
    duration: 1,
    src_bytes: 491,
    dst_bytes: 2020,
    logged_in: 1,
    land: 0,
    count: 1,
    srv_count: 1,
    serror_rate: 0.0,
    dst_host_count: 4,
    dst_host_srv_count: 4,
    same_srv_rate: 1.0,
    wrong_fragment: 0,
    urgent: 0,
    hot: 0,
    num_failed_logins: 0,
    num_compromised: 0,
    root_shell: 0,
    su_attempted: 0,
    num_root: 0,
    num_file_creations: 0,
    num_shells: 0,
    num_access_files: 0,
    num_outbound_cmds: 0,
    is_host_login: 0,
    is_guest_login: 0,
    srv_serror_rate: 0.0,
    rerror_rate: 0.0,
    srv_rerror_rate: 0.0,
    diff_srv_rate: 0.0,
    srv_diff_host_rate: 0.0,
    dst_host_same_srv_rate: 1.0,
    dst_host_diff_srv_rate: 0.0,
    dst_host_same_src_port_rate: 0.0,
    dst_host_srv_diff_host_rate: 0.0,
    dst_host_serror_rate: 0.0,
    dst_host_srv_serror_rate: 0.0,
    dst_host_rerror_rate: 0.0,
    dst_host_srv_rerror_rate: 0.0
  },
  u2r: {
    protocol_type: 'tcp',
    service: 'telnet',
    flag: 'SF',
    duration: 9,
    src_bytes: 1755,
    dst_bytes: 2132,
    logged_in: 1,
    land: 0,
    count: 1,
    srv_count: 1,
    serror_rate: 0.0,
    dst_host_count: 1,
    dst_host_srv_count: 1,
    same_srv_rate: 1.0,
    wrong_fragment: 0,
    urgent: 0,
    hot: 0,
    num_failed_logins: 0,
    num_compromised: 0,
    root_shell: 0,
    su_attempted: 0,
    num_root: 0,
    num_file_creations: 0,
    num_shells: 0,
    num_access_files: 0,
    num_outbound_cmds: 0,
    is_host_login: 0,
    is_guest_login: 0,
    srv_serror_rate: 0.0,
    rerror_rate: 0.0,
    srv_rerror_rate: 0.0,
    diff_srv_rate: 0.0,
    srv_diff_host_rate: 0.0,
    dst_host_same_srv_rate: 1.0,
    dst_host_diff_srv_rate: 0.0,
    dst_host_same_src_port_rate: 0.0,
    dst_host_srv_diff_host_rate: 0.0,
    dst_host_serror_rate: 0.0,
    dst_host_srv_serror_rate: 0.0,
    dst_host_rerror_rate: 0.0,
    dst_host_srv_rerror_rate: 0.0
  }
};

const CLASS_COLORS = {
  Normal: '#00d4f5',
  DoS: '#f5334a',
  Probe: '#f5c842',
  R2L: '#f5834a',
  U2R: '#a855f7'
};

function loadPreset(name) {
  const p = PRESETS[name];
  Object.keys(p).forEach((k) => {
    const el = document.getElementById(k);
    if (el) el.value = p[k];
  });
}

function getFormData() {
  const fields = Object.keys(PRESETS.normal);
  const d = {};
  fields.forEach((f) => {
    const el = document.getElementById(f);
    if (!el) {
      d[f] = 0;
      return;
    }
    d[f] = isNaN(+el.value) ? el.value : +el.value;
  });
  return d;
}

function showState(state) {
  document.getElementById('resultIdle').style.display =
    state === 'idle' ? 'flex' : 'none';
  document.getElementById('resultLoading').style.display =
    state === 'loading' ? 'flex' : 'none';
  document.getElementById('resultOutput').style.display =
    state === 'result' ? 'flex' : 'none';
}

const LOADING_MSGS = [
  'Preparing request…',
  'Contacting backend…',
  'Running Random Forest classifier…',
  'Computing confidence scores…'
];

async function analyze() {
  const btn = document.getElementById('analyzeBtn');
  btn.disabled = true;
  showState('loading');

  let msgIdx = 0;
  const msgEl = document.getElementById('loadingText');
  msgEl.textContent = LOADING_MSGS[0];
  const msgTimer = setInterval(() => {
    msgIdx = (msgIdx + 1) % LOADING_MSGS.length;
    msgEl.textContent = LOADING_MSGS[msgIdx];
  }, 900);

  const data = getFormData();

  try {
    const res = await fetch('/predict', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    });

    if (!res.ok) throw new Error(`API error: ${res.status}`);
    const result = await res.json();

    clearInterval(msgTimer);
    renderResult(result, data);
  } catch (e) {
    clearInterval(msgTimer);
    msgEl.textContent = `❌ Error: ${e.message}. Is the backend running?`;
    showState('loading');
    setTimeout(() => {
      btn.disabled = false;
    }, 2000);
    return;
  }

  btn.disabled = false;
}

function renderResult(result, data) {
  const cls = result.prediction.class;
  const probabilities = result.prediction.probabilities;
  const color = CLASS_COLORS[cls] || '#fff';
  const topConf = (result.prediction.confidence * 100).toFixed(1);

  // Verdict
  const box = document.getElementById('verdictBox');
  box.style.borderColor = color + '60';
  box.style.background = color + '10';
  document.getElementById('verdictClass').textContent = cls;
  document.getElementById('verdictClass').style.color = color;
  document.getElementById('verdictConf').textContent = `Confidence: ${topConf}%`;
  document.getElementById('verdictConf').style.color = color;

  // Confidence bars
  const bars = Object.entries(probabilities).sort((a, b) => b[1] - a[1]);
  document.getElementById('confBars').innerHTML = bars
    .map(
      ([c, v]) => `
    <div class="conf-row">
      <span class="conf-label" style="color:${CLASS_COLORS[c]}">${c}</span>
      <div class="conf-bar-bg"><div class="conf-bar-fill" style="width:${(v * 100).toFixed(1)}%;background:${CLASS_COLORS[c]}"></div></div>
      <span class="conf-pct" style="color:${c === cls ? '#fff' : 'var(--muted)'}">${(v * 100).toFixed(1)}%</span>
    </div>
  `
    )
    .join('');

  // Explanation
  document.getElementById('explanationText').textContent = result.verdict;

  // Terminal log
  const ts = new Date().toISOString();
  document.getElementById('terminalLog').innerHTML = `
<span class="t-muted">[${ts}]</span> <span class="t-cyan">backend</span> &gt; analyzing connection...<br/>
<span class="t-muted">&gt;</span> protocol=<span class="t-cyan">${data.protocol_type}</span> service=<span class="t-cyan">${data.service}</span> flag=<span class="t-cyan">${data.flag}</span><br/>
<span class="t-muted">&gt;</span> src_bytes=<span class="t-cyan">${data.src_bytes}</span> dst_bytes=<span class="t-cyan">${data.dst_bytes}</span> total=<span class="t-cyan">${data.src_bytes + data.dst_bytes}</span><br/>
<span class="t-muted">&gt;</span> count=<span class="t-cyan">${data.count}</span> serror_rate=<span class="t-cyan">${data.serror_rate}</span> logged_in=<span class="t-cyan">${data.logged_in}</span><br/>
<span class="t-muted">&gt;</span> running Random Forest classifier (n=300)...<br/>
<span class="t-muted">&gt;</span> prediction: <span style="color:${color};font-weight:bold">${cls}</span> [conf: ${topConf}%]<br/>
<span class="${cls === 'Normal' ? 't-green' : 't-red'}">&gt; VERDICT: ${cls === 'Normal' ? 'CLEAN TRAFFIC ✓' : 'ATTACK DETECTED ⚠'}</span>
  `;

  showState('result');
}
