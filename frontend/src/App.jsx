import React, { useState, useEffect } from 'react';
import {
  Shield, Activity, AlertTriangle, Database,
  Play, Square, RefreshCw, Clock, CheckCircle2,
  Cpu, BarChart3, Wifi, Zap, Lock, TrendingUp
} from 'lucide-react';
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid,
  Tooltip, ResponsiveContainer, ReferenceLine
} from 'recharts';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

/* ── Custom Tooltip ─────────────────────── */
const ChartTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  return (
    <div style={{
      background: '#0a1520', border: '1px solid rgba(0,212,255,0.25)',
      borderRadius: 8, padding: '12px 16px', fontFamily: 'Share Tech Mono, monospace',
      fontSize: 12, minWidth: 160,
    }}>
      <p style={{ color: '#3d5a72', letterSpacing: 1, marginBottom: 8 }}>⏱ {label}</p>
      {payload.map((p, i) => (
        <p key={i} style={{ color: p.stroke, letterSpacing: 1, lineHeight: 1.8 }}>
          {p.name.toUpperCase()}: {p.value.toFixed(1)}%
        </p>
      ))}
    </div>
  );
};

/* ── Status Orb ─────────────────────────── */
const StatusOrb = ({ active }) => (
  <div className={`status-orb ${active ? 'active' : 'idle'}`}>
    <div className="status-orb-core" />
    <div className="status-orb-glow" />
  </div>
);

/* ── Pulse Ring ─────────────────────────── */
const PulseRing = () => (
  <div className="pulse-ring">
    <div className="core" />
    <div className="ring" />
  </div>
);

/* ════════════════════════════════════════
   MAIN APP
   ════════════════════════════════════════ */
export default function App() {
  const [stats, setStats] = useState({
    live: { packets_processed: 0, intrusions_detected: 0, last_confidence: 0 },
    is_running: false,
    system_status: 'Standby',
    model_ready: false,
  });
  const [logs, setLogs]         = useState([]);
  const [activeTab, setActiveTab] = useState('dashboard');
  const [isTraining, setIsTraining] = useState(false);
  const [connected, setConnected]   = useState(false);

  /* Poll API every 2 s */
  useEffect(() => {
    const fetchData = async () => {
      try {
        const [sRes, lRes] = await Promise.all([
          fetch(`${API_URL}/stats`),
          fetch(`${API_URL}/logs`),
        ]);
        setStats(await sRes.json());
        setLogs(await lRes.json());
        setConnected(true);
      } catch {
        setConnected(false);
      }
    };
    fetchData();
    const id = setInterval(fetchData, 2000);
    return () => clearInterval(id);
  }, []);

  const toggleSimulation = async () => {
    const ep = stats.is_running ? 'stop' : 'start';
    await fetch(`${API_URL}/simulation/${ep}`, { method: 'POST' });
  };

  const handleTrain = async () => {
    setIsTraining(true);
    await fetch(`${API_URL}/train`, { method: 'POST' });
    setTimeout(() => setIsTraining(false), 5000);
  };

  /* Build chart data from logs */
  const chartData = [...logs].reverse().slice(0, 30).map(l => ({
    name:       l.timestamp,
    confidence: +(l.confidence * 100).toFixed(1),
    threat:     l.is_alert ? +(l.confidence * 100).toFixed(1) : 0,
  }));

  const threatRate = logs.length
    ? ((logs.filter(l => l.is_alert).length / logs.length) * 100).toFixed(1)
    : '0.0';

  return (
    <>
      {/* ── Top Navigation ─────────────────── */}
      <header className="topbar">
        <div className="topbar-brand">
          <div className="topbar-logo">
            <Shield size={18} />
          </div>
          <span className="topbar-name">SentinelNet</span>
        </div>

        <div className="topbar-divider" />

        <nav className="topbar-nav">
          {[
            { id: 'dashboard', icon: <BarChart3 size={15} />, label: 'Overview'    },
            { id: 'live',      icon: <Activity   size={15} />, label: 'Live Traffic' },
            { id: 'alerts',    icon: <AlertTriangle size={15} />, label: 'Incidents' },
          ].map(t => (
            <button
              key={t.id}
              className={`nav-btn ${activeTab === t.id ? 'active' : ''}`}
              onClick={() => setActiveTab(t.id)}
            >
              {t.icon} {t.label}
            </button>
          ))}
        </nav>

        <div className="topbar-right">
          <button className="btn btn-ghost" onClick={handleTrain} disabled={isTraining}>
            <RefreshCw size={14} className={isTraining ? 'spin' : ''} />
            Re-Train
          </button>
          <button
            className={`btn ${stats.is_running ? 'btn-stop' : 'btn-start'}`}
            onClick={toggleSimulation}
          >
            {stats.is_running
              ? <><Square size={13} fill="currentColor" /> Halt</>
              : <><Play  size={13} fill="currentColor" /> Activate</>}
          </button>
        </div>
      </header>

      {/* ── Workspace ──────────────────────── */}
      <div className="workspace">

        {/* ═══ DASHBOARD ═══════════════════ */}
        {activeTab === 'dashboard' && (
          <>
            {/* KPI Cards */}
            <div className="kpi-row">
              <KPICard
                accent="teal"
                icon={<Database size={17} />}
                label="Packets Analyzed"
                value={stats.live.packets_processed.toLocaleString()}
                sub="Live stream volume"
                dotClass="dot-teal"
              />
              <KPICard
                accent="orange"
                icon={<AlertTriangle size={17} />}
                label="Threats Detected"
                value={stats.live.intrusions_detected}
                sub="Quarantined this session"
                dotClass="dot-orange"
              />
              <KPICard
                accent="green"
                icon={<Shield size={17} />}
                label="Threat Rate"
                value={`${threatRate}%`}
                sub="Attack / total ratio"
                dotClass="dot-green"
              />
              <KPICard
                accent="yellow"
                icon={<Zap size={17} />}
                label="AI Confidence"
                value={`${(stats.live.last_confidence * 100).toFixed(1)}%`}
                sub="Last inference score"
                dotClass="dot-yellow"
              />
            </div>

            {/* Chart + Feed */}
            <div className="bottom-grid">
              {/* Area Chart Panel */}
              <div className="panel">
                <div className="panel-header">
                  <div>
                    <div className="panel-title">Threat Probability Matrix</div>
                    <div className="panel-subtitle">Real-time AI inference confidence vs anomaly score</div>
                  </div>
                  <div className="legend">
                    <div className="legend-item">
                      <div className="legend-line" style={{ background: '#00d4ff', boxShadow: '0 0 6px #00d4ff' }} />
                      AI Confidence
                    </div>
                    <div className="legend-item">
                      <div className="legend-line" style={{ background: '#ff6b35', boxShadow: '0 0 6px #ff6b35' }} />
                      Threat Score
                    </div>
                  </div>
                </div>
                <div className="panel-body">
                  {chartData.length === 0 ? (
                    <div className="empty-state">
                      <Activity size={32} />
                      <p>Awaiting data stream — activate surveillance</p>
                    </div>
                  ) : (
                    <ResponsiveContainer width="100%" height="100%">
                      <AreaChart data={chartData} margin={{ top: 10, right: 10, left: -10, bottom: 0 }}>
                        <defs>
                          <linearGradient id="gTeal" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="0%"   stopColor="#00d4ff" stopOpacity={0.5} />
                            <stop offset="100%" stopColor="#00d4ff" stopOpacity={0}   />
                          </linearGradient>
                          <linearGradient id="gOrange" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="0%"   stopColor="#ff6b35" stopOpacity={0.6} />
                            <stop offset="100%" stopColor="#ff6b35" stopOpacity={0}   />
                          </linearGradient>
                        </defs>
                        <CartesianGrid
                          strokeDasharray="1 4"
                          vertical={false}
                          stroke="rgba(0,212,255,0.06)"
                        />
                        <XAxis
                          dataKey="name"
                          stroke="#3d5a72"
                          fontSize={10}
                          axisLine={false}
                          tickLine={false}
                          tickMargin={8}
                          fontFamily="Share Tech Mono"
                          tick={{ letterSpacing: 1 }}
                        />
                        <YAxis
                          stroke="#3d5a72"
                          fontSize={10}
                          axisLine={false}
                          tickLine={false}
                          domain={[0, 100]}
                          tickMargin={8}
                          fontFamily="Share Tech Mono"
                          unit="%"
                        />
                        <Tooltip content={<ChartTooltip />} />
                        <ReferenceLine y={70} stroke="rgba(255,107,53,0.2)" strokeDasharray="4 4" />
                        <Area
                          type="monotone"
                          dataKey="confidence"
                          name="confidence"
                          stroke="#00d4ff"
                          strokeWidth={2}
                          fill="url(#gTeal)"
                          dot={false}
                          activeDot={{ r: 4, fill: '#00d4ff', stroke: '#000', strokeWidth: 2 }}
                        />
                        <Area
                          type="monotone"
                          dataKey="threat"
                          name="threat"
                          stroke="#ff6b35"
                          strokeWidth={2}
                          fill="url(#gOrange)"
                          dot={false}
                          activeDot={{ r: 4, fill: '#ff6b35', stroke: '#000', strokeWidth: 2 }}
                        />
                      </AreaChart>
                    </ResponsiveContainer>
                  )}
                </div>
              </div>

              {/* Packet Feed Panel */}
              <div className="panel">
                <div className="panel-header">
                  <div>
                    <div className="panel-title">Tactical Feed</div>
                    <div className="panel-subtitle">Live interception stream</div>
                  </div>
                  <div className="feed-header">
                    {stats.is_running && <PulseRing />}
                    <span style={{ fontFamily: 'Share Tech Mono', fontSize: 11, color: 'var(--c-teal)', letterSpacing: 2, textTransform: 'uppercase' }}>
                      {stats.is_running ? 'Live' : 'Idle'}
                    </span>
                  </div>
                </div>
                <div className="feed-body">
                  {logs.length === 0 ? (
                    <div className="empty-state">
                      <Clock size={28} />
                      <p>No events captured</p>
                    </div>
                  ) : logs.slice(0, 12).map((log, i) => (
                    <div key={i} className={`feed-item fade-in ${log.is_alert ? 'threat' : 'normal'}`}>
                      <div className="feed-row1">
                        <span className="feed-type">{log.packet_type}</span>
                        <span className="feed-time">{log.timestamp}</span>
                      </div>
                      <div className="feed-row2">
                        <span className={`tag ${log.is_alert ? 'threat' : 'normal'}`}>
                          {log.prediction}
                        </span>
                        <div className="conf-bar-wrap">
                          <div className="conf-bar">
                            <div
                              className={`conf-fill ${log.is_alert ? 'threat' : 'normal'}`}
                              style={{ width: `${log.confidence * 100}%` }}
                            />
                          </div>
                          <span className="conf-pct">{(log.confidence * 100).toFixed(0)}%</span>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </>
        )}

        {/* ═══ LIVE TRAFFIC / INCIDENTS ════ */}
        {(activeTab === 'live' || activeTab === 'alerts') && (
          <div className="panel" style={{ flex: 1, minHeight: 0 }}>
            <div className="panel-header">
              <div>
                <div className="panel-title">
                  {activeTab === 'alerts' ? 'Incident Log' : 'Global Packet Stream'}
                </div>
                <div className="panel-subtitle">
                  {activeTab === 'alerts'
                    ? 'Filtered view — anomalies and threats only'
                    : 'Full real-time interception record'}
                </div>
              </div>
              <div className="feed-header">
                {stats.is_running && <PulseRing />}
                <span style={{ fontFamily: 'Share Tech Mono', fontSize: 11, color: 'var(--c-teal)', letterSpacing: 2 }}>
                  {logs.length} EVENTS
                </span>
              </div>
            </div>
            <div className="table-wrap">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Timestamp</th>
                    <th>Signature</th>
                    <th>Classification</th>
                    <th>AI Confidence</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {(activeTab === 'alerts' ? logs.filter(l => l.is_alert) : logs).map((log, i) => (
                    <tr key={i} className={log.is_alert ? 'row-threat' : ''}>
                      <td className="mono">{log.timestamp}</td>
                      <td className="bold">{log.packet_type}</td>
                      <td>
                        <span className={`badge ${log.is_alert ? 'threat' : 'normal'}`}>
                          <span style={{ width: 5, height: 5, borderRadius: '50%', background: 'currentColor', display: 'inline-block' }} />
                          {log.prediction}
                        </span>
                      </td>
                      <td className="mono">{(log.confidence * 100).toFixed(2)}%</td>
                      <td>
                        {log.is_alert
                          ? <button className="action-link quarantine">⚠ Quarantine</button>
                          : <button className="action-link pass">— Permit</button>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>

      {/* ── Status Bar ─────────────────────── */}
      <footer className="statusbar">
        <div className="statusbar-item">
          <StatusOrb active={connected} />
          {connected ? 'API Connected' : 'API Offline'}
        </div>
        <div className="statusbar-item">
          <div className="statusbar-dot" style={{ background: stats.model_ready ? 'var(--c-green)' : 'var(--c-orange)' }} />
          {stats.model_ready ? 'Model Ready' : 'Model Not Loaded'}
        </div>
        <div className="statusbar-item">
          <StatusOrb active={stats.is_running} />
          {stats.system_status}
        </div>
        <div className="statusbar-item" style={{ marginLeft: 'auto', fontFamily: 'Share Tech Mono', fontSize: 11, color: 'var(--text-dim)' }}>
          SentinelNet v2.0 · NSL-KDD · Random Forest
        </div>
      </footer>
    </>
  );
}

/* ── KPI Card Component ─────────────────── */
function KPICard({ accent, icon, label, value, sub, dotClass }) {
  return (
    <div className={`kpi-card ${accent}`}>
      <div className="kpi-top">
        <span className="kpi-label">{label}</span>
        <div className={`kpi-icon ${accent}`}>{icon}</div>
      </div>
      <div className="kpi-value">{value}</div>
      <div className="kpi-sub">
        <div className={`dot ${dotClass}`} />
        {sub}
      </div>
    </div>
  );
}