import React, { useState, useEffect } from 'react';
import { 
  Shield, Activity, AlertTriangle, Database, 
  Play, Square, RefreshCw, Clock, 
  CheckCircle2, Cpu, BarChart3, Hexagon 
} from 'lucide-react';
import { 
  LineChart, Line, XAxis, YAxis, CartesianGrid, 
  Tooltip, ResponsiveContainer, AreaChart, Area 
} from 'recharts';

const API_URL = 'http://localhost:8000';

function App() {
  const [stats, setStats] = useState({ 
    live: { packets_processed: 0, intrusions_detected: 0, last_confidence: 0 },
    is_running: false,
    system_status: 'Initializing...'
  });
  const [logs, setLogs] = useState([]);
  const [activeTab, setActiveTab] = useState('dashboard');
  const [isTraining, setIsTraining] = useState(false);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const statsRes = await fetch(`${API_URL}/stats`);
        const statsData = await statsRes.json();
        setStats(statsData);

        const logsRes = await fetch(`${API_URL}/logs`);
        const logsData = await logsRes.json();
        setLogs(logsData);
      } catch (err) {
        console.error("API Error", err);
      }
    };

    fetchData();
    const interval = setInterval(fetchData, 2000);
    return () => clearInterval(interval);
  }, []);

  const handleToggleSimulation = async () => {
    const endpoint = stats.is_running ? 'stop' : 'start';
    await fetch(`${API_URL}/simulation/${endpoint}`, { method: 'POST' });
  };

  const handleTrain = async () => {
    setIsTraining(true);
    await fetch(`${API_URL}/train`, { method: 'POST' });
    setTimeout(() => setIsTraining(false), 5000);
  };

  const chartData = logs.slice(0, 20).reverse().map(log => ({
    name: log.timestamp,
    confidence: log.confidence * 100,
    is_alert: log.is_alert ? 100 : 0
  }));

  return (
    <div className="app-wrapper">
      {/* Sidebar */}
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-icon">
            <Hexagon size={28} />
          </div>
          <h1 className="brand-text">SentinelNet</h1>
        </div>
        
        <nav className="nav-menu">
          <NavItem 
            active={activeTab === 'dashboard'} 
            onClick={() => setActiveTab('dashboard')}
            icon={<BarChart3 size={18}/>} label="Overview" 
          />
          <NavItem 
            active={activeTab === 'live'} 
            onClick={() => setActiveTab('live')}
            icon={<Activity size={18}/>} label="Live Traffic" 
          />
          <NavItem 
            active={activeTab === 'training'} 
            onClick={() => setActiveTab('training')}
            icon={<Cpu size={18}/>} label="AI Models" 
          />
          <NavItem 
            active={activeTab === 'alerts'} 
            onClick={() => setActiveTab('alerts')}
            icon={<AlertTriangle size={18}/>} label="Incidents" 
          />
        </nav>

        <div className="system-status">
          <div className="status-header">
            <div className={`status-indicator ${stats.is_running ? 'active' : 'inactive'}`}></div>
            <span className="status-label">System State</span>
          </div>
          <p className="status-text">{stats.system_status}</p>
        </div>
      </aside>

      {/* Main Content */}
      <main className="main-content">
        <header className="top-header">
          <div>
            <h2 className="page-title">Network Intelligence</h2>
            <p className="page-subtitle">Real-time AI threat detection and anomaly analytics framework</p>
          </div>
          <div className="header-actions">
            <button 
              onClick={handleToggleSimulation}
              className={`btn ${stats.is_running ? 'btn-danger' : 'btn-primary'}`}
            >
              {stats.is_running ? <Square size={16} fill="currentColor"/> : <Play size={16} fill="currentColor"/>}
              {stats.is_running ? 'Halt Surveillance' : 'Initiate Surveillance'}
            </button>
            <button 
              onClick={handleTrain}
              disabled={isTraining}
              className="btn btn-outline"
            >
              <RefreshCw size={16} className={isTraining ? 'anim-spin' : ''}/>
              Re-Train Matrix
            </button>
          </div>
        </header>

        {activeTab === 'dashboard' && (
          <div className="dashboard-grid">
            {/* Stat Cards */}
            <div className="glass-panel col-4">
              <div className="stat-header">
                <div className="icon-box"><Database size={24} /></div>
                <span className="stat-label">Traffic Volume</span>
              </div>
              <h4 className="stat-value">{stats.live.packets_processed.toLocaleString()}</h4>
              <p className="stat-sub"><CheckCircle2 size={14} className="text-emerald-500"/> Live Stream Packets Analyzed</p>
            </div>
            
            <div className="glass-panel col-4">
              <div className="stat-header">
                <div className="icon-box" style={{color: '#00ff88'}}><Shield size={24} /></div>
                <span className="stat-label">Security Protocol</span>
              </div>
              <h4 className="stat-value">Active</h4>
              <p className="stat-sub"><CheckCircle2 size={14} className="text-emerald-500"/> Neuro-Net v2.1 Online</p>
            </div>
            
            <div className={`glass-panel col-4 ${stats.live.intrusions_detected > 0 ? 'is-urgent' : ''}`}>
              <div className="stat-header">
                <div className="icon-box"><AlertTriangle size={24} /></div>
                <span className="stat-label">Threats Quarantined</span>
              </div>
              <h4 className="stat-value">{stats.live.intrusions_detected}</h4>
              <p className="stat-sub">
                {stats.live.intrusions_detected > 0 
                  ? <AlertTriangle size={14} /> 
                  : <CheckCircle2 size={14} className="text-emerald-500"/>
                } 
                Anomalies blocked this session
              </p>
            </div>

            {/* Chart */}
            <div className="glass-panel col-8" style={{height: '420px', padding: '28px 28px 10px 10px'}}>
              <div className="chart-header" style={{paddingLeft: '18px'}}>
                <div>
                  <h3 className="chart-title">Threat Probability Matrix</h3>
                  <p className="chart-subtitle">Confidence Level vs Anomaly Spike Score</p>
                </div>
                <div className="chart-legend">
                  <div className="legend-item"><div className="dot dot-cyan"></div>AI Confidence</div>
                  <div className="legend-item"><div className="dot dot-red"></div>Intrusion Alert</div>
                </div>
              </div>
              <ResponsiveContainer width="100%" height="80%">
                <AreaChart data={chartData}>
                  <defs>
                    <linearGradient id="glowCyan" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#00f0ff" stopOpacity={0.6}/>
                      <stop offset="100%" stopColor="#00f0ff" stopOpacity={0}/>
                    </linearGradient>
                    <linearGradient id="glowRed" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#ff2a2a" stopOpacity={0.6}/>
                      <stop offset="100%" stopColor="#ff2a2a" stopOpacity={0}/>
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="rgba(255,255,255,0.05)" />
                  <XAxis dataKey="name" stroke="#8a9bb8" fontSize={11} axisLine={false} tickLine={false} tickMargin={10} />
                  <YAxis stroke="#8a9bb8" fontSize={11} axisLine={false} tickLine={false} domain={[0, 100]} tickMargin={10} />
                  <Tooltip 
                    contentStyle={{ backgroundColor: '#0a0f25', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '12px', boxShadow: '0 10px 30px rgba(0,0,0,0.5)' }}
                    itemStyle={{ color: '#f8fafc', fontWeight: 600 }}
                  />
                  <Area type="monotone" dataKey="confidence" stroke="#00f0ff" strokeWidth={3} fill="url(#glowCyan)" />
                  <Area type="monotone" dataKey="is_alert" stroke="#ff2a2a" strokeWidth={2} fill="url(#glowRed)" />
                </AreaChart>
              </ResponsiveContainer>
            </div>

            {/* Logs Sidebar */}
            <div className="glass-panel col-4 logs-panel">
              <div className="logs-header">
                <Clock size={18} style={{color: '#00f0ff'}}/> Tactical Feed
              </div>
              <div className="logs-container">
                {logs.length === 0 ? (
                  <div style={{height:'100%', display:'flex', alignItems:'center', justifyContent:'center', color:'#8a9bb8', fontSize:'13px', fontStyle:'italic'}}>
                    Awaiting data stream...
                  </div>
                ) : logs.slice(0, 6).map((log, i) => (
                  <div key={i} className={`log-item ${log.is_alert ? 'alert' : ''}`}>
                    <div className="log-top">
                      <span className={`log-pred ${log.is_alert ? 'alert' : 'normal'}`}>{log.prediction}</span>
                      <span className="log-time">{log.timestamp}</span>
                    </div>
                    <div className="log-type">{log.packet_type}</div>
                    <div className="conf-wrap">
                      <div className="progress-bar">
                        <div className={`progress-fill ${log.is_alert ? 'alert' : 'normal'}`} style={{width: `${log.confidence * 100}%`}}></div>
                      </div>
                      <span className="conf-val">{(log.confidence * 100).toFixed(0)}%</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {(activeTab === 'live' || activeTab === 'alerts') && (
          <div className="glass-panel table-panel" style={{height: '100%'}}>
            <div className="table-header">
              <div>
                <h3 className="chart-title">Global Data Stream</h3>
                <p className="chart-subtitle">Real-time Packet Interception Protocol</p>
              </div>
              <div className="live-badge">
                <div className="ping"></div>
                <span className="live-text">Live Sync</span>
              </div>
            </div>
            <div className="data-table-wrap">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Timestamp</th>
                    <th>Packet Signature</th>
                    <th>Classification</th>
                    <th>AI Confidence</th>
                    <th>System Action</th>
                  </tr>
                </thead>
                <tbody>
                  {logs.map((log, i) => (
                    <tr key={i} className={log.is_alert ? 'row-alert' : ''}>
                      <td className="font-mono" style={{color: '#8a9bb8'}}>{log.timestamp}</td>
                      <td style={{fontWeight: 600, color: '#f8fafc'}}>{log.packet_type}</td>
                      <td>
                        <span className={`badge ${log.is_alert ? 'alert' : 'normal'}`}>
                          {log.prediction}
                        </span>
                      </td>
                      <td className="font-mono">{(log.confidence * 100).toFixed(2)}%</td>
                      <td>
                        {log.is_alert ? (
                          <span style={{color: '#ff2a2a', fontWeight: 600, fontSize: '13px', cursor: 'pointer'}}>Triggered Quarantine</span>
                        ) : (
                          <span style={{color: '#8a9bb8', fontSize: '13px'}}>Permitted</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}

function NavItem({ icon, label, active, onClick }) {
  return (
    <button className={`nav-item ${active ? 'active' : ''}`} onClick={onClick}>
      {React.cloneElement(icon, { size: 20 })}
      <span>{label}</span>
    </button>
  );
}

export default App;