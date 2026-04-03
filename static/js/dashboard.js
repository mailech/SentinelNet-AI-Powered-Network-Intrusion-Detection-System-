const { useState, useEffect, useRef } = React;

const CYAN = '#00d4f5';
const GREEN = '#00f5a0';
const RED = '#f5334a';
const YELLOW = '#f5c842';
const ORANGE = '#f5834a';
const PURPLE = '#a855f7';

Chart.defaults.color = '#3d6880';
Chart.defaults.font.family = "'Share Tech Mono', monospace";
Chart.defaults.font.size = 11;

function ChartCard({ id, title, sub, col, children }) {
  const [vis, setVis] = useState(false);
  const ref = useRef();
  
  useEffect(() => {
    const obs = new IntersectionObserver(([e]) => {
      if (e.isIntersecting) {
        setVis(true);
        obs.disconnect();
      }
    }, { threshold: 0.1 });
    
    if (ref.current) obs.observe(ref.current);
    return () => obs.disconnect();
  }, []);
  
  return (
    <div
      ref={ref}
      className={`card ${col}`}
      style={{
        opacity: vis ? 1 : 0,
        transform: vis ? 'none' : 'translateY(20px)',
        transition: 'opacity .6s,transform .6s'
      }}
    >
      <div className="card-title">
        {title}
        <span className="sub">{sub}</span>
      </div>
      {children}
    </div>
  );
}

function DonutChart() {
  const ref = useRef();
  const chart = useRef();
  
  useEffect(() => {
    if (chart.current) chart.current.destroy();
    chart.current = new Chart(ref.current, {
      type: 'doughnut',
      data: {
        labels: ['Normal', 'DoS', 'Probe', 'R2L', 'U2R'],
        datasets: [
          {
            data: [67343, 45927, 11656, 995, 52],
            backgroundColor: [CYAN, RED, YELLOW, ORANGE, PURPLE],
            borderColor: '#080f1a',
            borderWidth: 4,
            hoverOffset: 10
          }
        ]
      },
      options: {
        animation: { animateRotate: true, duration: 1200 },
        plugins: {
          legend: {
            position: 'bottom',
            labels: {
              padding: 16,
              usePointStyle: true,
              pointStyleWidth: 8
            }
          }
        },
        cutout: '62%'
      }
    });
    return () => chart.current?.destroy();
  }, []);
  
  return <canvas ref={ref} height={240} />;
}

function ProtocolChart() {
  const ref = useRef();
  const chart = useRef();
  
  useEffect(() => {
    if (chart.current) chart.current.destroy();
    chart.current = new Chart(ref.current, {
      type: 'bar',
      data: {
        labels: ['TCP', 'UDP', 'ICMP'],
        datasets: [
          {
            label: 'Normal',
            data: [55620, 7903, 3820],
            backgroundColor: CYAN + '88',
            borderColor: CYAN,
            borderWidth: 1,
            borderRadius: 3
          },
          {
            label: 'Attack',
            data: [47069, 7090, 4471],
            backgroundColor: RED + '88',
            borderColor: RED,
            borderWidth: 1,
            borderRadius: 3
          }
        ]
      },
      options: {
        animation: { duration: 1000, easing: 'easeOutQuart' },
        plugins: { legend: { position: 'top' } },
        scales: {
          x: { grid: { color: '#0d2e4a55' } },
          y: {
            grid: { color: '#0d2e4a55' },
            ticks: { callback: (v) => (v >= 1000 ? v / 1000 + 'K' : v) }
          }
        }
      }
    });
    return () => chart.current?.destroy();
  }, []);
  
  return <canvas ref={ref} height={240} />;
}

function RadarChart() {
  const ref = useRef();
  const chart = useRef();
  
  useEffect(() => {
    if (chart.current) chart.current.destroy();
    chart.current = new Chart(ref.current, {
      type: 'radar',
      data: {
        labels: ['Duration', 'Src Bytes', 'Dst Bytes', 'Logged In', 'Srv Count', 'Error Rate'],
        datasets: [
          {
            label: 'DoS',
            data: [0.05, 0.72, 0.28, 0.12, 0.91, 0.15],
            borderColor: RED,
            backgroundColor: RED + '22',
            pointBackgroundColor: RED
          },
          {
            label: 'Probe',
            data: [0.22, 0.44, 0.35, 0.08, 0.65, 0.42],
            borderColor: YELLOW,
            backgroundColor: YELLOW + '22',
            pointBackgroundColor: YELLOW
          },
          {
            label: 'R2L',
            data: [0.55, 0.31, 0.68, 0.78, 0.18, 0.33],
            borderColor: ORANGE,
            backgroundColor: ORANGE + '22',
            pointBackgroundColor: ORANGE
          },
          {
            label: 'Normal',
            data: [0.38, 0.52, 0.71, 0.85, 0.42, 0.06],
            borderColor: CYAN,
            backgroundColor: CYAN + '22',
            pointBackgroundColor: CYAN
          }
        ]
      },
      options: {
        animation: { duration: 1200 },
        scales: {
          r: {
            grid: { color: '#0d2e4a' },
            angleLines: { color: '#0d2e4a' },
            pointLabels: { color: '#3d6880', font: { size: 10 } },
            ticks: { display: false },
            min: 0,
            max: 1
          }
        },
        plugins: {
          legend: {
            position: 'bottom',
            labels: { padding: 12, usePointStyle: true }
          }
        }
      }
    });
    return () => chart.current?.destroy();
  }, []);
  
  return <canvas ref={ref} height={240} />;
}

function ROCChart() {
  const ref = useRef();
  const chart = useRef();
  
  useEffect(() => {
    if (chart.current) chart.current.destroy();
    
    const makeROC = (auc) => {
      const pts = [[0, 0]];
      for (let i = 1; i <= 100; i++) {
        const x = i / 100;
        const y = Math.min(1, auc * (1 - Math.pow(1 - x, 1 / (1.5 * (1 - auc) + 0.5))));
        pts.push([x, y]);
      }
      pts.push([1, 1]);
      return pts;
    };
    
    chart.current = new Chart(ref.current, {
      type: 'line',
      data: {
        datasets: [
          {
            label: 'Guess',
            data: [
              { x: 0, y: 0 },
              { x: 1, y: 1 }
            ],
            borderColor: '#3d6880',
            borderDash: [4, 4],
            pointRadius: 0,
            borderWidth: 1
          },
          ...['Normal (1.000)', 'DoS (1.000)', 'Probe (.999)', 'R2L (.998)', 'U2R (.997)'].map(
            ([label, auc, color], idx) => ({
              label: label,
              data: makeROC([1.0, 1.0, 0.999, 0.998, 0.997][idx]).map(([x, y]) => ({ x, y })),
              borderColor: [CYAN, RED, YELLOW, ORANGE, PURPLE][idx],
              backgroundColor: 'transparent',
              pointRadius: 0,
              borderWidth: 2,
              tension: 0.4
            })
          )
        ]
      },
      options: {
        animation: { duration: 1500, easing: 'easeOutQuart' },
        scales: {
          x: {
            type: 'linear',
            min: 0,
            max: 1,
            title: { display: true, text: 'False Positive Rate', color: '#3d6880' },
            grid: { color: '#0d2e4a55' }
          },
          y: {
            min: 0,
            max: 1,
            title: { display: true, text: 'True Positive Rate', color: '#3d6880' },
            grid: { color: '#0d2e4a55' }
          }
        },
        plugins: {
          legend: {
            position: 'bottom',
            labels: { padding: 10, usePointStyle: true }
          }
        }
      }
    });
    return () => chart.current?.destroy();
  }, []);
  
  return <canvas ref={ref} height={220} />;
}

function AttackBar() {
  const ref = useRef();
  const chart = useRef();
  
  useEffect(() => {
    if (chart.current) chart.current.destroy();
    
    const labels = ['normal', 'neptune', 'satan', 'ipsweep', 'portsweep', 'smurf', 'nmap', 'back', 'warezclient', 'teardrop', 'pod', 'guess_passwd', 'buffer_overflow', 'land', 'warezmaster'];
    const data = [67343, 41214, 3633, 3599, 2931, 2646, 1493, 956, 892, 892, 264, 53, 30, 25, 20];
    const colors = [CYAN, RED, RED, RED, YELLOW, RED, YELLOW, RED, ORANGE, RED, RED, ORANGE, PURPLE, RED, ORANGE];
    
    chart.current = new Chart(ref.current, {
      type: 'bar',
      data: {
        labels,
        datasets: [
          {
            data,
            backgroundColor: colors.map((c) => c + 'bb'),
            borderColor: colors,
            borderWidth: 1,
            borderRadius: 3
          }
        ]
      },
      options: {
        animation: { duration: 1200, delay: (ctx) => ctx.dataIndex * 40 },
        plugins: { legend: { display: false } },
        scales: {
          x: {
            grid: { color: '#0d2e4a55' },
            ticks: { maxRotation: 35, font: { size: 10 } }
          },
          y: {
            grid: { color: '#0d2e4a55' },
            ticks: { callback: (v) => (v >= 1000 ? v / 1000 + 'K' : v) }
          }
        }
      }
    });
    return () => chart.current?.destroy();
  }, []);
  
  return <canvas ref={ref} height={100} />;
}

function ConfMatrix() {
  const classes = ['Normal', 'DoS', 'Probe', 'R2L', 'U2R'];
  const cm = [
    [13467, 0, 1, 0, 0],
    [0, 13468, 1, 0, 0],
    [1, 0, 13466, 1, 0],
    [0, 0, 1, 13465, 2],
    [0, 0, 0, 2, 13466]
  ];
  const maxV = 13468;
  
  function heatColor(v) {
    const n = v / maxV;
    if (n > 0.5) return `rgba(0,212,245,${0.1 + n * 0.5})`;
    if (n > 0) return `rgba(245,51,74,${0.2 + n * 0.4})`;
    return 'rgba(255,255,255,.02)';
  }
  
  return (
    <div className="cm-grid">
      <div className="cm-cell cm-rl" />
      {classes.map((c) => (
        <div key={c} className="cm-cell cm-hdr">
          {c}
        </div>
      ))}
      {cm.map((row, i) => [
        <div key={`rl${i}`} className="cm-cell cm-rl">
          {classes[i]}
        </div>,
        ...row.map((v, j) => (
          <div
            key={`${i}${j}`}
            className="cm-cell"
            style={{
              background: heatColor(v),
              color: i === j ? CYAN : v > 0 ? RED : '#3d6880',
              fontFamily: 'var(--mono)',
              fontSize: '0.75rem',
              fontWeight: i === j ? '700' : '400',
              borderRadius: '3px'
            }}
          >
            {v.toLocaleString()}
          </div>
        ))
      ])}
    </div>
  );
}

function FeatureImportances() {
  const feats = [
    ['total_bytes', 0.0805],
    ['src_bytes', 0.066],
    ['dst_bytes', 0.0548],
    ['src_bytes_ratio', 0.0443],
    ['logged_in', 0.0363],
    ['log_src_bytes', 0.0341],
    ['log_dst_bytes', 0.0318],
    ['count', 0.0295],
    ['srv_count', 0.027],
    ['dst_host_count', 0.0258],
    ['packet_rate', 0.0231],
    ['byte_diff', 0.0218],
    ['dst_host_srv_count', 0.0205],
    ['protocol_tcp', 0.0191],
    ['flag_SF', 0.0178]
  ];
  const [vis, setVis] = useState(false);
  const ref = useRef();
  
  useEffect(() => {
    const obs = new IntersectionObserver(
      ([e]) => {
        if (e.isIntersecting) {
          setTimeout(() => setVis(true), 200);
          obs.disconnect();
        }
      },
      { threshold: 0.2 }
    );
    if (ref.current) obs.observe(ref.current);
    return () => obs.disconnect();
  }, []);
  
  return (
    <div className="feat-list" ref={ref}>
      {feats.map(([name, score], i) => (
        <div className="feat-row" key={name}>
          <span className="feat-name">{name}</span>
          <div className="feat-bg">
            <div
              className="feat-fill"
              style={{
                width: vis ? `${((score / feats[0][1]) * 100).toFixed(1)}%` : '0%',
                transitionDelay: `${i * 0.04}s`
              }}
            />
          </div>
          <span className="feat-sc">{score.toFixed(4)}</span>
        </div>
      ))}
    </div>
  );
}

function App() {
  return (
    <div className="dash">
      <div className="kpi-row">
        {[
          ['67,343', 'Normal Traffic', '53.46% of dataset', 'c0'],
          ['45,927', 'DoS Attacks', '36.46% of dataset', 'c1'],
          ['11,656', 'Probe Attacks', '9.25% of dataset', 'c2'],
          ['995', 'R2L Attacks', '0.79% of dataset', 'c3'],
          ['52', 'U2R Attacks', '0.04% of dataset', 'c4']
        ].map(([v, l, s, c], i) => (
          <div key={l} className={`kpi ${c}`} style={{ animation: `fadeSlideUp .5s ${i * 0.08}s both` }}>
            <span className="kpi-v">{v}</span>
            <div className="kpi-l">{l}</div>
            <div className="kpi-s">{s}</div>
          </div>
        ))}
      </div>

      <ChartCard id="pie" title="Traffic Distribution" sub="Training Set" col="col-4">
        <DonutChart />
      </ChartCard>
      <ChartCard id="proto" title="Protocol Breakdown" sub="Normal vs Attack" col="col-4">
        <ProtocolChart />
      </ChartCard>
      <ChartCard id="radar" title="Attack Category Profile" sub="Normalised Features" col="col-4">
        <RadarChart />
      </ChartCard>

      <ChartCard id="bench" title="Model Benchmark" sub="5-Fold CV" col="col-6">
        <table>
          <thead>
            <tr>
              <th>Model</th>
              <th>Accuracy</th>
              <th>F1 Macro</th>
              <th>Precision</th>
              <th>Recall</th>
            </tr>
          </thead>
          <tbody>
            <tr className="winner">
              <td>
                Random Forest ★
              </td>
              <td>
                99.98% <span className="badge b-g">Best</span>
              </td>
              <td>0.9998</td>
              <td>0.9998</td>
              <td>0.9998</td>
            </tr>
            <tr>
              <td>XGBoost</td>
              <td>99.82%</td>
              <td>0.9981</td>
              <td>0.9980</td>
              <td>0.9982</td>
            </tr>
            <tr>
              <td>Decision Tree</td>
              <td>99.71%</td>
              <td>0.9970</td>
              <td>0.9968</td>
              <td>0.9972</td>
            </tr>
            <tr>
              <td>Logistic Regression</td>
              <td>
                91.4% <span className="badge b-r">Weak</span>
              </td>
              <td>0.8870</td>
              <td>0.9020</td>
              <td>0.8730</td>
            </tr>
          </tbody>
        </table>
      </ChartCard>

      <ChartCard id="roc" title="ROC AUC — One vs Rest" sub="All Classes" col="col-6">
        <ROCChart />
      </ChartCard>

      <ChartCard id="cm" title="Confusion Matrix" sub="Validation Set 20%" col="col-6">
        <ConfMatrix />
      </ChartCard>
      <ChartCard id="feat" title="Top 15 Feature Importances" sub="Random Forest" col="col-6">
        <FeatureImportances />
      </ChartCard>

      <ChartCard id="bar" title="Granular Attack Distribution" sub="Top 15 types" col="col-12">
        <AttackBar />
      </ChartCard>
    </div>
  );
}

ReactDOM.render(<App />, document.getElementById('root'));
