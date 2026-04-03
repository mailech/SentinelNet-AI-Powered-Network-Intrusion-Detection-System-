const { useState, useEffect, useRef } = React;

function CountUp({ end, duration = 2000, suffix = '' }) {
  const [n, setN] = useState(0);
  const ref = useRef();

  useEffect(() => {
    const obs = new IntersectionObserver(([e]) => {
      if (!e.isIntersecting) return;
      obs.disconnect();

      const t0 = performance.now();
      const tick = (t) => {
        const p = Math.min((t - t0) / duration, 1);
        const e2 = 1 - Math.pow(1 - p, 3);
        setN(Math.round(end * e2));
        if (p < 1) requestAnimationFrame(tick);
      };
      requestAnimationFrame(tick);
    }, { threshold: 0.5 });

    if (ref.current) obs.observe(ref.current);
    return () => obs.disconnect();
  }, [end, duration]);

  return (
    <span ref={ref}>
      {n.toLocaleString()}
      {suffix}
    </span>
  );
}

const ATTACKS = [
  { name: 'Normal', sub: 'Legitimate network traffic — baseline connections', count: 67343, color: '#00d4f5', pct: 100 },
  { name: 'DoS', sub: 'neptune, smurf, teardrop, mailbomb, apache2…', count: 45927, color: '#f5334a', pct: 68 },
  { name: 'Probe', sub: 'satan, ipsweep, nmap, portsweep, mscan, saint…', count: 11656, color: '#f5c842', pct: 17 },
  { name: 'R2L', sub: 'guess_passwd, ftp_write, imap, phf, multihop…', count: 995, color: '#f5834a', pct: 5 },
  { name: 'U2R', sub: 'buffer_overflow, rootkit, loadmodule, perl, ps…', count: 52, color: '#a855f7', pct: 2 }
];

const PIPELINE = [
  {
    icon: '⬇️',
    title: 'Data Extraction',
    desc: 'Downloads KDDTrain+ & KDDTest+ from GitHub, assigns 43 column names, validates zero missing values, saves a clean labeled CSV.',
    tags: ['requests', 'pandas', '125K rows']
  },
  {
    icon: '🔍',
    title: 'EDA',
    desc: 'Deep analysis of class distribution, protocol breakdown, attack patterns, land attack detection, service and flag statistics with rich visualizations.',
    tags: ['seaborn', 'matplotlib', '23 classes']
  },
  {
    icon: '⚙️',
    title: 'Feature Engineering',
    desc: 'Isolation Forest outlier flagging, log transforms on skewed cols, 6 engineered features, OHE + frequency encoding, correlation pruning.',
    tags: ['RobustScaler', 'PCA', '66 features']
  },
  {
    icon: '🧠',
    title: 'Modeling',
    desc: 'Random Forest classifier with 300 estimators achieves 99.98% accuracy across all 5 classes using 5-fold stratified cross-validation.',
    tags: ['RandomForest', 'XGBoost', 'ROC AUC']
  }
];

const RESULTS = [
  { m: '99.98%', l: 'Validation Accuracy' },
  { m: '0.9998', l: 'F1 Macro Score' },
  { m: '1.000', l: 'ROC AUC Normal' },
  { m: '1.000', l: 'ROC AUC DoS' },
  { m: '5-Fold', l: 'Stratified CV' },
  { m: 'RF > XGB', l: 'Benchmark Winner' }
];

const TECH = [
  'Python 3',
  'Pandas',
  'NumPy',
  'Matplotlib',
  'Seaborn',
  'Scikit-Learn',
  'RandomForest',
  'XGBoost',
  'IsolationForest',
  'RobustScaler',
  'PCA',
  'Joblib',
  'Jupyter',
  'Vercel'
];

function PipCard({ icon, title, desc, tags, index }) {
  return (
    <div className="pip-card" style={{ animation: `fadeSlideUp .6s ${0.1 + index * 0.12}s both` }}>
      <div className="pip-num">{String(index + 1).padStart(2, '0')}</div>
      <div className="pip-step">Step {String(index + 1).padStart(2, '0')}</div>
      <span className="pip-icon">{icon}</span>
      <div className="pip-title">{title}</div>
      <div className="pip-desc">{desc}</div>
      <div className="pip-tags">
        {tags.map((t) => (
          <span className="pip-tag" key={t}>
            {t}
          </span>
        ))}
      </div>
    </div>
  );
}

function AtkRow({ atk, index }) {
  const [vis, setVis] = useState(false);
  const ref = useRef();

  useEffect(() => {
    const obs = new IntersectionObserver(
      ([e]) => {
        if (e.isIntersecting) {
          setTimeout(() => setVis(true), index * 100);
          obs.disconnect();
        }
      },
      { threshold: 0.2 }
    );

    if (ref.current) obs.observe(ref.current);
    return () => obs.disconnect();
  }, [index]);

  return (
    <div
      ref={ref}
      className="atk-row"
      style={{
        opacity: vis ? 1 : 0,
        transform: vis ? 'none' : 'translateX(-20px)',
        transition: `opacity .5s ${index * 0.08}s,transform .5s ${index * 0.08}s`
      }}
    >
      <style>{`.atk-row:nth-child(${index + 1})::before{background:${atk.color}}`}</style>
      <div className="atk-name">
        <div className="atk-dot" style={{ background: atk.color, color: atk.color }} />
        <div>
          <div className="atk-lbl">{atk.name}</div>
          <div className="atk-sub">{atk.sub}</div>
        </div>
      </div>
      <div className="atk-bar-bg">
        <div
          className="atk-bar"
          style={{
            background: atk.color,
            width: vis ? `${atk.pct}%` : '0%',
            opacity: 0.75
          }}
        />
      </div>
      <div className="atk-cnt">{atk.count.toLocaleString()}</div>
    </div>
  );
}

function ResCard({ m, l, index }) {
  const [vis, setVis] = useState(false);
  const ref = useRef();

  useEffect(() => {
    const obs = new IntersectionObserver(
      ([e]) => {
        if (e.isIntersecting) {
          setTimeout(() => setVis(true), index * 80);
          obs.disconnect();
        }
      },
      { threshold: 0.3 }
    );

    if (ref.current) obs.observe(ref.current);
    return () => obs.disconnect();
  }, [index]);

  return (
    <div
      ref={ref}
      className="res-card"
      style={{
        opacity: vis ? 1 : 0,
        transform: vis ? 'none' : 'translateY(24px)',
        transition: 'opacity .5s,transform .5s'
      }}
    >
      <span className="r-m">{m}</span>
      <span className="r-l">{l}</span>
    </div>
  );
}

function App() {
  return (
    <>
      <section className="hero">
        <div className="hero-grid" />
        <div className="hero-content">
          <div className="hero-eyebrow" id="hero-ey">
            NSL-KDD Dataset <span className="sep">·</span> Random Forest <span className="sep">·</span> 99.98% Accuracy
          </div>
          <h1 className="hero-title" id="hero-t">
            <span className="line">
              <span className="word accent">SENTINEL</span>
            </span>
            <span className="line">
              <span className="word outline">NET</span>
            </span>
          </h1>
          <div className="hero-sub" id="hero-s">
            // Network Intrusion Detection System &nbsp;·&nbsp; 125,973 samples &nbsp;·&nbsp; 5 attack classes
          </div>
          <div className="hero-cta" id="hero-c">
            <a href="demo.html" className="btn btn-primary">
              ▶ &nbsp;Try Live Demo
            </a>
            <a href="dashboard.html" className="btn btn-ghost">
              📊 &nbsp;Dashboard
            </a>
          </div>
        </div>
        <div className="scroll-ind" id="scroll-ind">
          <span className="scroll-txt">scroll</span>
          <div className="scroll-line" />
        </div>
        <div className="stats-bar">
          {[
            { v: 125973, l: 'Training Samples' },
            { v: 9998, l: 'F1 Macro ×10⁻⁴' },
            { v: 5, l: 'Attack Classes' },
            { v: 66, l: 'Features' },
            { v: 300, l: 'RF Estimators' }
          ].map((s, i) => (
            <div className="stat-item" key={i}>
              <span className="stat-val">
                <CountUp end={s.v} duration={1800 + i * 200} />
              </span>
              <span className="stat-label">{s.l}</span>
            </div>
          ))}
        </div>
      </section>

      <section className="pip-section s-pad" id="pipeline">
        <div className="container">
          <div className="s-tag" data-reveal>
            Methodology
          </div>
          <h2 className="s-h" data-reveal>
            4-STAGE
            <br />
            ML PIPELINE
          </h2>
          <p className="s-p" data-reveal>
            Each notebook handles a distinct stage — from raw data ingestion to a production-ready classifier.
          </p>
          <div className="pip-grid">
            {PIPELINE.map((p, i) => (
              <PipCard key={i} index={i} {...p} />
            ))}
          </div>
        </div>
      </section>

      <section className="atk-section" id="dataset">
        <div className="container">
          <div className="s-tag" data-reveal>
            Dataset
          </div>
          <h2 className="s-h" data-reveal>
            ATTACK
            <br />
            CATEGORIES
          </h2>
          <p className="s-p" data-reveal>
            23 granular attack types mapped into 5 meaningful categories for classification and analysis.
          </p>
          <div className="atk-list">
            {ATTACKS.map((a, i) => (
              <AtkRow key={a.name} atk={a} index={i} />
            ))}
          </div>
        </div>
      </section>

      <section className="res-section" id="results">
        <div className="container">
          <div className="s-tag" data-reveal>
            Performance
          </div>
          <h2 className="s-h" data-reveal>
            NEAR-PERFECT
            <br />
            CLASSIFICATION
          </h2>
          <p className="s-p" data-reveal>
            Random Forest with 300 estimators — state-of-the-art across all five attack categories.
          </p>
          <div className="res-grid">
            {RESULTS.map((r, i) => (
              <ResCard key={r.m} index={i} m={r.m} l={r.l} />
            ))}
          </div>
        </div>
      </section>

      <section className="tech-section">
        <div className="container">
          <div className="s-tag" data-reveal>
            Stack
          </div>
          <h2 className="s-h" data-reveal>
            TECHNOLOGIES
          </h2>
          <div className="tech-grid" data-reveal>
            {TECH.map((t) => (
              <div className="tech-pill" key={t}>
                {t}
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="cta-section">
        <div className="cta-glow" />
        <div className="container">
          <div className="s-tag" style={{ justifyContent: 'center' }} data-reveal>
            Explore
          </div>
          <h2 className="s-h" data-reveal style={{ marginBottom: '1.5rem' }}>
            SEE IT IN
            <br />
            ACTION
          </h2>
          <p className="s-p" style={{ margin: '0 auto 3rem', textAlign: 'center' }} data-reveal>
            Input network features and watch the classifier work, or dive into the full analytics dashboard.
          </p>
          <div className="hero-cta" data-reveal>
            <a href="demo.html" className="btn btn-primary">
              ▶ &nbsp;Live Prediction Demo
            </a>
            <a href="dashboard.html" className="btn btn-ghost">
              📊 &nbsp;Analytics Dashboard
            </a>
          </div>
        </div>
      </section>

      <footer>
        <span>SentinelNet &nbsp;·&nbsp; NSL-KDD Intrusion Detection</span>
        <span>
          Scikit-Learn · Hosted on <a href="https://vercel.com" target="_blank" rel="noreferrer">Vercel</a>
        </span>
      </footer>
    </>
  );
}

ReactDOM.render(<App />, document.getElementById('root'));
