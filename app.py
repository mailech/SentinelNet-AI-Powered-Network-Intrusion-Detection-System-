"""
SentinelNet — AI-Powered Network Intrusion Detection System
Flask Backend
"""

import os
import io
import random
import threading
import time
from collections import deque
from datetime import datetime, timedelta

import joblib
import numpy as np
import pandas as pd
from flask import Flask, render_template, jsonify, request

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50 MB upload limit

# ── Column names (NSL-KDD) ─────────────────────────────────────────────────
COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations",
    "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login",
    "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate",
    "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
    "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "class", "difficulty_level",
]
FEATURE_COLS = [c for c in COLUMNS if c not in ("class", "difficulty_level")]

DOS_ATTACKS    = {"neptune","back","land","pod","smurf","teardrop","apache2","udpstorm","processtable","worm"}
PROBE_ATTACKS  = {"satan","ipsweep","nmap","portsweep","mscan","saint"}
R2L_ATTACKS    = {"guess_passwd","ftp_write","imap","phf","multihop","warezmaster","warezclient",
                  "spy","xlock","xsnoop","snmpguess","snmpgetattack","httptunnel","sendmail","named"}
U2R_ATTACKS    = {"buffer_overflow","loadmodule","rootkit","perl","sqlattack","xterm","ps"}

BASE          = os.path.dirname(__file__)
MODEL_PATH    = os.path.join(BASE, "notebooks", "models", "best_model.pkl")
PREPROC_PATH  = os.path.join(BASE, "notebooks", "models", "preprocessor.pkl")
TRAIN_PATH    = os.path.join(BASE, "notebooks", "data", "KDDTrain+.txt")
TEST_PATH     = os.path.join(BASE, "notebooks", "data", "KDDTest+.txt")

# ── Real-Time Simulation State ─────────────────────────────────────────────
SIMULATION_ACTIVE = True
simulation_status = "active"
quarantined_ips = set()

live_alerts = deque(maxlen=100)
live_timeseries = deque(maxlen=60) # Last 60 updates

traffic_stats = {
    "total": 0,
    "normal": 0,
    "attack": 0,
    "attack_types": {},
    "protocols": {},
    "blocked": 0
}

def simulate_realtime_traffic():
    """Background thread to process traffic continuously."""
    print("🚀 Starting real-time traffic simulation...")
    try:
        df_test = pd.read_csv(TEST_PATH, names=COLUMNS)
    except Exception as e:
        print(f"⚠️ Simulation could not load test data: {e}")
        return
        
    while SIMULATION_ACTIVE:
        time.sleep(2.0) # Update every 2 seconds
        
        if simulation_status == "paused":
            continue
            
        # Simulate persistent attacks being firewalled off
        if quarantined_ips:
            for _ in quarantined_ips:
                dropped = random.randint(3, 15)
                traffic_stats["blocked"] += dropped
                traffic_stats["total"] += dropped
                
        # Take a random batch of packets
        batch_size = random.randint(15, 60)
        sample = df_test.sample(n=batch_size)
        
        preds, probas = predict_dataframe(sample)
        attacks_in_batch = 0
        now_str = datetime.now().strftime("%H:%M:%S")
        
        for i, (idx, row) in enumerate(sample.iterrows()):
            src_ip = f"192.168.{random.randint(1,10)}.{random.randint(1,254)}"
            
            # Simulated Firewall / Quarantine check
            if src_ip in quarantined_ips:
                traffic_stats["blocked"] += 1
                continue
                
            traffic_stats["total"] += 1
            
            p = str(row["protocol_type"])
            traffic_stats["protocols"][p] = traffic_stats["protocols"].get(p, 0) + 1
            
            if preds[i] == 1:
                traffic_stats["attack"] += 1
                attacks_in_batch += 1
                
                t = classify_attack(row["class"])
                traffic_stats["attack_types"][t] = traffic_stats["attack_types"].get(t, 0) + 1
                
                prob = float(probas[i])
                live_alerts.appendleft({
                    "id": traffic_stats["total"],
                    "timestamp": now_str,
                    "src_ip": src_ip,
                    "dst_ip": f"10.0.{random.randint(0,5)}.{random.randint(1,50)}",
                    "protocol": p.upper(),
                    "service": str(row["service"]),
                    "actual": t,
                    "confidence": round(prob * 100, 1),
                    "severity": get_severity(prob),
                })
            else:
                traffic_stats["normal"] += 1
                
        live_timeseries.append({
            "timestamp": now_str,
            "total": batch_size,
            "attacks": attacks_in_batch
        })

# ── Load artifacts once ────────────────────────────────────────────────────
model, preprocessor, df_train = None, None, None
load_error_message = None

def load_all():
    global model, preprocessor, df_train, load_error_message
    try:
        model        = joblib.load(MODEL_PATH)
        preprocessor = joblib.load(PREPROC_PATH)
        df_train     = pd.read_csv(TRAIN_PATH, names=COLUMNS)
        df_train["binary_class"] = df_train["class"].apply(lambda x: 0 if x.strip()=="normal" else 1)
        print("✅ Resources loaded.")
        
        # Start the simulation thread
        t = threading.Thread(target=simulate_realtime_traffic, daemon=True)
        t.start()
    except Exception as e:
        import traceback
        load_error_message = traceback.format_exc()
        print(f"⚠️  Load error: {e}")

load_all()

# ── Helpers ────────────────────────────────────────────────────────────────
def get_severity(prob: float) -> str:
    if prob > 0.90: return "Critical"
    if prob > 0.75: return "High"
    if prob > 0.50: return "Medium"
    return "Low"

def classify_attack(label: str) -> str:
    l = str(label).strip().lower()
    if l == "normal":              return "Normal"
    if l in DOS_ATTACKS:           return "DoS"
    if l in PROBE_ATTACKS:         return "Probe"
    if l in R2L_ATTACKS:           return "R2L"
    if l in U2R_ATTACKS:           return "U2R"
    return "Attack"

def predict_dataframe(df: pd.DataFrame):
    """Run model on a dataframe that has exactly FEATURE_COLS columns."""
    X_proc  = preprocessor.transform(df[FEATURE_COLS])
    preds   = model.predict(X_proc)
    probas  = model.predict_proba(X_proc)[:, 1]
    return preds, probas

# ── Pages ──────────────────────────────────────────────────────────────────
@app.route("/")
@app.route("/<page>")
def index(page="dashboard"):
    return render_template("index.html")

@app.route("/api/debug")
def api_debug():
    return jsonify(error=load_error_message)

# ── API: dataset overview stats ────────────────────────────────────────────
@app.route("/api/live_data")
def api_live_data():
    return jsonify(
        stats=traffic_stats,
        timeseries=list(live_timeseries),
        alerts=list(live_alerts),
        status=simulation_status,
        quarantined=list(quarantined_ips)
    )

@app.route("/api/sim/toggle", methods=["POST"])
def api_sim_toggle():
    global simulation_status
    data = request.get_json(force=True)
    if data.get("action") == "start":
        simulation_status = "active"
    else:
        simulation_status = "paused"
    return jsonify(status=simulation_status)

@app.route("/api/quarantine", methods=["POST"])
def api_quarantine():
    data = request.get_json(force=True)
    ip = data.get("ip")
    if ip:
        quarantined_ips.add(ip)
    return jsonify(success=True, quarantined=list(quarantined_ips))

@app.route("/api/stats")
def api_stats():
    if df_train is None:
        return jsonify(error="Dataset not loaded"), 500
    total   = len(df_train)
    attacks = int(df_train["binary_class"].sum())
    normal  = total - attacks
    # attack-type breakdown
    type_counts = {}
    for _, row in df_train[["class"]].iterrows():
        t = classify_attack(row["class"])
        type_counts[t] = type_counts.get(t, 0) + 1
    proto_counts = df_train["protocol_type"].value_counts().to_dict()
    return jsonify(
        total=total, attacks=attacks, normal=normal,
        attack_rate=round(attacks/total*100, 2) if total > 0 else 0,
        attack_types=type_counts, protocols=proto_counts
    )

# ── API: model metrics (from your notebooks) ───────────────────────────────
@app.route("/api/metrics")
def api_metrics():
    return jsonify(
        accuracy=99.2, precision=99.4, recall=99.1, f1=99.2, roc_auc=99.7,
        model="Random Forest (Tuned via GridSearchCV)",
        train_samples=125973, test_samples=22544, features=41
    )

# ── API: sample alerts from test set ──────────────────────────────────────
@app.route("/api/sample_alerts")
def api_sample_alerts():
    if model is None or preprocessor is None:
        return jsonify([])
    try:
        df = pd.read_csv(TEST_PATH, names=COLUMNS)
        sample = df.sample(n=min(200, len(df)), random_state=7)
        preds, probas = predict_dataframe(sample)
        now = datetime.now()
        alerts = []
        for i, (idx, row) in enumerate(sample.iterrows()):
            if preds[i] == 1:
                prob = float(probas[i])
                alerts.append(dict(
                    id=int(idx),
                    timestamp=(now - timedelta(minutes=random.randint(0,1440))).strftime("%Y-%m-%d %H:%M:%S"),
                    src_ip=f"192.168.{random.randint(1,254)}.{random.randint(1,254)}",
                    dst_ip=f"10.0.{random.randint(0,5)}.{random.randint(1,50)}",
                    protocol=str(row["protocol_type"]).upper(),
                    service=str(row["service"]),
                    actual=classify_attack(row["class"]),
                    confidence=round(prob*100, 1),
                    severity=get_severity(prob),
                ))
        alerts.sort(key=lambda x: x["confidence"], reverse=True)
        return jsonify(alerts[:40])
    except Exception as e:
        print(f"Sample alerts error: {e}")
        return jsonify([])

# ── API: single-connection predict ─────────────────────────────────────────
@app.route("/api/predict", methods=["POST"])
def api_predict():
    if model is None or preprocessor is None:
        return jsonify(error="Model not loaded"), 503
    data = request.get_json(force=True)
    try:
        row = {col: data.get(col, 0) for col in FEATURE_COLS}
        df  = pd.DataFrame([row])
        preds, probas = predict_dataframe(df)
        pred = int(preds[0]); prob = float(probas[0])
        return jsonify(
            prediction="Attack" if pred == 1 else "Normal",
            confidence=round(prob*100, 2),
            severity=get_severity(prob) if pred==1 else "None"
        )
    except Exception as e:
        return jsonify(error=str(e)), 400

# ── API: file upload & batch predict ──────────────────────────────────────
@app.route("/api/upload", methods=["POST"])
def api_upload():
    if model is None or preprocessor is None:
        return jsonify(error="Model not loaded"), 503

    file = request.files.get("file")
    if not file or file.filename == "":
        return jsonify(error="No file provided"), 400

    fname = file.filename.lower()
    try:
        content = file.read().decode("utf-8", errors="replace")
        # Try with headers first, else use COLUMNS
        try:
            df = pd.read_csv(io.StringIO(content))
            # If it has all FEATURE_COLS already, keep it
            if not all(c in df.columns for c in FEATURE_COLS):
                # Assume NSL-KDD raw format
                df = pd.read_csv(io.StringIO(content), names=COLUMNS)
        except Exception:
            df = pd.read_csv(io.StringIO(content), names=COLUMNS)

        # Drop label columns if present
        for col in ("class", "difficulty_level", "binary_class"):
            if col in df.columns:
                df = df.drop(columns=[col])

        # Check we have the right features
        missing = [c for c in FEATURE_COLS if c not in df.columns]
        if missing:
            return jsonify(error=f"Missing columns: {', '.join(missing[:5])}…"), 400

        total = len(df)
        if total == 0:
            return jsonify(error="File is empty"), 400
        if total > 5000:
            df = df.sample(n=5000, random_state=42)

        preds, probas = predict_dataframe(df)

        n_attacks = int(preds.sum())
        n_normal  = total - n_attacks

        rows = []
        for i in range(min(len(df), 100)):
            prob = float(probas[i]); pred = int(preds[i])
            rows.append(dict(
                row_num=i+1,
                prediction="Attack" if pred==1 else "Normal",
                confidence=round(prob*100, 1),
                severity=get_severity(prob) if pred==1 else "—",
                protocol=str(df.iloc[i].get("protocol_type","—")).upper(),
                service=str(df.iloc[i].get("service","—")),
            ))

        # severity breakdown
        sev_counts = {"Critical":0,"High":0,"Medium":0,"Low":0}
        for i, pred in enumerate(preds):
            if pred == 1:
                sev_counts[get_severity(float(probas[i]))] += 1

        return jsonify(
            filename=file.filename,
            total=total,
            attacks=n_attacks,
            normal=n_normal,
            attack_rate=round(n_attacks/total*100, 2),
            severity_breakdown=sev_counts,
            rows=rows
        )
    except Exception as e:
        return jsonify(error=f"Processing failed: {str(e)}"), 500

if __name__ == "__main__":
    app.run(debug=True, port=5050)
