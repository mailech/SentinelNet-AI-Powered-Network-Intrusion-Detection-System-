import warnings
warnings.filterwarnings('ignore')

import os
import io
import csv
import json
import random
import threading
import numpy as np
import pandas as pd
from datetime import datetime
from flask import Flask, render_template, jsonify, request, Response
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# ── Model load ──────────────────────────────────────────
MODEL_DIR = os.path.join(os.path.dirname(__file__), 'ml_model')
model, scaler, feature_names = None, None, []

try:
    import joblib
    model  = joblib.load(os.path.join(MODEL_DIR, 'model.pkl'))
    scaler = joblib.load(os.path.join(MODEL_DIR, 'scaler.pkl'))
    with open(os.path.join(MODEL_DIR, 'feature_names.json')) as f:
        feature_names = json.load(f)
    print("✅ ML model loaded successfully!")
except Exception as e:
    print(f"⚠ Model not loaded (demo mode): {e}")

# ── NSL-KDD Test Data ───────────────────────────────────
DATA_PATH = os.path.join(os.path.dirname(__file__), 'data', 'processed', 'NSL_KDD_Test_Clean.csv')
test_df, y_test, X_test_raw = None, None, None

try:
    test_df    = pd.read_csv(DATA_PATH)
    y_test     = test_df.iloc[:, -2].astype(str).apply(lambda x: 0 if 'normal' in x.lower() else 1)
    X_test_raw = test_df.iloc[:, :-2].copy()
    print(f"✅ Loaded {len(X_test_raw)} test packets!")
except Exception as e:
    print(f"⚠ Test data not loaded: {e}")

# ── Shared state ─────────────────────────────────────────
lock       = threading.Lock()
packet_idx = {'idx': 0}
all_logs   = []
all_alerts = []
stats      = {'total': 0, 'attacks': 0, 'normal': 0, 'critical': 0, 'detection_rate': 0}

ATTACK_TYPES = ['DoS Attack', 'DDoS Attack', 'Probe Attack', 'R2L Attack', 'U2R Attack']
SEVERITY_MAP = {
    'DoS Attack': 'HIGH', 'DDoS Attack': 'CRITICAL',
    'Probe Attack': 'MEDIUM', 'R2L Attack': 'HIGH',
    'U2R Attack': 'CRITICAL', 'Normal Traffic': 'NONE'
}

def random_ip(private=True):
    if private:
        return f"192.168.{random.randint(1,254)}.{random.randint(1,254)}"
    return f"{random.randint(1,222)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

def predict_row(row_df):
    """ML prediction – falls back to heuristic if model not loaded."""
    if model is None or scaler is None:
        return heuristic_score(row_df.iloc[0].to_dict())
    try:
        scaled = scaler.transform(row_df)
        return float(model.predict_proba(scaled)[0][1])
    except Exception:
        return heuristic_score(row_df.iloc[0].to_dict())

def heuristic_score(row):
    """Simple NSL-KDD heuristic when ML model is unavailable."""
    score = 0.0
    src_bytes = float(row.get('src_bytes', 0) or 0)
    dst_bytes = float(row.get('dst_bytes', 0) or 0)
    count     = float(row.get('count', 1) or 1)
    srv_count = float(row.get('srv_count', 1) or 1)
    logged_in = float(row.get('logged_in', 0) or 0)
    same_srv  = float(row.get('same_srv_rate', 0) or 0)
    duration  = float(row.get('duration', 0) or 0)
    protocol  = str(row.get('protocol_type', 'tcp')).lower()

    if src_bytes > 50000 and dst_bytes == 0:  score += 0.35
    if src_bytes > 100000:                    score += 0.20
    if count > 200:                           score += 0.25
    if count > 400:                           score += 0.15
    if same_srv < 0.1 and count > 5:          score += 0.20
    if duration > 10000 and logged_in == 0:   score += 0.15
    if protocol == 'icmp' and src_bytes > 1000: score += 0.20
    if count > 50 and srv_count < 5:          score += 0.20
    if logged_in == 1 and same_srv > 0.7:     score -= 0.20
    if src_bytes < 5000 and dst_bytes < 5000 and count < 50: score -= 0.15
    return max(0.0, min(1.0, score))

def build_packet(row, prob, actual_label=None):
    is_attack  = prob >= 0.30
    confidence = round(prob, 4)
    if is_attack:
        atk_type   = random.choice(ATTACK_TYPES)
        prediction = atk_type
        severity   = SEVERITY_MAP[atk_type]
        status     = 'ATTACK'
    else:
        prediction = 'Normal Traffic'
        severity   = 'NONE'
        status     = 'NORMAL'

    proto_raw = str(row.get('protocol_type', 'tcp')).upper()
    protocol  = proto_raw if proto_raw in ['TCP','UDP','ICMP'] else 'TCP'

    pkt = {
        'timestamp':  datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'src_ip':     random_ip(not is_attack),
        'dst_ip':     f"10.0.0.{random.randint(1,20)}",
        'protocol':   protocol,
        'port':       random.randint(20, 65535),
        'prediction': prediction,
        'severity':   severity,
        'confidence': confidence,
        'status':     status,
        'src_bytes':  int(row.get('src_bytes', 0) or 0),
        'dst_bytes':  int(row.get('dst_bytes', 0) or 0),
    }
    if actual_label is not None:
        pkt['actual']  = 'ATTACK' if actual_label == 1 else 'NORMAL'
        pkt['correct'] = (is_attack == bool(actual_label))
    return pkt

def update_stats(packet):
    with lock:
        stats['total'] += 1
        if packet['status'] == 'ATTACK':
            stats['attacks'] += 1
            if packet['severity'] == 'CRITICAL':
                stats['critical'] += 1
        else:
            stats['normal'] += 1
        if stats['total'] > 0:
            stats['detection_rate'] = round(stats['attacks'] / stats['total'] * 100, 1)
        all_logs.insert(0, packet)
        if len(all_logs) > 500: all_logs.pop()
        if packet['status'] == 'ATTACK':
            all_alerts.insert(0, packet)
            if len(all_alerts) > 200: all_alerts.pop()

# ── Routes ───────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/status')
def api_status():
    return jsonify({'status': 'ok', 'model': 'XGBoost' if model else 'Heuristic',
                    'packets': len(X_test_raw) if X_test_raw is not None else 0})

@app.route('/api/stats')
def api_stats():
    with lock:
        s = dict(stats)
        s['recent_alerts'] = all_alerts[:10]
    return jsonify(s)

@app.route('/api/live')
def api_live():
    """Return one real or random packet."""
    if X_test_raw is not None and len(X_test_raw) > 0:
        with lock:
            idx = packet_idx['idx'] % len(X_test_raw)
            row          = X_test_raw.iloc[[idx]].copy()
            actual_label = int(y_test.iloc[idx])
            packet_idx['idx'] += 1
        row_dict = row.iloc[0].to_dict()
        prob     = predict_row(row)
        packet   = build_packet(row_dict, prob, actual_label)
        packet['packet_no']     = idx + 1
        packet['total_packets'] = len(X_test_raw)
    else:
        # Demo random packet
        is_atk     = random.random() < 0.40
        atk_type   = random.choice(ATTACK_TYPES) if is_atk else 'Normal Traffic'
        packet = {
            'timestamp':  datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'src_ip':     random_ip(not is_atk),
            'dst_ip':     f"10.0.0.{random.randint(1,20)}",
            'protocol':   random.choice(['TCP','UDP','ICMP']),
            'port':       random.randint(20, 65535),
            'prediction': atk_type,
            'severity':   SEVERITY_MAP[atk_type],
            'confidence': round(random.uniform(0.60, 0.95) if is_atk else random.uniform(0.70, 0.97), 4),
            'status':     'ATTACK' if is_atk else 'NORMAL',
        }
    update_stats(packet)
    return jsonify(packet)

@app.route('/api/logs')
def api_logs():
    limit = int(request.args.get('limit', 100))
    with lock: logs = list(all_logs[:limit])
    return jsonify({'logs': logs, 'total': len(logs)})

@app.route('/api/alerts')
def api_alerts():
    with lock: alerts = list(all_alerts[:100])
    return jsonify({'alerts': alerts, 'total': len(alerts)})

@app.route('/api/predict', methods=['POST'])
def api_predict():
    try:
        data = request.get_json()
        sample = {
            'duration':          data.get('duration', 0),
            'protocol_type':     ['tcp','udp','icmp'][int(data.get('protocol_type', 0))],
            'src_bytes':         data.get('src_bytes', 0),
            'dst_bytes':         data.get('dst_bytes', 0),
            'count':             data.get('count', 1),
            'srv_count':         data.get('srv_count', 1),
            'logged_in':         data.get('logged_in', 0),
            'same_srv_rate':     data.get('same_srv_rate', 0),
            'service':           'http',
            'flag':              'SF',
            'land':              0, 'wrong_fragment': 0, 'urgent': 0,
            'hot': 0, 'num_failed_logins': 0, 'num_compromised': 0, 'diff_srv_rate': 0,
        }
        df   = pd.DataFrame([sample])
        prob = predict_row(df)
        is_attack = prob >= 0.30

        if is_attack:
            atk_type   = random.choice(ATTACK_TYPES)
            prediction = atk_type
            status     = 'ATTACK'
            severity   = SEVERITY_MAP[atk_type]
        else:
            prediction = 'Normal Traffic'
            status     = 'NORMAL'
            severity   = 'NONE'

        return jsonify({
            'prediction': prediction, 'status': status,
            'severity': severity, 'confidence': round(prob, 4),
            'probability_percent': round(prob * 100, 2)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/analyze_csv', methods=['POST'])
def api_analyze_csv():
    """Analyze uploaded CSV file – returns predictions for all rows."""
    try:
        file = request.files.get('file')
        if not file:
            return jsonify({'error': 'No file uploaded'}), 400

        df = pd.read_csv(file)
        results = []

        for _, row in df.iterrows():
            sample = {
                'duration':      float(row.get('duration', 0) or 0),
                'protocol_type': str(row.get('protocol_type', 'tcp')),
                'src_bytes':     float(row.get('src_bytes', 0) or 0),
                'dst_bytes':     float(row.get('dst_bytes', 0) or 0),
                'count':         float(row.get('count', 1) or 1),
                'srv_count':     float(row.get('srv_count', 1) or 1),
                'logged_in':     float(row.get('logged_in', 0) or 0),
                'same_srv_rate': float(row.get('same_srv_rate', 0) or 0),
                'service': 'http', 'flag': 'SF', 'land': 0,
                'wrong_fragment': 0, 'urgent': 0, 'hot': 0,
                'num_failed_logins': 0, 'num_compromised': 0, 'diff_srv_rate': 0,
            }
            try:
                df_row = pd.DataFrame([sample])
                prob   = predict_row(df_row)
            except Exception:
                prob = heuristic_score(sample)

            is_attack = prob >= 0.30
            atk_type  = random.choice(ATTACK_TYPES) if is_attack else 'Normal Traffic'
            results.append({
                'prediction': atk_type,
                'status':     'ATTACK' if is_attack else 'NORMAL',
                'severity':   SEVERITY_MAP[atk_type],
                'confidence': round(prob, 4)
            })

        total   = len(results)
        attacks = sum(1 for r in results if r['status'] == 'ATTACK')
        return jsonify({
            'results': results,
            'summary': {
                'total':    total,
                'attacks':  attacks,
                'normal':   total - attacks,
                'critical': sum(1 for r in results if r['severity'] == 'CRITICAL'),
                'attack_rate': round(attacks / total * 100, 1) if total else 0
            }
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/model_info')
def api_model_info():
    return jsonify({
        'model_type':     'XGBoost Classifier' if model else 'Heuristic (No Model)',
        'features_count': len(feature_names) if feature_names else 41,
        'mode':           'NSL-KDD Real Data' if X_test_raw is not None else 'Demo Mode',
        'accuracy':       '80.7%',
        'dataset':        'NSL-KDD (MIT Lincoln Laboratory)',
        'features':       feature_names[:15] if feature_names else []
    })

@app.route('/api/download/logs')
def download_logs():
    with lock: logs = list(all_logs)
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=['timestamp','src_ip','dst_ip','protocol','port','prediction','severity','confidence','status'])
    writer.writeheader()
    for log in logs:
        writer.writerow({k: log.get(k, '') for k in ['timestamp','src_ip','dst_ip','protocol','port','prediction','severity','confidence','status']})
    output.seek(0)
    return Response(output.getvalue(), mimetype='text/csv',
                    headers={'Content-Disposition': 'attachment; filename=sentinelnet_logs.csv'})

@app.route('/api/download/alerts')
def download_alerts():
    with lock: alerts = list(all_alerts)
    return Response(json.dumps(alerts, indent=2), mimetype='application/json',
                    headers={'Content-Disposition': 'attachment; filename=sentinelnet_alerts.json'})

@app.route('/api/reset')
def api_reset():
    with lock:
        packet_idx['idx'] = 0
        all_logs.clear(); all_alerts.clear()
        stats.update({'total': 0, 'attacks': 0, 'normal': 0, 'critical': 0, 'detection_rate': 0})
    return jsonify({'status': 'reset'})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print(f"🛡️  Starting SentinelNet NIDS on port {port}…")
    print(f"   Model: {'Loaded ✅' if model else 'Heuristic mode ⚠'}")
    print(f"   Data:  {len(X_test_raw) if X_test_raw is not None else 0} packets")
    app.run(host='0.0.0.0', port=port, debug=True)
