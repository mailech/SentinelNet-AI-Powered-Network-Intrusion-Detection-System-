import os, joblib
import numpy as np
import pandas as pd
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS

app = Flask(__name__)
CORS(app, origins="*")

# ── Load all model artifacts ────────────────────────────────────────────────
MODEL_DIR = os.path.join(os.path.dirname(__file__), 'models')

sentinel_brain    = joblib.load(os.path.join(MODEL_DIR, 'sentinel_brain.joblib'))
le                = joblib.load(os.path.join(MODEL_DIR, 'label_encoder.joblib'))
ohe               = joblib.load(os.path.join(MODEL_DIR, 'ohe_encoder.joblib'))
freq_map          = joblib.load(os.path.join(MODEL_DIR, 'freq_map.joblib'))
scaler            = joblib.load(os.path.join(MODEL_DIR, 'scaler.joblib'))
selected_features = joblib.load(os.path.join(MODEL_DIR, 'selected_features.joblib'))

COLUMNS = [
    'duration','protocol_type','service','flag','src_bytes','dst_bytes',
    'land','wrong_fragment','urgent','hot','num_failed_logins','logged_in',
    'num_compromised','root_shell','su_attempted','num_root','num_file_creations',
    'num_shells','num_access_files','num_outbound_cmds','is_host_login',
    'is_guest_login','count','srv_count','serror_rate','srv_serror_rate',
    'rerror_rate','srv_rerror_rate','same_srv_rate','diff_srv_rate',
    'srv_diff_host_rate','dst_host_count','dst_host_srv_count',
    'dst_host_same_srv_rate','dst_host_diff_srv_rate','dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate','dst_host_serror_rate','dst_host_srv_serror_rate',
    'dst_host_rerror_rate','dst_host_srv_rerror_rate','label','difficulty_level'
]
SEVERITY_MAP = {'normal':'None','DoS':'Critical','Probe':'Medium','R2L':'High','U2R':'Critical'}

# ── Serve frontend ──────────────────────────────────────────────────────────
@app.route("/")
def index():
    return send_from_directory("frontend", "index.html")

# ── THIS IS THE KEY FIX: serve style.css, app.js, and any other static files
@app.route("/<path:filename>")
def static_files(filename):
    return send_from_directory("frontend", filename)

# ── Everything below is UNCHANGED ──────────────────────────────────────────

def preprocess(df):
    df = df.copy()
    for col in COLUMNS:
        if col not in df.columns:
            df[col] = 0
    if 'label' not in df.columns:
        df['label'] = 'normal'
    cats = ['protocol_type', 'flag']
    enc_df = pd.DataFrame(
        ohe.transform(df[cats]),
        columns=ohe.get_feature_names_out(cats),
        index=df.index
    )
    df = pd.concat([df, enc_df], axis=1)
    df['service_freq'] = df['service'].map(freq_map).fillna(0)
    for col in ['src_bytes', 'dst_bytes', 'duration']:
        df[f'log_{col}'] = np.log1p(df[col].astype(float))
    df['total_bytes']     = df['src_bytes'].astype(float) + df['dst_bytes'].astype(float)
    df['src_bytes_ratio'] = df['src_bytes'].astype(float) / (df['total_bytes'] + 1e-5)
    df['is_error_flag']   = df['flag'].isin(['S0','S1','S2','S3','REJ']).astype(int)
    for f in selected_features:
        if f not in df.columns:
            df[f] = 0
    feature_matrix = df[selected_features].values
    feature_matrix = scaler.transform(feature_matrix)
    return feature_matrix

@app.route('/health')
def health():
    return jsonify({'status': 'online', 'model': 'sentinel_brain'})

@app.route('/predict', methods=['POST', 'OPTIONS'])
def predict():
    if request.method == 'OPTIONS':
        return jsonify({}), 200
    try:
        data = request.get_json(force=True)
        rows = data.get('rows', [])
        df   = pd.DataFrame(rows)
        X    = preprocess(df)
        preds   = sentinel_brain.predict(X)
        proba   = sentinel_brain.predict_proba(X)
        classes = le.inverse_transform(preds)
        results = [
            {
                'predicted_class': cls,
                'severity':        SEVERITY_MAP.get(cls, 'Unknown'),
                'confidence':      round(float(conf), 4),
                'is_intrusion':    cls != 'normal'
            }
            for cls, conf in zip(classes, proba.max(axis=1))
        ]
        return jsonify({'status': 'ok', 'results': results})
    except Exception as e:
        import traceback
        return jsonify({'status': 'error', 'message': str(e),
                        'trace': traceback.format_exc()}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=7860)