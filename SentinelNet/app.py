from flask import Flask, render_template, request, send_file
import pandas as pd
import joblib
import datetime
import io
from collections import Counter

app = Flask(__name__)

# Load model and encoder
try:
    model = joblib.load("intrusion_model.pkl")
    le = joblib.load("label_encoder.pkl")
except Exception as e:
    print(f"Model Load Error: {e}")

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/predict", methods=["POST"])
def predict():
    file = request.files.get("file")
    if not file: return "No file uploaded"

    COL_NAMES = ['duration','protocol_type','service','flag','src_bytes','dst_bytes','land','wrong_fragment','urgent','hot','num_failed_logins','logged_in','num_compromised','root_shell','su_attempted','num_root','num_file_creations','num_shells','num_access_files','num_outbound_cmds','is_host_login','is_guest_login','count','srv_count','serror_rate','srv_serror_rate','rerror_rate','srv_rerror_rate','same_srv_rate','diff_srv_rate','srv_diff_host_rate','dst_host_count','dst_host_srv_count','dst_host_same_srv_rate','dst_host_diff_srv_rate','dst_host_same_src_port_rate','dst_host_srv_diff_host_rate','dst_host_serror_rate','dst_host_srv_serror_rate','dst_host_rerror_rate','dst_host_srv_rerror_rate','label','difficulty_level']

    try:
        df = pd.read_csv(file, header=None, names=COL_NAMES)
        if 'label' in df.columns: df = df.drop(columns=['label'])
        
        # Encoding
        df_encoded = pd.get_dummies(df, columns=['protocol_type', 'service', 'flag'])
        df_encoded = df_encoded.reindex(columns=model.feature_names_in_, fill_value=0)
        
        # Prediction
        preds = model.predict(df_encoded)
        results = [str(r).strip().upper() for r in le.inverse_transform(preds)]
        
        # Dashboard Stats
        counts = Counter(results)
        total = len(results)
        attacks = sum(v for k, v in counts.items() if k != 'NORMAL')
        safe = counts.get('NORMAL', 0)
        percent = round((attacks / total * 100), 1) if total > 0 else 0

        return render_template("index.html", 
                               predictions=results[:50], 
                               total=total, attacks=attacks, safe=safe, percent=percent,
                               chart_labels=list(counts.keys()), 
                               chart_values=list(counts.values()))
    except Exception as e:
        return f"System Error: {str(e)}"

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001, debug=True)