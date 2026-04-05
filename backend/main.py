"""
SentinelNet – FastAPI Backend
==============================
Run:  python main.py
Requires: rf_model.pkl, scaler.pkl, encoder.pkl, feature_names.pkl in ../models/
Generate those by running:  python train_model.py
"""

import os, sys, time, random, threading
import numpy as np
import pandas as pd
import joblib
from fastapi import FastAPI, BackgroundTasks, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime
from pydantic import BaseModel
from typing import List, Optional, Dict, Any

# ─── App ─────────────────────────────────────────────────────────────────────
app = FastAPI(title="SentinelNet AI API", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── Paths ───────────────────────────────────────────────────────────────────
BASE_DIR   = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR   = os.path.join(BASE_DIR, "data")
MODEL_DIR  = os.path.join(BASE_DIR, "models")
LOG_FILE   = os.path.join(BASE_DIR, "alerts.log")

CATEGORICAL = ["protocol_type", "service", "flag"]

COL_NAMES = [
    "duration","protocol_type","service","flag","src_bytes","dst_bytes",
    "land","wrong_fragment","urgent","hot","num_failed_logins","logged_in",
    "num_compromised","root_shell","su_attempted","num_root","num_file_creations",
    "num_shells","num_access_files","num_outbound_cmds","is_host_login",
    "is_guest_login","count","srv_count","serror_rate","srv_serror_rate",
    "rerror_rate","srv_rerror_rate","same_srv_rate","diff_srv_rate",
    "srv_diff_host_rate","dst_host_count","dst_host_srv_count",
    "dst_host_same_srv_rate","dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate","dst_host_srv_diff_host_rate",
    "dst_host_serror_rate","dst_host_srv_serror_rate","dst_host_rerror_rate",
    "dst_host_srv_rerror_rate","label","difficulty_level"
]

# ─── Model Registry ──────────────────────────────────────────────────────────
class ModelRegistry:
    def __init__(self):
        self.model        = None
        self.scaler       = None
        self.encoder      = None
        self.feature_cols = None
        self.loaded       = False
        self.error        = None

    def load(self):
        """Load all saved artefacts. Returns True on success."""
        paths = {
            "model":    os.path.join(MODEL_DIR, "rf_model.pkl"),
            "scaler":   os.path.join(MODEL_DIR, "scaler.pkl"),
            "encoder":  os.path.join(MODEL_DIR, "encoder.pkl"),
            "features": os.path.join(MODEL_DIR, "feature_names.pkl"),
        }
        missing = [k for k, p in paths.items() if not os.path.exists(p)]
        if missing:
            self.error = f"Missing model artefacts: {missing}. Run 'python train_model.py' first."
            self.loaded = False
            return False
        try:
            self.model        = joblib.load(paths["model"])
            self.scaler       = joblib.load(paths["scaler"])
            self.encoder      = joblib.load(paths["encoder"])
            self.feature_cols = joblib.load(paths["features"])
            self.loaded       = True
            self.error        = None
            return True
        except Exception as e:
            self.error  = str(e)
            self.loaded = False
            return False

    def predict(self, raw_df: pd.DataFrame):
        """
        raw_df must contain the original NSL-KDD numeric + categorical columns
        (before encoding/scaling). Returns (prediction_int, confidence_float,
        proba_normal, proba_attack).
        """
        # Encode categoricals
        enc_cols = CATEGORICAL
        encoded = pd.DataFrame(
            self.encoder.transform(raw_df[enc_cols]),
            columns=self.encoder.get_feature_names_out(enc_cols),
            index=raw_df.index
        )
        processed = pd.concat([raw_df.drop(columns=enc_cols), encoded], axis=1)

        # Align to training feature order (fills zeros for any unseen categories)
        processed = processed.reindex(columns=self.feature_cols, fill_value=0.0)

        # Scale
        X = self.scaler.transform(processed.values)

        # Predict
        pred   = int(self.model.predict(X)[0])
        probas = self.model.predict_proba(X)[0]
        classes = list(self.model.classes_)

        # model.classes_ is ["attack","normal"] or [0,1] depending on training
        # We stored 0=normal, 1=attack in train_model.py
        if 0 in classes:
            p_normal = float(probas[classes.index(0)])
            p_attack = float(probas[classes.index(1)])
        else:
            # string labels fallback
            p_normal = float(probas[classes.index("normal")]) if "normal" in classes else probas[0]
            p_attack = 1.0 - p_normal
            pred = 1 if p_attack > 0.5 else 0

        confidence = max(p_normal, p_attack)
        return pred, confidence, p_normal, p_attack

registry = ModelRegistry()
registry.load()   # attempt load at startup

# ─── Simulation State ────────────────────────────────────────────────────────
class SimulationState:
    running  = False
    thread   = None
    recent_logs: List[Dict[str, Any]] = []
    stats = {
        "packets_processed":   0,
        "intrusions_detected": 0,
        "last_confidence":     0.0,
        "status":              "Idle"
    }

sim_state = SimulationState()

def simulation_worker():
    sim_state.running      = True
    sim_state.stats["status"] = "Monitoring..."

    test_csv = os.path.join(MODEL_DIR, "test_selected.csv")
    if not registry.loaded:
        sim_state.stats["status"] = f"Error: {registry.error}"
        sim_state.running = False
        return

    if not os.path.exists(test_csv):
        sim_state.stats["status"] = "Error: test_selected.csv not found. Run train_model.py."
        sim_state.running = False
        return

    seed = pd.read_csv(test_csv, nrows=300)
    # The CSV has the processed (encoded) format saved by train_model.py
    # For simulation we read the processed numeric rows directly and use model.predict via scaled path
    feature_cols = registry.feature_cols
    label_col    = "label" if "label" in seed.columns else "target"

    numeric_seed = seed.reindex(columns=feature_cols + [label_col], fill_value=0.0)
    normal_seeds = numeric_seed[numeric_seed[label_col] == 0].drop(columns=[label_col])
    attack_seeds = numeric_seed[numeric_seed[label_col] == 1].drop(columns=[label_col])

    while sim_state.running:
        try:
            is_attack = random.random() < 0.22

            if is_attack and not attack_seeds.empty:
                base = attack_seeds.sample(1).copy()
                packet_type = "Suspicious Packet"
            elif not normal_seeds.empty:
                base = normal_seeds.sample(1).copy()
                packet_type = "User Activity"
            else:
                time.sleep(1)
                continue

            # Add realistic noise
            for col in base.columns:
                v = base.at[base.index[0], col]
                if isinstance(v, (int, float)) and v > 1:
                    base.at[base.index[0], col] = v * random.uniform(0.88, 1.12)

            # Scale directly (already encoded)
            X = registry.scaler.transform(base.reindex(columns=feature_cols, fill_value=0.0).values)
            pred_raw   = int(registry.model.predict(X)[0])
            probas     = registry.model.predict_proba(X)[0]
            confidence = float(max(probas))

            # Normalise prediction to 0/1 regardless of model.classes_ type
            classes = list(registry.model.classes_)
            if isinstance(classes[0], str):
                pred = 1 if classes[pred_raw] == "attack" else 0
            else:
                pred = pred_raw

            timestamp = datetime.now().strftime("%H:%M:%S")
            log_entry = {
                "timestamp":   timestamp,
                "packet_type": packet_type,
                "prediction":  "Intrusion" if pred == 1 else "Normal",
                "confidence":  round(confidence, 4),
                "is_alert":    pred == 1,
                "probas": {
                    "normal": round(float(probas[0]), 4),
                    "attack": round(float(probas[1]), 4) if len(probas) > 1 else round(1 - float(probas[0]), 4)
                }
            }

            sim_state.stats["packets_processed"] += 1
            if pred == 1:
                sim_state.stats["intrusions_detected"] += 1
                with open(LOG_FILE, "a") as f:
                    f.write(f"[{timestamp}] ALERT: {packet_type} | conf={confidence:.4f}\n")

            sim_state.stats["last_confidence"] = log_entry["confidence"]
            sim_state.recent_logs.insert(0, log_entry)
            sim_state.recent_logs = sim_state.recent_logs[:50]

            time.sleep(random.uniform(0.4, 1.8))

        except Exception as e:
            print(f"[Sim Worker Error] {e}", flush=True)
            time.sleep(1)

    sim_state.stats["status"] = "Stopped"

# ─── Pydantic Schemas ─────────────────────────────────────────────────────────
class PredictRequest(BaseModel):
    duration: float = 0
    protocol_type: str = "tcp"
    service: str = "http"
    flag: str = "SF"
    src_bytes: float = 0
    dst_bytes: float = 0
    land: float = 0
    wrong_fragment: float = 0
    urgent: float = 0
    hot: float = 0
    num_failed_logins: float = 0
    logged_in: float = 1
    num_compromised: float = 0
    root_shell: float = 0
    su_attempted: float = 0
    num_root: float = 0
    num_file_creations: float = 0
    num_shells: float = 0
    num_access_files: float = 0
    num_outbound_cmds: float = 0
    is_host_login: float = 0
    is_guest_login: float = 0
    count: float = 1
    srv_count: float = 1
    serror_rate: float = 0
    srv_serror_rate: float = 0
    rerror_rate: float = 0
    srv_rerror_rate: float = 0
    same_srv_rate: float = 1
    diff_srv_rate: float = 0
    srv_diff_host_rate: float = 0
    dst_host_count: float = 1
    dst_host_srv_count: float = 1
    dst_host_same_srv_rate: float = 1
    dst_host_diff_srv_rate: float = 0
    dst_host_same_src_port_rate: float = 0
    dst_host_srv_diff_host_rate: float = 0
    dst_host_serror_rate: float = 0
    dst_host_srv_serror_rate: float = 0
    dst_host_rerror_rate: float = 0
    dst_host_srv_rerror_rate: float = 0

# ─── Routes ───────────────────────────────────────────────────────────────────
@app.get("/")
def root():
    return {
        "status": "SentinelNet AI API v2.0 is live",
        "model_loaded": registry.loaded,
        "model_error": registry.error
    }

@app.get("/model/info")
def model_info():
    if not registry.loaded:
        raise HTTPException(status_code=503, detail=registry.error or "Model not loaded")
    return {
        "type": type(registry.model).__name__,
        "n_estimators": registry.model.n_estimators,
        "n_features": len(registry.feature_cols),
        "classes": list(registry.model.classes_),
        "feature_importances_top10": sorted(
            zip(registry.feature_cols, registry.model.feature_importances_),
            key=lambda x: -x[1]
        )[:10]
    }

@app.post("/predict")
def predict(req: PredictRequest):
    if not registry.loaded:
        raise HTTPException(status_code=503, detail=registry.error or "Model not loaded. Run train_model.py first.")
    
    raw = pd.DataFrame([req.model_dump()])
    pred, confidence, p_normal, p_attack = registry.predict(raw)
    return {
        "prediction":   "attack" if pred == 1 else "normal",
        "is_attack":    pred == 1,
        "confidence":   round(confidence, 4),
        "probabilities": {
            "normal": round(p_normal, 4),
            "attack": round(p_attack, 4)
        }
    }

@app.get("/stats")
def get_stats():
    return {
        "live":          sim_state.stats,
        "is_running":    sim_state.running,
        "system_status": sim_state.stats["status"],
        "model_ready":   registry.loaded
    }

@app.get("/logs")
def get_logs():
    return sim_state.recent_logs

@app.post("/simulation/start")
def start_simulation():
    if not registry.loaded:
        raise HTTPException(status_code=503, detail=registry.error or "Train model first.")
    if not sim_state.running:
        t = threading.Thread(target=simulation_worker, daemon=True)
        t.start()
        sim_state.thread = t
        return {"message": "Simulation started", "ok": True}
    return {"message": "Simulation already running", "ok": False}

@app.post("/simulation/stop")
def stop_simulation():
    sim_state.running = False
    return {"message": "Simulation stopping…"}

@app.post("/model/reload")
def reload_model():
    """Hot-reload model artefacts without restarting the server."""
    ok = registry.load()
    if ok:
        return {"message": "Model reloaded successfully", "ok": True}
    raise HTTPException(status_code=500, detail=registry.error)

@app.post("/train")
def trigger_training(background_tasks: BackgroundTasks):
    """Launch train_model.py as a background subprocess."""
    import subprocess
    def run_training():
        sim_state.stats["status"] = "Training in progress…"
        script = os.path.join(os.path.dirname(__file__), "train_model.py")
        try:
            result = subprocess.run(
                [sys.executable, script],
                capture_output=True, text=True, timeout=600
            )
            if result.returncode == 0:
                registry.load()   # reload fresh artefacts
                sim_state.stats["status"] = "Training complete — model reloaded"
            else:
                sim_state.stats["status"] = f"Training failed: {result.stderr[-200:]}"
        except Exception as e:
            sim_state.stats["status"] = f"Training error: {e}"

    background_tasks.add_task(run_training)
    return {"message": "Training started in background. Poll /stats for updates."}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=False)