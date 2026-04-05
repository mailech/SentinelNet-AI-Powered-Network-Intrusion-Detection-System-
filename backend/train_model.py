"""
SentinelNet – Network Intrusion Detection Model Trainer
=======================================================
Trains a Random Forest classifier on the NSL-KDD dataset.
Saves three artefacts to ../models/:
  - rf_model.pkl          : trained RandomForestClassifier
  - scaler.pkl            : fitted RobustScaler
  - encoder.pkl           : fitted OneHotEncoder
  - feature_names.pkl     : ordered list of feature columns expected at inference
  - test_selected.csv     : 500-row sample of processed test data for the simulator

Run this script once from the backend/ directory:
    python train_model.py
"""

import os
import sys
import time
import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import RobustScaler, OneHotEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, classification_report, confusion_matrix
)

# ─── Paths ───────────────────────────────────────────────────────────────────
SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
BASE_DIR    = os.path.dirname(SCRIPT_DIR)                     # SentinelNet/
DATA_DIR    = os.path.join(BASE_DIR, "data")
MODEL_DIR   = os.path.join(BASE_DIR, "models")
os.makedirs(MODEL_DIR, exist_ok=True)

TRAIN_FILE  = os.path.join(DATA_DIR, "KDDTrain+.txt")
TEST_FILE   = os.path.join(DATA_DIR, "KDDTest+.txt")

# ─── Column names (NSL-KDD 42 columns) ───────────────────────────────────────
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

CATEGORICAL = ["protocol_type", "service", "flag"]

def load_and_label(path: str) -> pd.DataFrame:
    df = pd.read_csv(path, header=None, names=COL_NAMES)
    # Binary target: 0 = normal, 1 = attack
    df["target"] = df["label"].apply(lambda x: 0 if x.strip() == "normal" else 1)
    df.drop(columns=["label", "difficulty_level"], inplace=True)
    return df

def log(msg: str):
    ts = time.strftime("%H:%M:%S")
    print(f"[{ts}] {msg}", flush=True)

def main():
    log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    log("  SentinelNet – Model Training Pipeline     ")
    log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

    # ── 1. Load data ──────────────────────────────────────────────────────────
    log(f"Loading training data from: {TRAIN_FILE}")
    if not os.path.exists(TRAIN_FILE):
        print(f"ERROR: Training file not found at {TRAIN_FILE}", file=sys.stderr)
        sys.exit(1)

    train_df = load_and_label(TRAIN_FILE)
    log(f"  → Train rows: {len(train_df):,}   (attack: {train_df['target'].sum():,}  |  normal: {(train_df['target']==0).sum():,})")

    has_test = os.path.exists(TEST_FILE)
    if has_test:
        log(f"Loading test data from: {TEST_FILE}")
        test_df = load_and_label(TEST_FILE)
        log(f"  → Test rows:  {len(test_df):,}")
    else:
        log("  → No separate test file found; will use train split only.")
        test_df = None

    # ── 2. Encode categoricals ────────────────────────────────────────────────
    log("Fitting OneHotEncoder on categorical columns …")
    encoder = OneHotEncoder(sparse_output=False, handle_unknown="ignore")
    encoder.fit(train_df[CATEGORICAL])

    def apply_encoder(df, enc):
        encoded = pd.DataFrame(
            enc.transform(df[CATEGORICAL]),
            columns=enc.get_feature_names_out(CATEGORICAL),
            index=df.index
        )
        df = pd.concat([df.drop(columns=CATEGORICAL), encoded], axis=1)
        return df

    train_df = apply_encoder(train_df, encoder)
    if test_df is not None:
        test_df = apply_encoder(test_df, encoder)

    # ── 3. Features / target split ────────────────────────────────────────────
    feature_cols = [c for c in train_df.columns if c != "target"]
    X = train_df[feature_cols].values
    y = train_df["target"].values

    # ── 4. Scale ──────────────────────────────────────────────────────────────
    log("Fitting RobustScaler …")
    scaler = RobustScaler()
    X_scaled = scaler.fit_transform(X)

    # ── 5. Train / validation split ───────────────────────────────────────────
    log("Splitting into 80/20 train-validation sets …")
    X_train, X_val, y_train, y_val = train_test_split(
        X_scaled, y, test_size=0.20, random_state=42, stratify=y
    )
    log(f"  → Train: {len(X_train):,}   Val: {len(X_val):,}")

    # ── 6. Train Random Forest ────────────────────────────────────────────────
    log("Training RandomForestClassifier (150 trees, all CPUs) …")
    t0 = time.time()
    rf = RandomForestClassifier(
        n_estimators=150,
        max_depth=None,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
        verbose=0
    )
    rf.fit(X_train, y_train)
    elapsed = time.time() - t0
    log(f"  → Training complete in {elapsed:.1f}s")

    # ── 7. Evaluate ───────────────────────────────────────────────────────────
    log("Evaluating on validation set …")
    y_pred = rf.predict(X_val)
    acc = accuracy_score(y_val, y_pred)
    log(f"  → Validation Accuracy: {acc * 100:.4f}%")
    print()
    print(classification_report(y_val, y_pred, target_names=["normal", "attack"]))

    # Evaluate on separate test set if available
    if test_df is not None:
        log("Evaluating on NSL-KDD+ test set …")
        X_test_raw = test_df[feature_cols].values
        X_test_scaled = scaler.transform(X_test_raw)
        y_test = test_df["target"].values
        y_test_pred = rf.predict(X_test_scaled)
        test_acc = accuracy_score(y_test, y_test_pred)
        log(f"  → Test Set Accuracy:  {test_acc * 100:.4f}%")
        print()
        print(classification_report(y_test, y_test_pred, target_names=["normal", "attack"]))

    # ── 8. Save artefacts ─────────────────────────────────────────────────────
    log("Saving model artefacts to models/ directory …")

    model_path        = os.path.join(MODEL_DIR, "rf_model.pkl")
    scaler_path       = os.path.join(MODEL_DIR, "scaler.pkl")
    encoder_path      = os.path.join(MODEL_DIR, "encoder.pkl")
    features_path     = os.path.join(MODEL_DIR, "feature_names.pkl")
    test_sample_path  = os.path.join(MODEL_DIR, "test_selected.csv")

    joblib.dump(rf,           model_path,    compress=3)
    joblib.dump(scaler,       scaler_path,   compress=3)
    joblib.dump(encoder,      encoder_path,  compress=3)
    joblib.dump(feature_cols, features_path, compress=1)

    log(f"  ✔  rf_model.pkl      → {model_path}")
    log(f"  ✔  scaler.pkl        → {scaler_path}")
    log(f"  ✔  encoder.pkl       → {encoder_path}")
    log(f"  ✔  feature_names.pkl → {features_path}")

    # Save a 500-row labeled test sample in processed (scaled) form for the simulator
    # We store the UNSCALED processed numeric values so the simulator can add noise
    sample_df = test_df if test_df is not None else train_df
    sample = sample_df.sample(min(500, len(sample_df)), random_state=42).copy()
    sample.rename(columns={"target": "label"}, inplace=True)
    sample.to_csv(test_sample_path, index=False)
    log(f"  ✔  test_selected.csv → {test_sample_path}")

    log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    log("  All done! Run 'python main.py' to start   ")
    log("  the FastAPI backend with the trained model.")
    log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

if __name__ == "__main__":
    main()
