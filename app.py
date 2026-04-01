from collections import Counter
from io import BytesIO
from pathlib import Path
import os
import time

import numpy as np
import pandas as pd
from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

PROJECT_RAW_DATA_PATH = "labeled_CSV"
PROJECT_MODEL_DATA_PATH = "log_transformed_train.csv"
STREAM_BATCH_SIZE = 1000

LABEL_CANDIDATES = ["attack_class", "label", "target", "class"]
NON_FEATURE_COLUMNS = [
    "label",
    "attack_class",
    "target",
    "class",
    "difficulty_level",
    "difficulty",
    "is_outlier",
]
NSL_KDD_COLUMNS = [
    "duration",
    "protocol_type",
    "service",
    "flag",
    "src_bytes",
    "dst_bytes",
    "land",
    "wrong_fragment",
    "urgent",
    "hot",
    "num_failed_logins",
    "logged_in",
    "num_compromised",
    "root_shell",
    "su_attempted",
    "num_root",
    "num_file_creations",
    "num_shells",
    "num_access_files",
    "num_outbound_cmds",
    "is_host_login",
    "is_guest_login",
    "count",
    "srv_count",
    "serror_rate",
    "srv_serror_rate",
    "rerror_rate",
    "srv_rerror_rate",
    "same_srv_rate",
    "diff_srv_rate",
    "srv_diff_host_rate",
    "dst_host_count",
    "dst_host_srv_count",
    "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate",
    "dst_host_srv_serror_rate",
    "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate",
    "class",
    "difficulty_level",
]
NSL_KDD_FEATURE_COLUMNS = NSL_KDD_COLUMNS[:-2]
FAMILY_ORDER = ["DoS", "Normal", "Probe", "R2L", "U2R"]
DISPLAY_SEVERITY_SCORES = {
    "Normal": 12.0,
    "Probe": 72.0,
    "R2L": 84.0,
    "U2R": 90.0,
    "DoS": 96.0,
    "Other": 70.0,
}

ATTACK_FAMILY_MAP = {
    "back": "DoS",
    "land": "DoS",
    "neptune": "DoS",
    "pod": "DoS",
    "smurf": "DoS",
    "teardrop": "DoS",
    "apache2": "DoS",
    "mailbomb": "DoS",
    "processtable": "DoS",
    "udpstorm": "DoS",
    "worm": "DoS",
    "ipsweep": "Probe",
    "nmap": "Probe",
    "portsweep": "Probe",
    "satan": "Probe",
    "mscan": "Probe",
    "saint": "Probe",
    "ftp_write": "R2L",
    "guess_passwd": "R2L",
    "imap": "R2L",
    "multihop": "R2L",
    "phf": "R2L",
    "spy": "R2L",
    "warezclient": "R2L",
    "warezmaster": "R2L",
    "xlock": "R2L",
    "xsnoop": "R2L",
    "snmpguess": "R2L",
    "snmpgetattack": "R2L",
    "httptunnel": "R2L",
    "sendmail": "R2L",
    "named": "R2L",
    "buffer_overflow": "U2R",
    "loadmodule": "U2R",
    "perl": "U2R",
    "rootkit": "U2R",
    "ps": "U2R",
    "sqlattack": "U2R",
    "xterm": "U2R",
}
INTEGER_SIGNAL_COLUMNS = [
    "duration",
    "src_bytes",
    "dst_bytes",
    "land",
    "wrong_fragment",
    "urgent",
    "hot",
    "num_failed_logins",
    "logged_in",
    "num_compromised",
    "root_shell",
    "su_attempted",
    "num_root",
    "num_file_creations",
    "num_shells",
    "num_access_files",
    "num_outbound_cmds",
    "is_host_login",
    "is_guest_login",
    "count",
    "srv_count",
    "dst_host_count",
    "dst_host_srv_count",
]


def get_label_column(df: pd.DataFrame) -> str | None:
    for col in LABEL_CANDIDATES:
        if col in df.columns:
            return col
    return None


def normalize_family(label: str) -> str:
    raw = str(label).strip().lower()
    if raw in {"normal", "0", "benign"}:
        return "Normal"
    if raw == "dos":
        return "DoS"
    if raw == "probe":
        return "Probe"
    if raw == "r2l":
        return "R2L"
    if raw == "u2r":
        return "U2R"
    return ATTACK_FAMILY_MAP.get(raw, "Other")


def normalize_schema(df: pd.DataFrame) -> pd.DataFrame:
    normalized = df.copy()
    normalized.columns = [str(col).strip() for col in normalized.columns]

    has_expected_headers = any(
        col in normalized.columns for col in {"duration", "protocol_type", "service", "src_bytes"}
    )
    if not has_expected_headers and normalized.shape[1] in {41, 42, 43}:
        if normalized.shape[1] == 43:
            normalized.columns = NSL_KDD_COLUMNS
        elif normalized.shape[1] == 42:
            normalized.columns = NSL_KDD_FEATURE_COLUMNS + ["difficulty_level"]
        else:
            normalized.columns = NSL_KDD_FEATURE_COLUMNS

    rename_map = {}
    if "label" in normalized.columns and "class" not in normalized.columns:
        rename_map["label"] = "class"
    if "attack_class" in normalized.columns and "class" not in normalized.columns:
        rename_map["attack_class"] = "class"
    if "difficulty" in normalized.columns and "difficulty_level" not in normalized.columns:
        rename_map["difficulty"] = "difficulty_level"
    if rename_map:
        normalized = normalized.rename(columns=rename_map)

    return normalized


def coerce_dataframe_types(df: pd.DataFrame) -> pd.DataFrame:
    normalized = normalize_schema(df).copy()

    for col in normalized.columns:
        if col in {"protocol_type", "service", "flag", "class"}:
            continue
        normalized[col] = pd.to_numeric(normalized[col], errors="coerce")

    for col in ("protocol_type", "service", "flag"):
        if col in normalized.columns:
            normalized[col] = (
                normalized[col]
                .fillna("missing")
                .astype(str)
                .str.strip()
                .str.lower()
            )

    label_col = get_label_column(normalized)
    if label_col:
        normalized[label_col] = normalized[label_col].fillna("unknown").astype(str).str.strip()

    return normalized


def is_probably_log_transformed(df: pd.DataFrame) -> bool:
    for col in INTEGER_SIGNAL_COLUMNS:
        if col not in df.columns:
            continue
        values = pd.to_numeric(df[col].head(1000), errors="coerce").dropna()
        if values.empty:
            continue
        fractional_ratio = ((values - np.round(values)).abs() > 1e-8).mean()
        if fractional_ratio > 0.05:
            return True
    return False


def transform_to_project_model_space(df: pd.DataFrame) -> pd.DataFrame:
    transformed = coerce_dataframe_types(df).copy()

    numeric_cols = [col for col in MODEL_NUMERIC_COLUMNS if col in transformed.columns]
    if numeric_cols and not is_probably_log_transformed(transformed):
        transformed.loc[:, numeric_cols] = np.log1p(transformed[numeric_cols].clip(lower=0))

    return transformed


def build_features(df: pd.DataFrame, fit_mode: bool = False) -> pd.DataFrame:
    base = df.drop(columns=[c for c in NON_FEATURE_COLUMNS if c in df.columns], errors="ignore").copy()

    for col in base.select_dtypes(include="object").columns:
        base[col] = base[col].fillna("missing").astype(str).str.strip().str.lower()

    features = pd.get_dummies(base, dtype=np.uint8)
    if fit_mode:
        return features.astype(np.float32)
    return features.reindex(columns=train_columns, fill_value=0).astype(np.float32)


def build_stats(labels: np.ndarray, source_df: pd.DataFrame) -> dict:
    families = [normalize_family(x) for x in labels]
    family_counter = Counter(families)

    total = len(families)
    normal_count = int(family_counter.get("Normal", 0))
    attacks = total - normal_count

    category_breakdown = {family: int(family_counter.get(family, 0)) for family in FAMILY_ORDER}
    threats_only = Counter({k: v for k, v in family_counter.items() if k != "Normal"})
    attack_breakdown = [
        {"name": name, "count": int(count)}
        for name, count in threats_only.most_common()
        if name in FAMILY_ORDER
    ]

    risk_status = "Safe"
    if total > 0 and attacks > total * 0.1:
        risk_status = "Medium"
    if total > 0 and attacks > total * 0.3:
        risk_status = "High"

    protocols = {}
    if "protocol_type" in source_df.columns:
        protocol_series = source_df["protocol_type"].fillna("unknown").astype(str).str.upper()
        protocols = {str(k): int(v) for k, v in protocol_series.value_counts().items()}

    return {
        "total": int(total),
        "attacks": int(attacks),
        "normal": int(normal_count),
        "breakdown": category_breakdown,
        "risk_status": risk_status,
        "top_threats": attack_breakdown[:5],
        "attack_breakdown": attack_breakdown,
        "category_breakdown": category_breakdown,
        "protocols": protocols,
    }


def run_inference(source_df: pd.DataFrame) -> tuple[np.ndarray, np.ndarray]:
    model_df = transform_to_project_model_space(source_df)
    X = build_features(model_df, fit_mode=False)

    pred_encoded = model.predict(X)
    raw_pred_labels = le.inverse_transform(pred_encoded).astype(str)
    pred_families = np.array([normalize_family(x) for x in raw_pred_labels], dtype=object)

    if hasattr(model, "predict_proba"):
        confidence_scores = (model.predict_proba(X).max(axis=1) * 100.0).astype(float)
    else:
        confidence_scores = np.full(shape=len(source_df), fill_value=50.0, dtype=float)

    return pred_families, np.round(confidence_scores, 2)


def scores_from_labels(labels: np.ndarray) -> np.ndarray:
    return np.array(
        [DISPLAY_SEVERITY_SCORES.get(str(label), DISPLAY_SEVERITY_SCORES["Other"]) for label in labels],
        dtype=float,
    )


def parse_uploaded_table(filename: str, raw_bytes: bytes) -> pd.DataFrame:
    suffix = Path(filename or "").suffix.lower()
    last_error = None

    if suffix in {".xlsx", ".xls"}:
        try:
            return pd.read_excel(BytesIO(raw_bytes))
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"Failed to read Excel: {exc}")

    try:
        df = pd.read_csv(BytesIO(raw_bytes))
        if df is not None and not df.empty:
            if not any(col in map(str, df.columns) for col in {"duration", "protocol_type", "src_bytes", "label", "class"}):
                if df.shape[1] in {41, 42, 43}:
                    return pd.read_csv(BytesIO(raw_bytes), header=None)
            return df
    except Exception as exc:
        last_error = exc

    try:
        df = pd.read_csv(BytesIO(raw_bytes), header=None)
        if df is not None and not df.empty:
            return df
    except Exception as exc:
        last_error = exc

    raise HTTPException(status_code=400, detail=f"Unsupported or invalid file format: {last_error}")


def extract_packet_size(row: pd.Series, is_log_scaled: bool) -> int:
    for column in ("src_bytes", "dst_bytes"):
        if column not in row or pd.isna(row[column]):
            continue
        value = float(row[column])
        if is_log_scaled:
            value = float(np.expm1(value))
        packet_size = int(round(value))
        if packet_size > 0:
            return packet_size
    return 512


def load_project_dataframe(path: str) -> pd.DataFrame:
    return coerce_dataframe_types(pd.read_csv(path))


# ======================
# LOAD DATA & MODEL
# ======================
print("Loading SentinelNet project datasets...")
train_raw_df = load_project_dataframe(PROJECT_RAW_DATA_PATH)
train_model_df = load_project_dataframe(PROJECT_MODEL_DATA_PATH)

train_label_col = get_label_column(train_model_df)
if not train_label_col:
    raise RuntimeError(f"No target column found. Expected one of: {LABEL_CANDIDATES}")

MODEL_NUMERIC_COLUMNS = [
    col
    for col in train_raw_df.columns
    if col not in NON_FEATURE_COLUMNS
    and col not in {"protocol_type", "service", "flag"}
    and pd.api.types.is_numeric_dtype(train_raw_df[col])
]

print(f"Training label column: {train_label_col}")
X_train = build_features(train_model_df, fit_mode=True)
train_columns = X_train.columns

le = LabelEncoder()
y_train = le.fit_transform(train_model_df[train_label_col].astype(str))

print("Training SentinelNet inference model...")
model = RandomForestClassifier(n_estimators=20, max_depth=12, random_state=42, n_jobs=-1)
model.fit(X_train, y_train)
print("Model ready.")

# Active state
active_df = train_raw_df.copy()
active_preds = np.array([normalize_family(x) for x in train_raw_df["class"].astype(str).values], dtype=object)
active_confidences = scores_from_labels(active_preds)
active_stats = build_stats(active_preds, active_df)
active_source_name = PROJECT_RAW_DATA_PATH
active_source_is_log_scaled = False
stream_index = 0


# ======================
# SERVE UI
# ======================
@app.get("/", response_class=HTMLResponse)
async def serve_ui():
    with open("templates/index.html", "r", encoding="utf-8") as f:
        return f.read()


# ======================
# DATASET/UPLOAD API
# ======================
@app.get("/dataset-stats")
async def get_dataset_stats():
    return {
        "has_data": True,
        "source_name": active_source_name,
        **active_stats,
    }


# ======================
# REAL-TIME LIVE FEED
# ======================
@app.get("/live-feed")
async def live_feed():
    global stream_index

    if len(active_df) == 0:
        empty_breakdown = {family: 0 for family in FAMILY_ORDER}
        return {
            "packets": [],
            "batch_summary": {"total": 0, "attacks": 0, "normal": 0, "attack_rate": 0.0},
            "live_summary": {"total": 0, "attacks": 0, "normal": 0, "category_breakdown": empty_breakdown},
        }

    if stream_index >= len(active_df):
        stream_index = 0

    end_index = min(stream_index + STREAM_BATCH_SIZE, len(active_df))
    rows = active_df.iloc[stream_index:end_index]
    batch_preds = active_preds[stream_index:end_index]
    batch_confidences = active_confidences[stream_index:end_index]

    packets = []
    for offset, (_, row) in enumerate(rows.iterrows()):
        family = str(batch_preds[offset])
        confidence = float(batch_confidences[offset])
        idx_in_df = stream_index + offset

        packets.append(
            {
                "timestamp": time.strftime("%H:%M:%S"),
                "packet_size": extract_packet_size(row, active_source_is_log_scaled),
                "src_ip": f"192.168.1.{idx_in_df % 254 + 1}",
                "dst_ip": f"10.0.0.{(idx_in_df * 2) % 254 + 1}",
                "confidence": round(confidence, 2),
                "prediction": family,
                "is_normal": family == "Normal",
            }
        )

    batch_total = len(packets)
    batch_attacks = int(np.sum(batch_preds != "Normal"))
    batch_normal = int(batch_total - batch_attacks)

    stream_index = end_index

    return {
        "packets": packets,
        "batch_summary": {
            "total": int(batch_total),
            "attacks": batch_attacks,
            "normal": batch_normal,
            "attack_rate": round((batch_attacks / batch_total) * 100.0, 2) if batch_total else 0.0,
        },
        "live_summary": {
            "total": active_stats["total"],
            "attacks": active_stats["attacks"],
            "normal": active_stats["normal"],
            "category_breakdown": active_stats["category_breakdown"],
        },
    }


# ======================
# FILE UPLOAD API
# ======================
@app.post("/analyze")
async def analyze(file: UploadFile = File(...)):
    global active_df, active_preds, active_confidences, active_stats
    global active_source_name, active_source_is_log_scaled, stream_index

    started_at = time.perf_counter()
    raw_bytes = await file.read()
    if not raw_bytes:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    source_df = coerce_dataframe_types(parse_uploaded_table(file.filename or "", raw_bytes))
    if source_df.empty:
        raise HTTPException(status_code=400, detail="Uploaded file has no rows.")

    label_col = get_label_column(source_df)
    if label_col:
        active_preds = np.array([normalize_family(x) for x in source_df[label_col].astype(str).values], dtype=object)
        active_confidences = scores_from_labels(active_preds)
        analysis_mode = "ground_truth"
    else:
        active_preds, active_confidences = run_inference(source_df)
        analysis_mode = "predicted"

    active_df = source_df.copy()
    active_stats = build_stats(active_preds, active_df)
    active_source_name = file.filename or "uploaded-file"
    active_source_is_log_scaled = is_probably_log_transformed(active_df)
    stream_index = 0

    analysis_seconds = round(time.perf_counter() - started_at, 3)

    return {
        "source_name": active_source_name,
        "analysis_mode": analysis_mode,
        "analysis_seconds": analysis_seconds,
        **active_stats,
        "live_summary": {
            "total": active_stats["total"],
            "attacks": active_stats["attacks"],
            "normal": active_stats["normal"],
            "category_breakdown": active_stats["category_breakdown"],
        },
    }


# ======================
# AI ANALYSIS API
# ======================
@app.post("/ai-analysis")
async def ai_analysis(request: Request):
    try:
        data = await request.json()
        threats = data.get("threats", [])
    except Exception:
        threats = ["Unknown"]

    threats_str = ", ".join(threats) if threats else "None detected"
    prompt = (
        "Analyze these network threat classes detected by our IDS and provide brief mitigation tips: "
        f"{threats_str}"
    )

    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        return {
            "analysis": (
                f"AI Analysis Engine (Offline Template): Detected patterns ({threats_str}). "
                "Mitigation Strategies: 1) Deploy strict IPS filtering against signature overlaps. "
                "2) Implement geo-blocking for anomalous origin IPs. "
                "3) Configure automated quarantine protocols scaling with Threat Density."
            )
        }

    try:
        from openai import OpenAI

        client = OpenAI(api_key=api_key)
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {
                    "role": "system",
                    "content": "You are a cybersecurity expert analyzing network threats. Keep it brief.",
                },
                {"role": "user", "content": prompt},
            ],
        )
        return {"analysis": response.choices[0].message.content}
    except Exception as exc:
        return {"analysis": f"OpenAI API Error: {str(exc)}"}
