import numpy as np
import pandas as pd

RAW_NUMERIC = [
    "duration", "src_bytes", "dst_bytes", "land", "wrong_fragment", "urgent",
    "hot", "num_failed_logins", "logged_in", "num_compromised", "root_shell",
    "su_attempted", "num_root", "num_file_creations", "num_shells",
    "num_access_files", "num_outbound_cmds", "is_host_login", "is_guest_login",
    "count", "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate",
    "srv_rerror_rate", "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate",
    "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
    "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate",
]

CATEGORICAL = ["protocol_type", "service", "flag"]
SKEWED_COLS = ["duration", "src_bytes", "dst_bytes"]
OHE_COLS    = ["protocol_type", "flag"]
ERROR_FLAGS = {"S0", "S1", "S2", "S3", "REJ"}


def preprocess_input(raw, ohe, service_freq, scaler, model):
    """
    Transform a raw NSL-KDD dict into a DataFrame ready for model.predict().

    Parameters
    ----------
    raw          : dict with the 41 raw NSL-KDD fields
    ohe          : fitted OneHotEncoder
    service_freq : dict  service_name -> training frequency
    scaler       : fitted RobustScaler
    model        : the trained RandomForestClassifier
                   (used for its feature_names_in_ — the authoritative column order)
    """
    # Canonical column order comes from the model itself — never from a separate pkl
    model_cols = list(model.feature_names_in_)

    df = _validate_and_cast(raw)
    df = _log_transform(df)
    df = _engineer_features(df)
    df = _encode_categoricals(df, ohe, service_freq)

    # Align to model's exact column order; missing cols → 0, extras dropped
    df = df.reindex(columns=model_cols, fill_value=0)

    # Scale using scaler's own column list (subset of model_cols, excludes is_outlier)
    scale_cols = list(scaler.feature_names_in_)
    present    = [c for c in scale_cols if c in df.columns]
    df[present] = scaler.transform(df[present])

    return df


def _validate_and_cast(raw):
    df = pd.DataFrame([raw])
    for col in RAW_NUMERIC:
        if col not in df.columns:
            raise KeyError(f"Missing required field: '{col}'")
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)
    for col in CATEGORICAL:
        if col not in df.columns:
            raise KeyError(f"Missing required categorical field: '{col}'")
        df[col] = df[col].astype(str).str.strip()
    # protocol_type trained lowercase; flag is uppercase (SF/S0/REJ)
    df["protocol_type"] = df["protocol_type"].str.lower()
    return df


def _log_transform(df):
    for col in SKEWED_COLS:
        df[f"log_{col}"] = np.log1p(df[col])
    return df


def _engineer_features(df):
    df["total_bytes"]          = df["src_bytes"] + df["dst_bytes"]
    df["src_bytes_ratio"]      = df["src_bytes"] / (df["total_bytes"] + 1e-5)
    df["packet_rate"]          = df["count"] / (df["duration"] + 1e-5)
    df["byte_diff"]            = np.abs(df["src_bytes"] - df["dst_bytes"])
    df["is_error_flag"]        = df["flag"].isin(ERROR_FLAGS).astype(int)
    df["same_srv_interaction"]  = df["same_srv_rate"] * df["dst_host_same_srv_rate"]
    df["is_outlier"]           = 0
    return df


def _encode_categoricals(df, ohe, service_freq):
    ohe_arr  = ohe.transform(df[OHE_COLS])
    ohe_cols = ohe.get_feature_names_out(OHE_COLS)
    ohe_df   = pd.DataFrame(ohe_arr, columns=ohe_cols, index=df.index)
    df["service_freq"] = df["service"].map(service_freq).fillna(0)
    df = pd.concat([df, ohe_df], axis=1)
    df.drop(columns=["protocol_type", "flag", "service"], inplace=True)
    return df
