import os
import joblib
import pandas as pd

from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.ensemble import RandomForestClassifier

# =========================
# PATHS
# =========================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
MODELS_DIR = os.path.join(BASE_DIR, "models")

os.makedirs(MODELS_DIR, exist_ok=True)

# change this if needed
TRAIN_FILE = os.path.join(DATA_DIR, "nsl_kdd_train.csv")

# =========================
# LOAD DATA
# =========================
df = pd.read_csv(TRAIN_FILE, low_memory=False)

# =========================
# AUTO-DETECT TARGET COLUMN
# =========================
possible_targets = ["class", "attack_class", "label", "target"]
target_col = None

for col in possible_targets:
    if col in df.columns:
        target_col = col
        break

if target_col is None:
    raise ValueError(f"Target column not found. Available columns: {list(df.columns)}")

# =========================
# SPLIT X, y
# =========================
y = df[target_col].copy()
X = df.drop(columns=[target_col]).copy()

# optional columns to drop if present
optional_drop_cols = ["difficulty_level", "difficulty", "attack_type"]
for col in optional_drop_cols:
    if col in X.columns:
        X = X.drop(columns=[col])

# =========================
# HANDLE CATEGORICAL COLUMNS
# =========================
categorical_cols = X.select_dtypes(include=["object", "string"]).columns.tolist()
if categorical_cols:
    X = pd.get_dummies(X, columns=categorical_cols)

# convert safely to numeric
X = X.apply(pd.to_numeric, errors="coerce")

# =========================
# LABEL ENCODER
# =========================
le = LabelEncoder()
y_encoded = le.fit_transform(y)

joblib.dump(le, os.path.join(MODELS_DIR, "label_encoder.pkl"))

# =========================
# NUMERIC PIPELINE
# =========================
numeric_pipeline = Pipeline([
    ("imputer", SimpleImputer(strategy="median")),
    ("scaler", StandardScaler())
])

X_processed = numeric_pipeline.fit_transform(X)

joblib.dump(numeric_pipeline, os.path.join(MODELS_DIR, "numeric_pipeline.pkl"))
joblib.dump(numeric_pipeline, os.path.join(MODELS_DIR, "preprocessing_engine.joblib"))

# save training feature order
joblib.dump(list(X.columns), os.path.join(MODELS_DIR, "feature_columns.pkl"))

# =========================
# RANDOM FOREST MODEL
# =========================
rf = RandomForestClassifier(
    n_estimators=200,
    max_depth=12,
    random_state=42,
    n_jobs=-1,
    class_weight="balanced"
)

rf.fit(X_processed, y_encoded)

joblib.dump(rf, os.path.join(MODELS_DIR, "rf_model.joblib"))

print("ALL MODELS CREATED SUCCESSFULLY")
print("Training file:", TRAIN_FILE)
print("Target column used:", target_col)
print("Number of features:", len(X.columns))
print("Saved files:")
print("- label_encoder.pkl")
print("- numeric_pipeline.pkl")
print("- preprocessing_engine.joblib")
print("- feature_columns.pkl")
print("- rf_model.joblib")