import pandas as pd
import joblib
import os

from sklearn.preprocessing import StandardScaler
from sklearn.feature_selection import SelectKBest, f_classif
from sklearn.metrics import classification_report, accuracy_score
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import cross_val_score

# -------------------------------
# 0. Check Working Directory
# -------------------------------
print("Current Working Directory:", os.getcwd())

# -------------------------------
# 1. Load Dataset (CORRECT PATH)
# -------------------------------
print("Loading dataset...")

train_df = pd.read_csv("data/processed/NSL_KDD_Train_Clean.csv")
test_df = pd.read_csv("data/processed/NSL_KDD_Test_Clean.csv")

# -------------------------------
# 2. Split Features & Target
# -------------------------------
X_train = train_df.iloc[:, :-1]
y_train = train_df.iloc[:, -1]

X_test = test_df.iloc[:, :-1]
y_test = test_df.iloc[:, -1]

# -------------------------------
# 3. Handle Categorical Data (IMPORTANT)
# -------------------------------
categorical_cols = X_train.select_dtypes(include=['object']).columns

X_train = pd.get_dummies(X_train, columns=categorical_cols)
X_test = pd.get_dummies(X_test, columns=categorical_cols)

# Align train & test columns
X_train, X_test = X_train.align(X_test, join='left', axis=1, fill_value=0)

# -------------------------------
# 4. Feature Scaling (NO leakage)
# -------------------------------
scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test = scaler.transform(X_test)

# -------------------------------
# 5. Feature Selection
# -------------------------------
selector = SelectKBest(score_func=f_classif, k=20)
X_train = selector.fit_transform(X_train, y_train)
X_test = selector.transform(X_test)

# -------------------------------
# 6. Model (Overfitting Control)
# -------------------------------
print("Training model...")

model = RandomForestClassifier(
    n_estimators=120,
    max_depth=10,
    min_samples_split=5,
    min_samples_leaf=2,
    random_state=42
)

model.fit(X_train, y_train)

# -------------------------------
# 7. Cross Validation
# -------------------------------
cv_scores = cross_val_score(model, X_train, y_train, cv=5)
print("\nCross Validation Accuracy:", cv_scores.mean())

# -------------------------------
# 8. Evaluation (REAL)
# -------------------------------
y_pred = model.predict(X_test)

print("\nTest Accuracy:", accuracy_score(y_test, y_pred))
print("\nClassification Report:\n", classification_report(y_test, y_pred))

# -------------------------------
# 9. Save Model + Preprocessing
# -------------------------------
os.makedirs("model", exist_ok=True)

joblib.dump(model, "model/model.pkl")
joblib.dump(scaler, "model/scaler.pkl")
joblib.dump(selector, "model/selector.pkl")

print("\nModel saved successfully ✅")