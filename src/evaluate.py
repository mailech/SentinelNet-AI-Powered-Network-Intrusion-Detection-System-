import pandas as pd
import joblib

from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

# load data
df = pd.read_csv("data/processed/NSL_KDD_Test_Clean.csv")

# remove extra column
df = df.drop("difficulty_level", axis=1)

# target and features
y = df["class"]
X = df.drop("class", axis=1)

# one-hot encoding
X = pd.get_dummies(X)

# load trained model
model = joblib.load("models/nids_model.pkl")

# prediction
pred = model.predict(X)

# accuracy
acc = accuracy_score(y, pred)

print("Test Accuracy:", acc)

print("\nClassification Report:\n")
print(classification_report(y, pred))

print("\nConfusion Matrix:\n")
print(confusion_matrix(y, pred))