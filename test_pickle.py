import sys
import warnings

def warn_with_traceback(message, category, filename, lineno, file=None, line=None):
    print("WARNING:", message)

warnings.showwarning = warn_with_traceback

try:
    import joblib
    model = joblib.load('notebooks/models/best_model.pkl')
    print("Model loaded successfully")
except Exception as e:
    print("Error:", e)
