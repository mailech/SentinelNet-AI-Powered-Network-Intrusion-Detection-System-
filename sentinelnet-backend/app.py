"""
SentinelNet — Production Flask Backend
Network Intrusion Detection API (NSL-KDD / Random Forest)
"""

import os
import logging
import numpy as np
import pandas as pd
import joblib
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from preprocessing import preprocess_input

# ─── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger(__name__)

# ─── App factory ──────────────────────────────────────────────────────────────
def create_app():
    # Get absolute path to static folder (parent directory of backend)
    static_folder = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'static')
    
    app = Flask(__name__, static_folder=static_folder, static_url_path='')
    CORS(app)  # Allow cross-origin requests from your frontend

    # ── Load model artefacts ──────────────────────────────────────────────────
    MODELS_DIR = os.environ.get("MODELS_DIR", "models")

    try:
        app.model          = joblib.load(os.path.join(MODELS_DIR, "model.pkl"))
        app.iso_model      = joblib.load(os.path.join(MODELS_DIR, "iso_model.pkl"))
        app.ohe            = joblib.load(os.path.join(MODELS_DIR, "ohe.pkl"))
        app.service_freq   = joblib.load(os.path.join(MODELS_DIR, "service_freq.pkl"))
        app.scaler         = joblib.load(os.path.join(MODELS_DIR, "scaler.pkl"))
        logger.info("✅ All model artefacts loaded successfully.")
    except FileNotFoundError as e:
        logger.error(f"❌ Could not load model artefact: {e}")
        logger.error("   Run your notebooks first to generate the .pkl files, then place them in models/")
        raise

    # ── Routes ────────────────────────────────────────────────────────────────

    @app.route("/", methods=["GET"])
    def serve_index():
        """Serve index.html from static folder"""
        return send_from_directory(app.static_folder, 'index.html')

    @app.route("/dashboard", methods=["GET"])
    def serve_dashboard():
        """Serve dashboard.html from static folder"""
        return send_from_directory(app.static_folder, 'dashboard.html')

    @app.route("/demo", methods=["GET"])
    def serve_demo():
        """Serve demo.html from static folder"""
        return send_from_directory(app.static_folder, 'demo.html')

    @app.route("/<path:filename>", methods=["GET"])
    def serve_static(filename):
        """Serve static files (HTML, CSS, JS, etc)"""
        try:
            return send_from_directory(app.static_folder, filename)
        except:
            return jsonify({"error": f"File {filename} not found"}), 404

    @app.route("/health", methods=["GET"])
    def health():
        """Liveness probe — used by load balancers and monitoring."""
        return jsonify({"status": "ok", "model": "SentinelNet Random Forest"}), 200

    @app.route("/predict", methods=["POST"])
    def predict():
        """
        POST /predict
        Body: JSON object with the 41 raw NSL-KDD network features.
        Returns: predicted attack class, confidence, per-class probabilities,
                 anomaly score, and a plain-English verdict.
        """
        data = request.get_json(force=True, silent=True)
        if not data:
            return jsonify({"error": "Request body must be valid JSON."}), 400

        try:
            X = preprocess_input(
                raw          = data,
                ohe          = app.ohe,
                service_freq = app.service_freq,
                scaler       = app.scaler,
                model        = app.model,
            )
        except (KeyError, ValueError) as e:
            return jsonify({"error": f"Preprocessing failed: {str(e)}"}), 422

        # ── Main classifier ───────────────────────────────────────────────────
        pred_class   = app.model.predict(X)[0]
        pred_proba   = app.model.predict_proba(X)[0]
        classes      = app.model.classes_.tolist()
        confidence   = float(pred_proba.max())

        # ── Anomaly detector ─────────────────────────────────────────────────
        anomaly_score = float(app.iso_model.decision_function(X)[0])
        is_anomaly    = bool(app.iso_model.predict(X)[0] == -1)

        # ── Verdict string ────────────────────────────────────────────────────
        verdict = _build_verdict(pred_class, confidence, is_anomaly, anomaly_score)

        return jsonify({
            "prediction": {
                "class":         pred_class,
                "confidence":    round(confidence, 4),
                "probabilities": {
                    cls: round(float(p), 4)
                    for cls, p in zip(classes, pred_proba)
                },
            },
            "anomaly": {
                "score":      round(anomaly_score, 4),
                "is_anomaly": is_anomaly,
                "note":       "Lower score = more anomalous",
            },
            "verdict": verdict,
        }), 200

    @app.route("/predict/batch", methods=["POST"])
    def predict_batch():
        """
        POST /predict/batch
        Body: { "records": [ {…}, {…}, … ] }
        Returns predictions for every record in the list.
        Capped at 500 records per request to protect memory.
        """
        data = request.get_json(force=True, silent=True)
        if not data or "records" not in data:
            return jsonify({"error": "Body must contain a 'records' list."}), 400

        records = data["records"]
        if not isinstance(records, list) or len(records) == 0:
            return jsonify({"error": "'records' must be a non-empty list."}), 400
        if len(records) > 500:
            return jsonify({"error": "Batch size capped at 500 records."}), 400

        results = []
        for i, record in enumerate(records):
            try:
                X = preprocess_input(
                    raw          = record,
                    ohe          = app.ohe,
                    service_freq = app.service_freq,
                    scaler       = app.scaler,
                    model        = app.model,
                )
                pred_class  = app.model.predict(X)[0]
                pred_proba  = app.model.predict_proba(X)[0]
                confidence  = float(pred_proba.max())
                anom_score  = float(app.iso_model.decision_function(X)[0])
                is_anomaly  = bool(app.iso_model.predict(X)[0] == -1)
                results.append({
                    "index":      i,
                    "class":      pred_class,
                    "confidence": round(confidence, 4),
                    "anomaly":    round(anom_score, 4),
                    "is_anomaly": is_anomaly,
                    "error":      None,
                })
            except Exception as e:
                results.append({"index": i, "error": str(e)})

        return jsonify({"count": len(results), "results": results}), 200

    @app.route("/features", methods=["GET"])
    def features():
        """Return the list of expected input features and their descriptions."""
        return jsonify({
            "expected_raw_features": RAW_FEATURES,
            "categorical_features": ["protocol_type", "service", "flag"],
            "note": (
                "Send the 41 raw NSL-KDD features. The API handles "
                "all feature engineering and encoding internally."
            ),
        }), 200

    @app.errorhandler(404)
    def not_found(_):
        return jsonify({"error": "Endpoint not found."}), 404

    @app.errorhandler(405)
    def method_not_allowed(_):
        return jsonify({"error": "Method not allowed."}), 405

    @app.errorhandler(500)
    def internal_error(e):
        logger.exception("Unhandled exception")
        return jsonify({"error": "Internal server error."}), 500

    return app


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _build_verdict(pred_class: str, confidence: float, is_anomaly: bool, anomaly_score: float) -> str:
    verdicts = {
        "normal": "✅ Traffic appears normal.",
        "DoS":    "🚨 Denial-of-Service attack detected — connection flooding suspected.",
        "Probe":  "🔍 Probe / reconnaissance activity detected — possible port scan.",
        "R2L":    "⚠️  Remote-to-Local attack detected — unauthorised access attempt.",
        "U2R":    "🔴 User-to-Root privilege escalation detected — critical threat.",
    }
    base = verdicts.get(pred_class, f"⚠️  Unknown class: {pred_class}.")
    conf_tag = f"Confidence: {confidence * 100:.1f}%."
    anom_tag = (
        f" Anomaly detector also flagged this record (score {anomaly_score:.3f})."
        if is_anomaly else ""
    )
    return f"{base} {conf_tag}{anom_tag}"


# ─── Feature reference ────────────────────────────────────────────────────────
RAW_FEATURES = [
    "duration", "protocol_type", "service", "flag",
    "src_bytes", "dst_bytes", "land", "wrong_fragment", "urgent", "hot",
    "num_failed_logins", "logged_in", "num_compromised", "root_shell",
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


# ─── Entry point ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", port=5000, debug=False)
