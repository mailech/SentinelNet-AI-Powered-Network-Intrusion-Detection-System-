import io
import os
import sqlite3
import time
import threading
from functools import wraps

import pandas as pd
from flask import Flask, render_template, request, redirect, url_for, flash, send_file, session, jsonify
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from werkzeug.security import generate_password_hash, check_password_hash

from utils.predictor import predict_from_file, predict_dataframe
from sniffer import start_sniffing
from live_features import build_live_feature_row

app = Flask(__name__)
app.secret_key = "ai_sentinel_secret"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
OUTPUT_FOLDER = os.path.join(BASE_DIR, "outputs")
INSTANCE_FOLDER = os.path.join(BASE_DIR, "instance")
DB_PATH = os.path.join(INSTANCE_FOLDER, "users.db")

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_FOLDER, exist_ok=True)
os.makedirs(INSTANCE_FOLDER, exist_ok=True)

LIVE_STATE = {
    "file_path": None,
    "cursor": 0,
    "chunk_size": 20
}

SIMULATION_STATE = {
    "attack_mode": False
}


# =========================
# DATABASE
# =========================
def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


init_db()


# =========================
# START MOBILE TRAFFIC SNIFFER
# =========================
threading.Thread(
    target=start_sniffing,
    kwargs={"interface": "Wi-Fi"},   # change if needed
    daemon=True
).start()


# =========================
# AUTH
# =========================
def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "user_email" not in session:
            flash("Please login first.")
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper


# =========================
# UI HELPERS
# =========================
def heat_class(score):
    if score >= 90:
        return "heat-high"
    if score >= 75:
        return "heat-good"
    if score >= 50:
        return "heat-medium"
    return "heat-low"


def badge(score):
    if score >= 90:
        return "Critical"
    if score >= 75:
        return "High"
    if score >= 50:
        return "Medium"
    return "Low"


def build_alerts(df):
    if df.empty or "threat_status" not in df.columns:
        return [{
            "title": "System Stable",
            "message": "No data available.",
            "severity": "low",
            "x": 50,
            "y": 50,
            "place": "Core Zone"
        }]

    threat_df = df[df["threat_status"] == "Threat"].copy()

    if threat_df.empty:
        return [{
            "title": "System Stable",
            "message": "No major threats detected.",
            "severity": "low",
            "x": 50,
            "y": 50,
            "place": "Core Zone"
        }]

    grouped = (
        threat_df.groupby("predicted_class")
        .agg(
            count=("predicted_class", "size"),
            peak_confidence=("confidence", "max")
        )
        .reset_index()
        .sort_values(by="peak_confidence", ascending=False)
    )

    fake_places = [
        ("North Gateway", 18, 18),
        ("East Node", 78, 25),
        ("South Cluster", 68, 78),
        ("West Access", 15, 65),
        ("Core Network", 50, 50),
        ("Remote Edge", 85, 60),
        ("Cloud Zone", 62, 22),
        ("Backup Node", 30, 75),
    ]

    alerts = []

    for i, row in enumerate(grouped.head(8).itertuples(index=False)):
        attack_name = str(row.predicted_class)
        count = int(row.count)
        score = float(row.peak_confidence)

        if score >= 90:
            severity = "high"
        elif score >= 75:
            severity = "medium"
        else:
            severity = "low"

        place, x, y = fake_places[i % len(fake_places)]

        alerts.append({
            "title": f"{attack_name} detected",
            "message": f"Location: {place} | Count: {count} | Peak Confidence: {score:.2f}%",
            "severity": severity,
            "x": x,
            "y": y,
            "place": place
        })

    return alerts


def build_dashboard_data(full_df, display_df):
    total_logs = len(full_df)
    total_threats = int((full_df["threat_status"] == "Threat").sum()) if "threat_status" in full_df.columns else 0
    total_safe = int((full_df["threat_status"] == "Normal").sum()) if "threat_status" in full_df.columns else 0
    threat_percentage = round((total_threats / total_logs) * 100, 2) if total_logs else 0
    safe_percentage = round((total_safe / total_logs) * 100, 2) if total_logs else 0
    avg_confidence = round(full_df["confidence"].mean(), 2) if "confidence" in full_df.columns and len(full_df) else 0

    threat_df = full_df[full_df["threat_status"] == "Threat"] if "threat_status" in full_df.columns else pd.DataFrame()
    top_attack = threat_df["predicted_class"].value_counts().idxmax() if not threat_df.empty else "normal"

    class_counts = full_df["predicted_class"].value_counts().to_dict() if "predicted_class" in full_df.columns else {}
    alerts = build_alerts(full_df)

    cards = []
    for i, (_, row) in enumerate(threat_df.head(8).iterrows(), start=1):
        score = float(row["confidence"])
        cards.append({
            "name": f"Record {i}",
            "attack_type": row["predicted_class"],
            "score": round(score, 2),
            "badge": badge(score),
            "heat_class": heat_class(score)
        })

    display_rows = display_df.head(20).copy()
    if "confidence" in display_rows.columns:
        display_rows["heat_class"] = display_rows["confidence"].apply(heat_class)
    else:
        display_rows["heat_class"] = "heat-low"

    return {
        "total_logs": total_logs,
        "total_threats": total_threats,
        "total_safe": total_safe,
        "threat_percentage": threat_percentage,
        "safe_percentage": safe_percentage,
        "avg_confidence": avg_confidence,
        "top_attack": top_attack,
        "chart_labels": list(class_counts.keys()),
        "chart_values": list(class_counts.values()),
        "alerts": alerts,
        "cards": cards,
        "rows": display_rows.to_dict(orient="records")
    }


# =========================
# ROUTES
# =========================
@app.route("/")
def index():
    if "user_email" in session:
        return redirect(url_for("home"))
    return redirect(url_for("login"))


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "").strip()

        if not name or not email or not password:
            flash("All fields are required.")
            return redirect(url_for("signup"))

        conn = get_db_connection()
        existing_user = conn.execute(
            "SELECT * FROM users WHERE email = ?",
            (email,)
        ).fetchone()

        if existing_user:
            conn.close()
            flash("Account already exists. Please login.")
            return redirect(url_for("login"))

        password_hash = generate_password_hash(password)

        conn.execute(
            "INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)",
            (name, email, password_hash)
        )
        conn.commit()
        conn.close()

        flash("Account created successfully. Please login.")
        return redirect(url_for("login"))

    return render_template("signup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "").strip()

        conn = get_db_connection()
        user = conn.execute(
            "SELECT * FROM users WHERE email = ?",
            (email,)
        ).fetchone()
        conn.close()

        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            session["user_name"] = user["name"]
            session["user_email"] = user["email"]
            flash("Login successful.")
            return redirect(url_for("home"))

        flash("Invalid email or password.")
        return redirect(url_for("login"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully.")
    return redirect(url_for("login"))


@app.route("/home")
@login_required
def home():
    return render_template("home.html")


@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    if request.method == "POST":
        file = request.files.get("dataset")

        if not file or file.filename == "":
            flash("Please upload a valid CSV file.")
            return redirect(url_for("upload"))

        save_path = os.path.join(UPLOAD_FOLDER, file.filename)
        file.save(save_path)

        try:
            full_result_df, display_result_df = predict_from_file(save_path)

            csv_path = os.path.join(OUTPUT_FOLDER, "prediction_results.csv")
            full_result_df.to_csv(csv_path, index=False)

            session["dashboard_data"] = build_dashboard_data(full_result_df, display_result_df)

            LIVE_STATE["file_path"] = save_path
            LIVE_STATE["cursor"] = 0

            flash("Analysis completed successfully.")
            return redirect(url_for("dashboard"))

        except Exception as e:
            flash(f"Error: {e}")
            return redirect(url_for("upload"))

    return render_template("upload.html")


@app.route("/dashboard")
@login_required
def dashboard():
    data = session.get("dashboard_data")
    if not data:
        flash("Upload dataset first.")
        return redirect(url_for("upload"))

    return render_template(
        "dashboard.html",
        total_logs=data.get("total_logs", 0),
        total_threats=data.get("total_threats", 0),
        total_safe=data.get("total_safe", 0),
        threat_percentage=data.get("threat_percentage", 0),
        safe_percentage=data.get("safe_percentage", 0),
        avg_confidence=data.get("avg_confidence", 0),
        top_attack=data.get("top_attack", "No data"),
        chart_labels=data.get("chart_labels", []),
        chart_values=data.get("chart_values", []),
        alerts=data.get("alerts", []),
        cards=data.get("cards", []),
        rows=data.get("rows", [])
    )


@app.route("/alerts")
@login_required
def alerts():
    data = session.get("dashboard_data")
    if not data:
        flash("Upload dataset first.")
        return redirect(url_for("upload"))
    return render_template("alerts.html", alerts=data.get("alerts", []))


@app.route("/live")
@login_required
def live():
    return render_template("live.html")


@app.route("/api/toggle-attack", methods=["POST"])
@login_required
def toggle_attack():
    SIMULATION_STATE["attack_mode"] = not SIMULATION_STATE["attack_mode"]
    return jsonify({
        "attack_mode": SIMULATION_STATE["attack_mode"]
    })


@app.route("/api/attack-status")
@login_required
def attack_status():
    return jsonify({
        "attack_mode": SIMULATION_STATE["attack_mode"]
    })


@app.route("/api/live-predict")
@login_required
def api_live_predict():
    file_path = LIVE_STATE.get("file_path")

    if not file_path or not os.path.exists(file_path):
        return jsonify({
            "time": time.strftime("%H:%M:%S"),
            "alerts": [],
            "rows": [],
            "total_logs": 0,
            "total_threats": 0,
            "total_safe": 0,
            "top_attack": "No data"
        })

    try:
        df = pd.read_csv(file_path, low_memory=False)

        start = LIVE_STATE.get("cursor", 0)
        chunk_size = LIVE_STATE.get("chunk_size", 20)
        end = start + chunk_size

        chunk_df = df.iloc[start:end].copy()

        if chunk_df.empty:
            LIVE_STATE["cursor"] = 0
            start = 0
            end = chunk_size
            chunk_df = df.iloc[start:end].copy()

        LIVE_STATE["cursor"] = end

        full_result_df, display_result_df = predict_dataframe(chunk_df)

        total_logs = len(full_result_df)
        total_threats = int((full_result_df["threat_status"] == "Threat").sum())
        total_safe = int((full_result_df["threat_status"] == "Normal").sum())

        threat_df = full_result_df[full_result_df["threat_status"] == "Threat"]
        top_attack = (
            threat_df["predicted_class"].value_counts().idxmax()
            if not threat_df.empty else "normal"
        )

        alerts = build_alerts(full_result_df)
        rows = display_result_df.head(10).to_dict(orient="records")

        return jsonify({
            "time": time.strftime("%H:%M:%S"),
            "alerts": alerts,
            "rows": rows,
            "total_logs": total_logs,
            "total_threats": total_threats,
            "total_safe": total_safe,
            "top_attack": top_attack
        })

    except Exception as e:
        return jsonify({
            "time": time.strftime("%H:%M:%S"),
            "alerts": [{
                "title": "Prediction Error",
                "message": str(e),
                "severity": "high",
                "x": 50,
                "y": 50,
                "place": "Error Zone"
            }],
            "rows": [],
            "total_logs": 0,
            "total_threats": 0,
            "total_safe": 0,
            "top_attack": "Error"
        })


@app.route("/api/mobile-live")
@login_required
def api_mobile_live():
    try:
        live_df, sniffer_error = build_live_feature_row()

        # =========================
        # REAL PACKET MODE
        # =========================
        if not sniffer_error and not live_df.empty:
            live_df = live_df.copy()

            # DEMO ATTACK MODE
            if SIMULATION_STATE["attack_mode"]:
                if "src_bytes" in live_df.columns:
                    live_df["src_bytes"] = live_df["src_bytes"] * 15
                if "dst_bytes" in live_df.columns:
                    live_df["dst_bytes"] = live_df["dst_bytes"] * 12
                if "count" in live_df.columns:
                    live_df["count"] = live_df["count"] + 20
                if "srv_count" in live_df.columns:
                    live_df["srv_count"] = live_df["srv_count"] + 15
                if "tcp_count" in live_df.columns:
                    live_df["tcp_count"] = live_df["tcp_count"] + 10

            full_result_df, display_result_df = predict_dataframe(live_df)

            # Force visible attack output for demo mode
            if SIMULATION_STATE["attack_mode"] and not full_result_df.empty:
                full_result_df = full_result_df.copy()
                display_result_df = display_result_df.copy()

                full_result_df["predicted_class"] = "dos"
                full_result_df["confidence"] = 96.45
                full_result_df["threat_status"] = "Threat"

                display_result_df["predicted_class"] = "dos"
                display_result_df["confidence"] = 96.45
                display_result_df["threat_status"] = "Threat"

            total_logs = len(full_result_df)
            total_threats = int((full_result_df["threat_status"] == "Threat").sum())
            total_safe = int((full_result_df["threat_status"] == "Normal").sum())

            alerts = build_alerts(full_result_df)

            threat_df = full_result_df[full_result_df["threat_status"] == "Threat"]
            top_attack = (
                threat_df["predicted_class"].value_counts().idxmax()
                if not threat_df.empty else "normal"
            )

            return jsonify({
                "time": time.strftime("%H:%M:%S"),
                "mode": "real",
                "alerts": alerts,
                "rows": display_result_df.to_dict(orient="records"),
                "total_logs": total_logs,
                "total_threats": total_threats,
                "total_safe": total_safe,
                "top_attack": top_attack,
                "status_message": "Demo attack simulation active" if SIMULATION_STATE["attack_mode"] else "Real packet monitoring active"
            })

        # =========================
        # FALLBACK: UPLOADED FILE SIMULATION
        # =========================
        file_path = LIVE_STATE.get("file_path")

        if file_path and os.path.exists(file_path):
            df = pd.read_csv(file_path, low_memory=False)

            start = LIVE_STATE.get("cursor", 0)
            chunk_size = LIVE_STATE.get("chunk_size", 20)
            end = start + chunk_size

            chunk_df = df.iloc[start:end].copy()

            if chunk_df.empty:
                LIVE_STATE["cursor"] = 0
                start = 0
                end = chunk_size
                chunk_df = df.iloc[start:end].copy()

            LIVE_STATE["cursor"] = end

            full_result_df, display_result_df = predict_dataframe(chunk_df)

            if SIMULATION_STATE["attack_mode"] and not full_result_df.empty:
                full_result_df = full_result_df.copy()
                display_result_df = display_result_df.copy()

                full_result_df["predicted_class"] = "dos"
                full_result_df["confidence"] = 96.45
                full_result_df["threat_status"] = "Threat"

                display_result_df["predicted_class"] = "dos"
                display_result_df["confidence"] = 96.45
                display_result_df["threat_status"] = "Threat"

            total_logs = len(full_result_df)
            total_threats = int((full_result_df["threat_status"] == "Threat").sum())
            total_safe = int((full_result_df["threat_status"] == "Normal").sum())

            alerts = build_alerts(full_result_df)

            threat_df = full_result_df[full_result_df["threat_status"] == "Threat"]
            top_attack = (
                threat_df["predicted_class"].value_counts().idxmax()
                if not threat_df.empty else "normal"
            )

            return jsonify({
                "time": time.strftime("%H:%M:%S"),
                "mode": "simulation",
                "alerts": alerts,
                "rows": display_result_df.to_dict(orient="records"),
                "total_logs": total_logs,
                "total_threats": total_threats,
                "total_safe": total_safe,
                "top_attack": top_attack,
                "status_message": "Demo attack simulation active" if SIMULATION_STATE["attack_mode"] else "Using uploaded data (live simulation)"
            })

        # =========================
        # NO DATA
        # =========================
        return jsonify({
            "time": time.strftime("%H:%M:%S"),
            "mode": "none",
            "alerts": [],
            "rows": [],
            "total_logs": 0,
            "total_threats": 0,
            "total_safe": 0,
            "top_attack": "No data",
            "status_message": "No packets and no uploaded file available"
        })

    except Exception as e:
        return jsonify({
            "time": time.strftime("%H:%M:%S"),
            "mode": "error",
            "alerts": [{
                "title": "Live Error",
                "message": str(e),
                "severity": "high",
                "x": 50,
                "y": 50,
                "place": "System"
            }],
            "rows": [],
            "total_logs": 0,
            "total_threats": 0,
            "total_safe": 0,
            "top_attack": "Error",
            "status_message": str(e)
        })


@app.route("/download/csv")
@login_required
def download_csv():
    file_path = os.path.join(OUTPUT_FOLDER, "prediction_results.csv")
    if not os.path.exists(file_path):
        flash("Prediction CSV not found. Upload and analyze dataset first.")
        return redirect(url_for("upload"))

    return send_file(file_path, as_attachment=True)


@app.route("/download/pdf")
@login_required
def download_pdf():
    data = session.get("dashboard_data")
    if not data:
        flash("Upload dataset first.")
        return redirect(url_for("upload"))

    buffer = io.BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=A4)
    y = 800

    pdf.setFont("Helvetica-Bold", 16)
    pdf.drawString(40, y, "AI Sentinel Report")
    y -= 35

    pdf.setFont("Helvetica", 11)
    for line in [
        f"Total Logs: {data.get('total_logs', 0)}",
        f"Total Threats: {data.get('total_threats', 0)}",
        f"Total Safe: {data.get('total_safe', 0)}",
        f"Threat Percentage: {data.get('threat_percentage', 0)}%",
        f"Safe Percentage: {data.get('safe_percentage', 0)}%",
        f"Average Confidence: {data.get('avg_confidence', 0)}%",
        f"Top Attack: {data.get('top_attack', 'No data')}",
    ]:
        pdf.drawString(40, y, line)
        y -= 18

    pdf.save()
    buffer.seek(0)

    return send_file(
        buffer,
        as_attachment=True,
        download_name="AI_Sentinel_Report.pdf",
        mimetype="application/pdf"
    )


if __name__ == "__main__":
    app.run(debug=True)