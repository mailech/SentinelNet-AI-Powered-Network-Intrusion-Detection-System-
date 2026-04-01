# 🛡 SentinelNet — AI-Powered Network Intrusion Detection System

![Python](https://img.shields.io/badge/Python-3.10-blue?style=flat-square&logo=python)
![Flask](https://img.shields.io/badge/Flask-2.x-black?style=flat-square&logo=flask)
![scikit-learn](https://img.shields.io/badge/scikit--learn-1.6-orange?style=flat-square&logo=scikit-learn)
![HuggingFace](https://img.shields.io/badge/HuggingFace-Spaces-yellow?style=flat-square&logo=huggingface)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

> A real-time network intrusion detection dashboard powered by a Random Forest classifier trained on the NSL-KDD dataset. Detects 5 categories of network threats with live visualization and batch CSV analysis.

🔴 **Live Demo:** [https://huggingface.co/spaces/Hitan2004/sentinelnet](https://huggingface.co/spaces/Hitan2004/sentinelnet)

---

## 📌 What It Does

SentinelNet analyzes network traffic and classifies each connection as one of 5 categories:

| Class | Type | Severity |
|-------|------|----------|
| `normal` | Clean traffic | None |
| `DoS` | Denial of Service attack | Critical |
| `Probe` | Reconnaissance / Port scanning | Medium |
| `R2L` | Remote to Local attack | High |
| `U2R` | User to Root / Privilege escalation | Critical |

---

## ✨ Features

### 📡 Live Monitor Tab
- Auto-generates NSL-KDD formatted network packets
- Sends each packet to the trained Random Forest model in real time
- Displays live detection feed with class, confidence, and severity
- Attack distribution bar chart updated in real time
- Threat timeline chart (last 60 seconds)
- Activity heatmap of last 60 packets
- Confidence distribution panel
- System log terminal
- Session summary stats

### 📂 CSV Analysis Tab
- Upload any NSL-KDD formatted CSV file
- Auto-detects headers (with or without column names)
- Processes rows in batches through the model
- Live progress bar with ETA and processing speed
- Row-by-row feed showing predictions as they come in
- On completion generates a full threat report including:
  - Risk score gauge (0–100)
  - Class distribution bar chart
  - Confidence waveform over dataset
  - Threat intensity rolling chart
  - Protocol breakdown
  - Top targeted services
  - Attack pattern clusters
  - Paginated full results table
- Export results as **Annotated CSV**, **PDF Report**, or **JSON**

---

## 🧠 Model Details

| Property | Value |
|----------|-------|
| Algorithm | Random Forest Classifier |
| Dataset | NSL-KDD (improved KDD Cup 1999) |
| Features | 41 network connection features |
| Classes | 5 (normal, DoS, Probe, R2L, U2R) |
| Preprocessing | OHE encoding, frequency encoding, log transforms, standard scaling |
| Deployment | HuggingFace Spaces (Flask API) |

### Preprocessing Pipeline
1. One-hot encode `protocol_type` and `flag`
2. Frequency encode `service` column
3. Log transform `src_bytes`, `dst_bytes`, `duration`
4. Engineer features: `total_bytes`, `src_bytes_ratio`, `is_error_flag`
5. Standard scale all selected features

---

## 🏗 Tech Stack

**Backend**
- Python 3.10
- Flask + Flask-CORS
- scikit-learn (Random Forest)
- pandas, numpy, joblib

**Frontend**
- Vanilla HTML/CSS/JavaScript (no frameworks)
- IBM Plex Mono + Space Grotesk fonts
- Canvas API for charts
- Split into 3 files: `index.html`, `style.css`, `app.js`

**Deployment**
- HuggingFace Spaces (Docker)
- Flask serves both the frontend and the `/predict` API

---

## 📁 Project Structure

```
sentinelnet/
├── frontend/
│   ├── index.html        # Main HTML structure
│   ├── style.css         # All styles and CSS variables
│   └── app.js            # All JavaScript logic
├── models/
│   ├── sentinel_brain.joblib      # Trained Random Forest model
│   ├── label_encoder.joblib       # Label encoder
│   ├── ohe_encoder.joblib         # One-hot encoder
│   ├── freq_map.joblib            # Service frequency map
│   ├── scaler.joblib              # Standard scaler
│   └── selected_features.joblib  # Selected feature list
├── app.py                # Flask backend + API
├── requirements.txt      # Python dependencies
└── Dockerfile            # HuggingFace deployment config
```

---

## 🚀 Running Locally

**1. Clone the repo**
```bash
git clone https://github.com/Hitan547/sentinelnet.git
cd sentinelnet
```

**2. Install dependencies**
```bash
pip install -r requirements.txt
```

**3. Run the Flask server**
```bash
python app.py
```

**4. Open in browser**
```
http://localhost:7860
```

---

## 🔌 API Reference

### `POST /predict`
Accepts a batch of NSL-KDD rows and returns predictions.

**Request:**
```json
{
  "rows": [
    {
      "duration": 0,
      "protocol_type": "tcp",
      "service": "http",
      "src_bytes": 181,
      "dst_bytes": 5450,
      ...
    }
  ]
}
```

**Response:**
```json
{
  "status": "ok",
  "results": [
    {
      "predicted_class": "normal",
      "severity": "None",
      "confidence": 0.9821,
      "is_intrusion": false
    }
  ]
}
```

### `GET /health`
Returns model status.
```json
{"status": "online", "model": "sentinel_brain"}
```

---

## 📊 Dataset

This project uses the **NSL-KDD dataset**, an improved version of the KDD Cup 1999 dataset for network intrusion detection research.

- Removes duplicate records from KDD Cup 99
- More balanced class distribution
- Widely used benchmark for IDS research
- 41 features per network connection record

---

## 🎯 What I Learned

- Training and deploying a multi-class classification model end to end
- Building a real-time dashboard with vanilla JavaScript
- Connecting a Flask API to a frontend with CORS handling
- Deploying on HuggingFace Spaces with Docker
- Performance optimization for large CSV batch processing
- Splitting a large frontend file for maintainability

---

## 📬 Contact

**Hitan** — [GitHub](https://github.com/Hitan547)

---

## 📄 License

MIT License — feel free to use this project for learning or portfolio purposes.
