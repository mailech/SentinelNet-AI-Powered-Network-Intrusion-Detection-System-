# SentinelNet: AI-Powered Network Intrusion Detection System

SentinelNet is a full-stack, real-time Network Intrusion Detection System (NIDS) that leverages Machine Learning to identify and classify network traffic as "Normal" or "Attack". Built on the industry-standard NSL-KDD dataset, it provides a high-fidelity "Neural Command Center" dashboard for monitoring network safety.

---

### 🌐 [Live Demo: SentinelNet Dashboard](https://sentinel-ywbn.onrender.com/)

---

## 🚀 Features

- **AI Classification**: Uses a Random Forest model trained on the NSL-KDD dataset to detect 4 major attack types (DoS, Probe, R2L, U2R).
- **Real-time Monitoring**: A live simulation engine that streams processed network packets through the model for instant inference.
- **Neural Command Center**: A premium, dark-themed React dashboard featuring:
  - **KPI Metrics**: Real-time tracking of traffic volume, threats detected, threat rate, and AI confidence.
  - **Threat Probability Matrix**: An interactive Area Chart visualizing confidence scores and anomaly spikes.
  - **Tactical Feed**: A live scrolling interception stream with detailed packet signatures.
  - **Incident Log**: A filtered view of all detected threats and quarantine actions.
- **Dynamic Training**: Integrated pipeline to re-train the model directly from the UI or via the backend script.

---

## 🛠️ Technology Stack

### Backend
- **FastAPI**: High-performance Python web framework for the ML API.
- **Scikit-Learn**: Used for the Random Forest classifier, preprocessing (RobustScaler), and encoding (OneHotEncoder).
- **Joblib**: Persistent storage for trained model artefacts.
- **Pandas/NumPy**: Data manipulation and numerical processing.

### Frontend
- **React**: Modern component-based UI.
- **Vite**: Ultra-fast build tool and dev server.
- **Lucide React**: For sleek, consistent iconography.
- **Recharts**: For high-performance, responsive data visualizations.
- **Vanilla CSS**: Custom "Cyber-Nexus" theme with glassmorphism and grid-based layouts.

---

## 📂 Project Structure

```text
SentinelNet/
├── backend/
│   ├── main.py            # FastAPI Application & Simulation Engine
│   ├── train_model.py     # ML Training Pipeline Script
│   └── alerts.log         # Persistent record of detected threats
├── frontend/
│   ├── src/
│   │   ├── App.jsx        # Main Dashboard UI
│   │   └── index.css      # Premium "Neural Command Center" Theme
│   └── index.html         # Application Entry Point
├── data/
│   ├── KDDTrain+.txt      # NSL-KDD Training Set
│   └── KDDTest+.txt       # NSL-KDD Testing Set
├── models/
│   ├── rf_model.pkl       # Trained Random Forest Model
│   ├── scaler.pkl         # Fitted RobustScaler
│   ├── encoder.pkl        # Fitted OneHotEncoder
│   └── test_selected.csv  # Simulator Seed Data
└── README.md
```

---

## 🚦 Getting Started

### 1. Prerequisites
- Python 3.8+
- Node.js & npm

### 2. Setup the Backend
Navigate to the `backend` directory and install dependencies:
```bash
cd backend
pip install fastapi uvicorn scikit-learn pandas numpy joblib
```

### 3. Train the Model
You must generate the model artefacts before running the server:
```bash
python train_model.py
```
*This will process the NSL-KDD dataset and save the model to the `models/` directory.*

### 4. Start the API Server
```bash
python main.py
```
*The API will be available at `http://localhost:8000`.*

### 5. Setup the Frontend
Open a new terminal, navigate to the `frontend` directory, and install dependencies:
```bash
cd frontend
npm install
npm install lucide-react recharts
```

### 6. Run the Dashboard
```bash
npm run dev
```
*Open the provided local link (usually `http://localhost:5173`) in your browser.*

---

## 🧠 Model Performance
The Random Forest model achieves approximately **99.9% accuracy** on the NSL-KDD+ validation set, providing robust detection across various network protocol signatures.

---

## 🛡️ License
This project is for educational and research purposes in the field of AI and Cybersecurity.
