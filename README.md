---
title: SentinelNet IDS
emoji: 🛡️
colorFrom: indigo
colorTo: blue
sdk: docker
pinned: false
---

# SentinelNet: AI-Powered Network Intrusion Detection System

[![Live Demo on Hugging Face](https://img.shields.io/badge/Live%20Demo-Hugging%20Face-blue?style=for-the-badge&logo=huggingface)](https://huggingface.co/spaces/reshmirajs/sentinelnet)

🎨 **Frontend Dashboard Link:** [https://huggingface.co/spaces/reshmirajs/sentinelnet](https://huggingface.co/spaces/reshmirajs/sentinelnet)  

## Overview

SentinelNet is an end-to-end machine learning-based Network Intrusion Detection System (NIDS) designed to identify malicious network traffic in real time. The system combines supervised learning, anomaly detection techniques, and a live simulation engine to classify network connections as normal or attack traffic.

The project goes beyond traditional model development by integrating a fully functional web application, real-time alert generation, and an interactive monitoring dashboard.

---

## Key Features

* Real-time network traffic simulation using NSL-KDD dataset
* Machine learning-based intrusion detection (Random Forest)
* Live alert generation with severity classification
* Interactive dashboard with real-time charts and metrics
* File upload system for batch traffic analysis
* Manual connection analyzer for single predictions
* Simulated firewall system for IP quarantine
* REST API-based backend using Flask

---

## Dataset

The project uses the NSL-KDD dataset, a benchmark dataset for intrusion detection systems.

* Training Records: 125,973
* Test Records: 22,544
* Features: 41 per network connection

Each record represents a network connection with attributes such as protocol type, service, byte counts, and traffic statistics.

---

## Machine Learning Pipeline

### 1. Data Exploration

* Understanding feature distributions and class imbalance
* Visualizing categorical and numerical features

### 2. Data Preprocessing

* One-hot encoding for categorical features
* Standard scaling for numerical features
* SMOTE applied only on training data to handle imbalance
* Pipeline built using ColumnTransformer

### 3. Feature Engineering & Selection

* Feature importance using Random Forest
* Removal of low-importance and redundant features

### 4. Model Training & Evaluation

Models tested:

* Logistic Regression
* Decision Tree
* Random Forest (selected)

Evaluation metrics:

* Accuracy
* Precision
* Recall
* F1-score

### 5. Model Tuning

* Hyperparameter optimization using GridSearchCV
* Cross-validation for stability
* ROC-AUC evaluation

### 6. Anomaly Detection

Unsupervised techniques explored:

* K-Means
* Isolation Forest
* Local Outlier Factor (LOF)
* One-Class SVM

---

## Final Model Performance

* Accuracy: 99.2%
* Precision: 99.4%
* Recall: 99.1%
* F1-Score: 99.2%
* ROC-AUC: 99.7%

---

## Real-Time Intrusion Detection (Week 7)

The system simulates live network traffic and performs real-time predictions using the trained model.

### Features:

* Continuous packet simulation using test dataset
* Predictions executed every 2 seconds
* Dynamic dashboard updates
* Real-time alert generation
* Intrusion logging

---

## Alert Generation & Severity Classification

Each detected intrusion is assigned a severity level based on model confidence:

* Critical → Probability > 0.90
* High → Probability > 0.75
* Medium → Probability > 0.50
* Low → Otherwise

Each alert includes:

* Timestamp
* Source IP and Destination IP
* Protocol and Service
* Attack Type (DoS, Probe, R2L, U2R)
* Confidence Score
* Severity Level

Alerts are stored in a CSV log file for further analysis.

---

## Web Application

The system includes a Flask-based web application with a Single Page Application (SPA) frontend.

### Dashboard Features:

* Real-time traffic statistics
* Live packet and attack charts
* Attack type and protocol distribution
* Live intrusion alerts table

### Functional Modules:

* File Upload: Analyze bulk traffic data (CSV/TXT)
* Single Analyzer: Predict individual connections
* Live Alerts: Monitor ongoing threats
* Quarantine System: Block malicious IPs

---

## API Endpoints

* GET /api/live_data → Live traffic statistics and alerts
* POST /api/predict → Predict single network connection
* POST /api/upload → Batch file prediction
* GET /api/metrics → Model performance metrics
* POST /api/quarantine → Block malicious IP
* POST /api/sim/toggle → Start/Stop simulation

---

## System Architecture

1. NSL-KDD Dataset
2. Preprocessing (Encoding + Scaling)
3. Random Forest Model (Tuned)
4. Flask Backend
5. Real-Time Simulation Engine
6. Alert Generation System
7. Dashboard UI

---

## Project Structure

SentinelNet/
├── app.py
├── templates/
│   └── index.html
├── static/
│   ├── main.js
│   └── style.css
├── notebooks/
│   ├── 01_dataset_acquisition_and_eda.ipynb
│   ├── 02_data_preprocessing.ipynb
│   ├── 03_feature_engineering_and_selection.ipynb
│   ├── 04_model_training_and_evaluation.ipynb
│   ├── 05_anomaly_detection.ipynb
│   ├── 06_model_evaluation_and_tuning.ipynb
│   ├── 07_alert_generation_and_logging.ipynb
│   ├── models/
│   │   ├── best_model.pkl
│   │   └── preprocessor.pkl
│   └── data/
├── logs/
│   └── intrusion_alerts.csv
├── reports/
├── README.md

---

## Installation & Setup

1. Install dependencies:

pip install flask pandas numpy scikit-learn joblib

2. Run the application:

python app.py

3. Open in browser:

http://127.0.0.1:5050

---

## Key Achievements

* Built a complete end-to-end intrusion detection pipeline
* Achieved high accuracy (~99%) using Random Forest
* Implemented real-time traffic simulation engine
* Developed an interactive monitoring dashboard
* Designed severity-based alert classification
* Implemented simulated firewall (IP quarantine system)

---

## Conclusion

SentinelNet demonstrates a production-style implementation of a Network Intrusion Detection System by combining machine learning, real-time processing, and interactive visualization. The system is capable of detecting malicious traffic efficiently while providing actionable insights through alerts and monitoring tools.

---
