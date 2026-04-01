#  SentinelNet – AI-Powered Network Intrusion Detection System (NIDS)

##  Live Demo

 https://sentinelnet-nids.onrender.com

---

## Project Overview

In this project, I developed **SentinelNet**, an AI-powered Network Intrusion Detection System (NIDS) designed to detect malicious network traffic and cyber-attacks. The system uses machine learning and anomaly detection techniques to classify network traffic as normal or suspicious, and supports real-time intrusion detection with alert generation and logging.

---

## Goal of the Project

* Detect malicious network traffic using AI
* Classify traffic as normal or attack
* Analyze traffic patterns
* Reduce false alarms
* Generate alerts for suspicious activity

---

## Understanding the Core Problem

* Modern networks continuously exchange data
* Cyber-attacks can be hidden in this traffic
* Rule-based systems fail for unknown attacks
* Machine Learning helps detect hidden patterns
* Main task: **Traffic Classification (Normal vs Intrusion)**

---

## Key Outcomes

* Understood network traffic & attack types
* Applied machine learning models
* Performed feature engineering
* Implemented anomaly detection
* Generated alerts & logs
* Built end-to-end ML pipeline

---

##  Dataset Used

**NSL-KDD Dataset**

| Component     | Details                      |
| ------------- | ---------------------------- |
| Dataset       | NSL-KDD                      |
| Training Data | KDDTrain.txt                 |
| Testing Data  | KDDTest.txt                  |
| Classes       | Normal, DoS, Probe, R2L, U2R |

---

##  System Workflow

Dataset → Preprocessing → Feature Engineering → Model Training → Evaluation → Anomaly Detection → Model Saving → Real-Time Prediction → Alert Generation → Logging

---

##  Module Implementation

### 1. Dataset Acquisition

* Downloaded NSL-KDD dataset
* Explored structure and features

### 2. Data Preprocessing

* Handled missing values
* One-Hot Encoding (protocol_type, service, flag)
* Label Encoding
* Removed `difficulty_level`
* Feature alignment

### 3. Feature Engineering

* Correlation analysis
* Removed redundant features

### 4. Model Training

* Random Forest
* Logistic Regression

### 5. Anomaly Detection

* Isolation Forest
* Local Outlier Factor
* One-Class SVM

### 6. Model Evaluation

* Accuracy, Precision, Recall, F1-score
* Confusion matrix
* Selected best model

### 7. Real-Time Detection

* Loaded model using joblib
* Generated alerts
* Logged predictions
* Visualized attack data

### 8. Documentation

* Prepared full pipeline
* Created presentation

---

##  Model Performance

* Random Forest performed best
* Feature engineering improved accuracy
* Anomaly detection enhanced unknown attack detection

---

## Conclusion

* Built complete intrusion detection system
* Used both supervised & unsupervised learning
* Developed real-time alert system
* Improved detection through feature engineering

---

## 👩‍💻 Developed By

** Konduru Vennela Raghava **
