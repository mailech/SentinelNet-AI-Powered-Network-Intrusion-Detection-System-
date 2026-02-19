# SentinelNet – AI Powered Network Intrusion Detection System

## Project Overview

This project focuses on building an AI-based Network Intrusion Detection System (NIDS) using the NSL-KDD dataset. The objective is to classify network traffic as **Normal** or **Attack** using machine learning techniques.

## Week 1 – Dataset Acquisition & Exploration

**Tasks Completed:**

* Downloaded and loaded the NSL-KDD dataset
* Defined column names manually
* Checked dataset structure, missing values, and duplicates
* Analyzed attack type distribution
* Created binary classification (Normal vs Attack)
* Performed visual analysis:

  * Protocol distribution
  * Service distribution
  * Class imbalance
  * Duration vs Attack comparison
  * Correlation heatmap

**Key Learnings:**

* Understanding data structure is essential before modeling.
* The dataset is imbalanced.
* Certain features show strong relationships with attack behavior.

---

## Week 2 – Data Cleaning & Preprocessing

**Tasks Completed:**

* Removed duplicate records
* Converted labels to binary format (0 = Normal, 1 = Attack)
* Performed stratified train-test split
* Identified categorical and numerical features
* Built preprocessing pipeline using:

  * StandardScaler (numerical features)
  * OneHotEncoder (categorical features)
* Prevented data leakage by fitting transformations only on training data
* Applied SMOTE on training data to address class imbalance

**Key Learnings:**

* Proper preprocessing significantly impacts model performance.
* Preventing data leakage is critical in ML workflows.
* Handling class imbalance is important in intrusion detection systems.

---

## 🚀 Next Steps

* Feature engineering and selection
* Model training (Random Forest, SVM, Logistic Regression)
* Model evaluation (Precision, Recall, F1-score)
* Alert generation and logging



