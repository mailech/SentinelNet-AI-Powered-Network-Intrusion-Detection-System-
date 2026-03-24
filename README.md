# SentinelNet: AI-Powered Network Intrusion Detection System

## Overview

SentinelNet is a machine learning-based network intrusion detection system built using the NSL-KDD dataset. The project focuses on identifying malicious network activity by combining data preprocessing, feature engineering, supervised learning, and anomaly detection techniques.

The goal is to develop a reliable pipeline that can distinguish between normal and attack traffic while maintaining strong generalization performance.

---

## Project Workflow

The project is structured into sequential stages:

1. **Data Exploration**
   - Understanding dataset structure and feature behavior
   - Identifying class imbalance and feature distributions

2. **Data Preprocessing**
   - Handling categorical and numerical features
   - Encoding and scaling using a preprocessing pipeline
   - Addressing class imbalance using SMOTE

3. **Feature Engineering & Selection**
   - Generating and selecting important features
   - Removing redundant and low-importance features
   - Improving data representation for modeling

4. **Model Training & Evaluation**
   - Training multiple machine learning models
   - Evaluating performance using accuracy, precision, recall, and F1 score
   - Comparing models to select the best performer

5. **Anomaly Detection**
   - Applying unsupervised methods such as K-Means, Isolation Forest, LOF, and One-Class SVM
   - Identifying unusual network behavior patterns

6. **Model Tuning & Validation**
   - Optimizing model performance using GridSearchCV
   - Validating model stability using cross-validation
   - Evaluating performance using ROC curves and confusion matrices

---

## Repository Structure
# SentinelNet: AI-Powered Network Intrusion Detection System

## Overview

SentinelNet is a machine learning-based network intrusion detection system built using the NSL-KDD dataset. The project focuses on identifying malicious network activity by combining data preprocessing, feature engineering, supervised learning, and anomaly detection techniques.

The goal is to develop a reliable pipeline that can distinguish between normal and attack traffic while maintaining strong generalization performance.

---

## Project Workflow

The project is structured into sequential stages:

1. **Data Exploration**
   - Understanding dataset structure and feature behavior
   - Identifying class imbalance and feature distributions

2. **Data Preprocessing**
   - Handling categorical and numerical features
   - Encoding and scaling using a preprocessing pipeline
   - Addressing class imbalance using SMOTE

3. **Feature Engineering & Selection**
   - Generating and selecting important features
   - Removing redundant and low-importance features
   - Improving data representation for modeling

4. **Model Training & Evaluation**
   - Training multiple machine learning models
   - Evaluating performance using accuracy, precision, recall, and F1 score
   - Comparing models to select the best performer

5. **Anomaly Detection**
   - Applying unsupervised methods such as K-Means, Isolation Forest, LOF, and One-Class SVM
   - Identifying unusual network behavior patterns

6. **Model Tuning & Validation**
   - Optimizing model performance using GridSearchCV
   - Validating model stability using cross-validation
   - Evaluating performance using ROC curves and confusion matrices

---

## Repository Structure
SentinelNet/
│
├── notebooks/
│ ├── 01_data_exploration.ipynb
│ ├── 02_preprocessing.ipynb
│ ├── 03_feature_engineering.ipynb
│ ├── 04_model_training_and_evaluation.ipynb
│ ├── 05_anomaly_detection.ipynb
│ ├── 06_model_evaluation_and_tuning.ipynb
│
├── data/
│
├── models/
│ └── preprocessor.pkl
│
├── reports/
│ ├── milestone_1.txt
│ ├── milestone_2.txt
│ ├── milestone_3.txt
│
├── README.md
├── weekly_progress_summary.txt


---

## Key Techniques Used

- Data preprocessing using `ColumnTransformer`
- Feature selection using Random Forest importance
- Class imbalance handling using SMOTE
- Supervised models:
  - Logistic Regression
  - Decision Tree
  - Random Forest
  - Gradient Boosting
- Unsupervised anomaly detection:
  - K-Means
  - Isolation Forest
  - Local Outlier Factor
  - One-Class SVM
- Model evaluation:
  - Classification report
  - Confusion matrix
  - ROC-AUC
  - Cross-validation

---

## Results

- Random Forest achieved strong performance after tuning.
- Feature engineering significantly improved model effectiveness.
- Anomaly detection methods provided additional insights into unusual traffic patterns.
- Cross-validation confirmed model stability and generalization capability.

---

## Conclusion

This project demonstrates a complete machine learning pipeline for network intrusion detection. By combining supervised and unsupervised techniques, the system is able to effectively detect malicious activity while maintaining robust performance.

---

## Notes

- The dataset used is NSL-KDD.
- SMOTE was applied only on training data to avoid data leakage.
- Some computationally intensive methods were applied on sampled data for efficiency.