🚨 AI-Powered Network Intrusion Detection System (NIDS)
 Description

The goal of this project is to build an AI-based Network Intrusion Detection System capable of identifying malicious network traffic and cyber-attacks.

Using Machine Learning, the system will classify network traffic as Normal or Suspicious based on historical data.

🔍 The Project Involves

Processing network traffic data

Preparing and cleaning the dataset

Training machine learning models (later stages)

Detecting anomalies and cyber-attacks

🧩 Milestone 1
📅 Week 1: Project Initialization & Dataset Acquisition

The main focus of this week was understanding the project and the dataset.

✅ Tasks Completed

Defined project goals and expected outcomes

Selected the NSL-KDD dataset

Explored dataset structure and attack categories

Loaded the dataset using Python & Pandas

Performed basic statistical analysis and validation

💡 This step helped in understanding the dataset features and how network traffic data is structured.

📅 Week 2: Data Cleaning & Preprocessing

This week focused on preparing the dataset for Machine Learning.

🧹 Data Cleaning

Checked for missing values

Verified duplicate records

Reviewed dataset structure and feature types

⚙️ Data Preprocessing

Converted categorical features into numerical format

Organized and saved cleaned datasets into CSV format

Prepared training and testing datasets

📊 Work Completed
📥 Dataset Handling

Loaded the NSL-KDD dataset

Explored the dataset using Pandas

Checked duplicates and unique values

📈 Exploratory Data Analysis (EDA)

Performed analysis to understand traffic behavior.

📊 Visualizations Created

Traffic volume by protocol

Distribution of source bytes

Protocol vs Flag heatmap

🔎 Data Quality Checks

Checked missing values in src_bytes




🚀 Milestone 2: Feature Engineering & Data Optimization
📌 Overview

This milestone focuses on transforming the raw network intrusion dataset into a structured, balanced, and optimized feature set suitable for machine learning model training.

The preprocessing pipeline enhances data quality, reduces redundancy, and improves model efficiency.

Feature Scaling

Numerical features were normalized using StandardScaler to ensure uniform distribution across variables and to prepare the dataset for dimensionality reduction techniques.

One-Hot Encoding

Categorical attributes such as protocol type, service, and flag were converted into numerical format using OneHotEncoder, enabling compatibility with machine learning algorithms.

Feature Engineering & Aggregation

New derived features were created by aggregating and combining related network traffic attributes, including byte-level and packet-level interactions. These transformations enhance the representation of network behavior patterns.

Correlation Analysis & Redundancy Removal

A correlation matrix was computed to identify highly correlated features. Columns exceeding the defined correlation threshold were removed to eliminate redundancy and reduce multicollinearity.

Noise Reduction

Low-variance features and irrelevant attributes were filtered out to improve the signal-to-noise ratio and optimize the dataset for training.

Class Imbalance Handling (SMOTE)

The dataset was balanced using SMOTE (Synthetic Minority Over-sampling Technique) to address class imbalance between normal and attack traffic. Synthetic samples were generated for minority classes to ensure fair model learning.

Dimensionality Reduction (PCA)

Principal Component Analysis (PCA) was applied after scaling to reduce dimensionality while retaining maximum variance. This step improved computational efficiency and simplified the feature space.

Final optimized feature count: 36 features/components
t-SNE Visualization

t-SNE was applied to visualize high-dimensional data in a 2D space.

Helped understand clustering of normal vs attack traffic
Provided insight into feature separability
🧠 Final Pipeline

Raw Data
→ Data Cleaning
→ Encoding
→ Feature Engineering
→ Correlation Filtering
→ Noise Reduction
→ Train-Test Split
→ SMOTE (Training Only)
→ Preprocessing Pipeline
→ Scaling
→ PCA
→ t-SNE Visualization
→ Anomaly Detection
→ Model Training
→ Evaluation

⚙️ Model Development & Final Steps
Data Preparation
Created attack_class from raw labels
Encoded target variable using LabelEncoder
Prepared feature dataset
Train-Test Split

Dataset was split into training and testing sets before applying SMOTE to prevent data leakage.

Preprocessing Pipeline

Pipeline included:

SimpleImputer
StandardScaler
PCA

Fitted on training data and applied to test data.
Saved using joblib for reuse.

Anomaly Detection

Applied Isolation Forest to detect unusual traffic patterns.

Generated:

iso_score
iso_pred
is_anomaly
Final Classifier
Trained Random Forest Classifier
Performed hyperparameter tuning using GridSearchCV
Selected best-performing model
Final Evaluation

Evaluated model using:

Accuracy
Precision
Recall
F1-score

Generated:

Classification report
Confusion matrix
ROC-AUC Analysis
Performed ROC-AUC evaluation on test data
Used One-vs-Rest approach for multiclass

Plotted ROC curves for each class
Deep Performance Audit

Conducted detailed class-wise performance analysis:

Per-class F1-score
Identification of easiest and hardest classes
Analysis of confusion patterns

Website Images
<img width="1912" height="911" alt="home" src="https://github.com/user-attachments/assets/fd944e7d-4370-4a12-a1f7-1d2e7e734b25" />
<img width="1915" height="926" alt="upload" src="https://github.com/user-attachments/assets/88384da2-3a4c-4372-87be-e1a60ac43721" />
<img width="1898" height="907" alt="dashboard1" src="https://github.com/user-attachments/assets/2c89bb04-11f0-4976-a197-afea31b6a92d" />
<img width="1901" height="916" alt="dashboard2" src="https://github.com/user-attachments/assets/93311700-068a-41e4-b747-a9309bf4d83a" />
<img width="877" height="820" alt="dashboard3" src="https://github.com/user-attachments/assets/6167fa95-0ee1-4d01-be23-0db2699be642" />
<img width="1902" height="913" alt="dashboard4" src="https://github.com/user-attachments/assets/c680c9f0-3c78-4b86-9074-571e4a0650c9" />
<img width="1902" height="925" alt="alerts1" src="https://github.com/user-attachments/assets/1c44c3fd-c64b-443c-b741-ed4d35df885e" />
<img width="1907" height="925" alt="alerts2" src="https://github.com/user-attachments/assets/bc458d8b-34f7-4c25-96d3-dad20531cea8" />
<img width="1913" height="906" alt="live1" src="https://github.com/user-attachments/assets/0b635dce-1e63-486b-814e-26b4cc9ead89" />
<img width="1917" height="927" alt="live2" src="https://github.com/user-attachments/assets/03f82327-cf12-4435-9299-6f2a1ae2150f" />
<img width="1902" height="921" alt="live3" src="https://github.com/user-attachments/assets/78d4ab14-753f-40c7-97fa-696f6e95f9af" />
<img width="1906" height="915" alt="live4" src="https://github.com/user-attachments/assets/7ec3e5b8-72eb-4375-92ff-498948d7cbf4" />

render deployment link
https://ai-sentinel-website.onrender.com












