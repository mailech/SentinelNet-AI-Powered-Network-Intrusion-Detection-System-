# 🚨 AI-Powered Network Intrusion Detection System (NIDS)

This project aims to build an AI-based Network Intrusion Detection System capable of identifying malicious network traffic and cyber-attacks using Machine Learning.

The system analyzes network connection features from the NSL-KDD dataset and classifies traffic as **Normal** or **Suspicious (DoS attacks)**.

---

# 🔍 Project Overview

The project involves:

- Processing network traffic data  
- Cleaning and preprocessing network features  
- Exploratory Data Analysis (EDA) of attack behavior  
- Feature engineering for intrusion detection  
- Training a Machine Learning classifier  
- Detecting anomalous and malicious traffic  

---

# 📁 Project Structure
nsl_kdd/
│
├── week1_eda.ipynb
├── week2_feature_engineering.ipynb
│
data/
│
derived_train_attack_category.csv
derived_test_attack_category.csv

---

# 🧩 Milestone 1 — Week 1  
## Project Initialization & Dataset Understanding

The focus of Week 1 was understanding the NSL-KDD dataset and network traffic structure.

### ✅ Tasks Completed

- Defined project goals and intrusion detection objective  
- Selected the NSL-KDD dataset  
- Loaded dataset using Python & Pandas  
- Assigned dataset column names from documentation  
- Explored attack types and categories  
- Analyzed protocol distribution across traffic  
- Performed statistical inspection of features  
- Verified dataset structure and feature types  

### 📊 Exploratory Data Analysis (EDA)

Performed analysis to understand network behavior and attack patterns.

#### Visualizations Created

- Traffic volume by protocol  
- Distribution of source bytes  
- Protocol vs connection flag heatmap  
- Feature distributions for network traffic  
- Protocol vs attack category analysis  
- Duration vs attack category comparison  

### 🔎 Data Quality Checks

- Checked missing values  
- Verified duplicate records  
- Inspected categorical feature values  
- Validated dataset consistency  

💡 **Outcome:**  
Gained understanding of network traffic features and attack characteristics in NSL-KDD.

---

# 🧹 Milestone 2 — Week 2  
## Data Cleaning & Preprocessing

This stage prepared the dataset for Machine Learning modeling.

### ⚙️ Data Preprocessing

- Filtered TCP traffic  
- Mapped attack types → attack categories  
- Created binary classification dataset (Normal vs DoS)  
- Encoded categorical features  
  - protocol_type  
  - service  
  - flag  
- Standardized numerical features  
  - duration  
  - src_bytes  
  - dst_bytes  
- Generated aggregated traffic statistics  
- Applied log-scale transformations  
- Saved processed datasets  

### 📊 Feature Analysis

- Compared feature distributions between Normal and DoS traffic  
- Analyzed duration and byte behavior across attacks  
- Identified rare attack patterns  
- Examined protocol behavior in attacks  

Output datasets:
derived_train_attack_category.csv
derived_test_attack_category.csv

---

# 🤖 Machine Learning Model

A Random Forest classifier was trained to detect intrusion traffic.

### Model Task
Binary classification:
- Normal traffic  
- DoS attack traffic  

### Steps

- Prepared feature matrix (X) and labels (y)  
- Trained RandomForestClassifier  
- Predicted on test dataset  
- Evaluated performance  

### Evaluation Metrics

- Classification report  
- Confusion matrix  
- Feature importance  

---

# 🔬 Additional Independent Analysis

Extended beyond baseline preprocessing:

- Protocol vs attack category relationships  
- Feature distribution comparison (Normal vs DoS)  
- Duration vs attack behavior  
- Misclassification inspection  
- Feature importance interpretation  
- Rare attack exploration  

---

# 📈 Key Observations

- TCP protocol carries most DoS attacks  
- Source and destination byte features strongly indicate attacks  
- DoS traffic shows distinct duration patterns  
- Certain services correlate with attack traffic  
- Engineered features improve separation between normal and attack traffic  

---

# 🧰 Technologies Used

- Python  
- Pandas  
- NumPy  
- Matplotlib  
- Seaborn  
- Scikit-learn  

---

# 📚 Dataset

**NSL-KDD**  
Benchmark dataset for network intrusion detection research.

---

# 🎯 Objective

Develop a machine-learning-based intrusion detection system capable of distinguishing normal network traffic from cyber-attack patterns.

---

# 👤 Author

Hitan
