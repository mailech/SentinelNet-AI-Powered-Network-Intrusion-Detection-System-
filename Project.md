# AI-Powered Network Intrusion Detection System (NIDS)


## Goal of the Project
* Develop an AI-based system to detect malicious network traffic.
* Classify traffic as **normal or attack** using machine learning.
* Analyze network traffic data and identify patterns.
* Reduce false alarms while improving detection accuracy.
* Generate alerts for suspicious activities.

---

## Understanding the Core Problem
* Modern networks continuously exchange data, and within this traffic, cyber-attacks occur.
* Traditional security systems depend on predefined rules which may fail for new or unknown attacks.
* Machine Learning helps detect hidden patterns in traffic data.
* **Main task:** Traffic Classification (Normal vs. Intrusion).

---

## Networking Fundamentals


| Protocol | Characteristics | Use Cases |
| :--- | :--- | :--- |
| **TCP (Transmission Control Protocol)** | Connection-oriented, uses a 3-way handshake, reliable communication, slower than UDP. | Widely used in web services, emails, and file transfers. |
| **UDP (User Datagram Protocol)** | Connectionless protocol, faster transmission, no delivery guarantee. | Streaming and real-time applications. |

**Other Important Protocols:** HTTP/HTTPS, DNS, SSH, and ICMP.

### Key Observations & Network Attacks
* The majority of attacks in the dataset are related to TCP traffic, while fewer attacks are observed in UDP and ICMP.
* Attack distribution varies based on protocol type, and TCP services are common attack targets. Some attack labels are completely protocol-specific.
* **Types of Network Attacks Discussed:** DDoS (Distributed Denial of Service), Brute Force Attacks, Port Scanning, Injection Attacks, and SYN Flood.

---

## Dataset Understanding & Multi-Dimensional Analysis

**Dataset Analysis:**
* **Features Analyzed:** `duration`, `protocol_type`, `service`, `flag`, `src_bytes`, `dst_bytes`, and `class label`.
* **Studies Conducted:** Distribution of normal vs. attack traffic, relationship between protocol and attack type, feature correlations, and class imbalance.

**Multi-Dimensional Analysis Concepts:**
* **Slicing:** Selecting data based on one condition (e.g., protocol = TCP).
* **Dicing:** Applying multiple filters (e.g., protocol + duration range).
* **Roll-up:** Aggregating data.
* **Drill-down:** Viewing detailed data.
* **Pivoting:** Changing data perspective.
* **Purpose:** To understand relationships between different categories and identify patterns between duration, protocol, and attack type.

---

## Data Preprocessing & Machine Learning Pipeline


**Data Cleaning, Engineering, & Preparation:**
* Removed duplicate records, checked missing values, and removed irrelevant features.
* Converted categorical features using encoding.
* Applied `log(1 + x)` transformation for skewed features like `src_bytes` and normalized numerical features.
* Split the dataset into training and testing sets to ensure proper evaluation setup, improve model performance, avoid bias, and prevent data leakage.

**The Machine Learning Pipeline:**
1. Data Extraction
2. Data Cleaning and Preprocessing
3. Feature Engineering
4. Model Training
5. Model Evaluation
6. Prediction and Alert Generation

---

## Evaluation Metrics & Key Considerations


**Evaluation Metrics:**
* **Confusion Matrix:** Measures True Positives (TP), False Positives (FP), True Negatives (TN), and False Negatives (FN).
* **Core Metrics:** Accuracy, Precision, Recall, F1-Score, and ROC Curve.

**Important Considerations:**
* **Intrusion Detection Priority:** Reducing False Negatives is critical. There must be a balance between the detection rate and false alarms.
* **Domain Knowledge:** Understanding the application domain helps in better feature selection, interpretation, and model performance.
* **Synthetic Data Addition:** Artificially generated data (e.g., timestamps) can be added to enhance dataset completeness or analysis capability.

**Data Architecture Definitions:**
* **OLTP (Online Transaction Processing):** System used for handling real-time transactional operations with high consistency and speed.
* **OLAP (Online Analytical Processing):** System used for analyzing large historical datasets to identify patterns and trends.
* **Data Warehousing:** Centralized storage system designed for analytical querying and reporting.
* **ETL (Extract, Transform, Load):** Process of collecting data, cleaning/transforming it, and loading it into a system for analysis.