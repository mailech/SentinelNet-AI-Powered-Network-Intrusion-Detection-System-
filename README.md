
#SentinelNet – AI-Powered Network Intrusion Detection System (NIDS)

## Project Overview
In this project, I developed **SentinelNet**, an AI-powered Network Intrusion Detection System (NIDS) designed to detect malicious network traffic and cyber-attacks.
The system uses **machine learning and anomaly detection techniques** to classify network traffic as **normal or suspicious**, and also supports **real-time intrusion detection with alert generation and logging**.

## Project Goal
The goal of this project is to:
* Detect cyber attacks in network traffic
* Classify traffic as normal or malicious
* Identify anomalies using machine learning
* Build a **real-time intrusion detection system**

## Key Outcomes

Through this project, I was able to:
* Understand network traffic data and attack types
* Apply machine learning models for intrusion detection
* Perform feature engineering and dimensionality reduction
* Implement anomaly detection techniques
* Generate alerts and logs for detected threats
* Build a complete end-to-end ML pipeline

## Dataset Used
I used the **NSL-KDD dataset**, a widely used benchmark dataset for intrusion detection.
| Component     | Details                      |
| ------------- | ---------------------------- |
| Dataset       | NSL-KDD                      |
| Training Data | KDDTrain.txt                 |
| Testing Data  | KDDTest.txt                  |
| Features      | 40+ network attributes       |
| Classes       | Normal, DoS, Probe, R2L, U2R |

##System Workflow
The complete pipeline of the project is as follows:
Dataset Acquisition → Data Preprocessing → Feature Engineering →
Model Training → Model Evaluation → Anomaly Detection →
Model Saving → Real-Time Prediction → Alert Generation → Logging

##Module Implementation (Step-by-Step)
### 1.Dataset Acquisition & Exploration
* Downloaded NSL-KDD dataset
* Explored dataset structure and features
* Understood different attack categories
* Performed basic statistical analysis

###2.Data Cleaning & Preprocessing

In this step, I prepared the dataset for modeling
* Checked for missing values and inconsistencies
* Handled categorical features using:
  * **One-Hot Encoding** (`protocol_type`, `service`, `flag`)
* Encoded target labels using **LabelEncoder**
* Removed unnecessary column:
  * `difficulty_level`
* Ensured **train-test feature alignment**
* Normalized/standardized data 

###3.Feature Engineering & Selection
This was a key part of my implementation:
* Performed **correlation analysis**
* Generated correlation matrix
* Identified highly correlated features
* Removed redundant features using:
  * **Upper triangular matrix method**
  * 
###4. Supervised Model Training
I trained multiple classification models:
* Random Forest Classifier 
* Logistic Regression

Steps performed:
* Split data into training and testing sets
* Trained models using Scikit-learn
* Evaluated using performance metrics
* 
###5.Anomaly Detection (Unsupervised Learning)
To detect unknown attacks, implemented:
* Isolation Forest
* Local Outlier Factor (LOF)
* One-Class SVM
 These models helped identify unusual traffic patterns beyond labeled data.

###6.Model Evaluation & Fine-Tuning
* Evaluated models using:
  * Accuracy
  * Precision
  * Recall
  * F1-score
* Compared model performance
* Selected **Random Forest as best model**   
* Analyzed results using:
  * Classification report
  * Confusion matrix
    
###7.Alert Generation & Logging (Real-Time System)
    Implemented a real-time intrusion detection system:
* Loaded trained model using **joblib**
* Predicted incoming data row-by-row
* Generated alerts:
  *“INTRUSION DETECTED”*
* Stored predictions in **CSV logs**
* Visualized attack counts using graphs
This makes the system practical and usable in real-world scenarios.

###8.Documentation & Presentation
* Documented the full pipeline and results
* Prepared presentation slides
* Structured project for demonstration

##Model Performance
* Random Forest achieved the best performance
* Feature engineering significantly improved accuracy
* Anomaly detection models enhanced detection of unknown attacks
  
## Conclusion
In this project,successfully built a **complete intrusion detection system**:
* Implemented end-to-end ML pipeline
* Applied both supervised and unsupervised techniques
* Developed a real-time detection and alert system
* Improved performance through feature engineering
