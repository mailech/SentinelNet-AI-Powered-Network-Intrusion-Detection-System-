## SentinelNet – AI-Based Network Intrusion Detection System

🔗 Live Demo: https://huggingface.co/spaces/tejaswini-24/SentinelSecure


##  Project Overview
SentinelNet is a machine learning-based Network Intrusion Detection System (NIDS) designed to identify and classify malicious network activities. The system analyzes network traffic patterns and detects potential cyber threats using both supervised and unsupervised learning techniques.
The project was developed in a structured, milestone-driven approach, covering the complete lifecycle from data acquisition to deployment as a web application.



##  Project Objective
The primary objective of this project is to:
- Detect and classify different types of network intrusions
- Identify abnormal traffic behavior using anomaly detection techniques
- Build a reliable and scalable intrusion detection model
- Deploy the solution as a real-time web-based application



## Dataset
The project utilizes standard intrusion detection datasets such as:
- NSL-KDD
- CICIDS2017
These datasets contain multiple network-related features including protocol types, service types, traffic statistics, and attack labels.



##  Project Development Timeline

###  Week 1 – Project Initialization & Dataset Acquisition
- Defined project scope, objectives, and expected outcomes
- Collected intrusion detection datasets (NSL-KDD / CICIDS2017)
- Explored dataset structure and attack categories
- Performed initial data validation and statistical analysis



###  Week 2 – Data Cleaning & Preprocessing
- Handled missing values and duplicate records
- Removed irrelevant and redundant features
- Applied encoding techniques to convert categorical variables
- Normalized and standardized numerical features
- Split dataset into training and testing sets



###  Week 3 – Feature Engineering & Selection
- Analyzed feature importance using statistical methods
- Performed correlation analysis to identify redundant features
- Applied dimensionality reduction techniques (if required)
- Engineered new features to improve model performance



###  Week 4 – Supervised Model Training
- Implemented multiple machine learning models:
  - Random Forest
  - Support Vector Machine (SVM)
  - Logistic Regression
- Trained models on processed dataset
- Evaluated performance using:
  - Accuracy
  - Precision
  - Recall
  - F1 Score



###  Week 5 – Anomaly Detection (Unsupervised Learning)
- Applied clustering-based and isolation techniques:
  - K-Means Clustering
  - Isolation Forest
- Identified patterns deviating from normal network behavior
- Compared effectiveness of unsupervised approaches



###  Week 6 – Model Evaluation & Fine-Tuning
- Compared performance across different models
- Performed hyperparameter tuning using cross-validation
- Analyzed:
  - Confusion Matrix
  - ROC Curve
- Selected the best-performing model for deployment



###  Week 7 – Alert Generation & Logging
- Simulated real-time predictions on test data
- Generated alerts for detected intrusions
- Implemented logging mechanisms
- Stored results in structured formats (CSV / text / logs)



###  Week 8 – Documentation & Presentation
- Documented complete methodology and results
- Prepared presentation and demo workflow
- Conducted final testing and validation of system




## 🌐 Live Web Application

The SentinelNet system has been successfully deployed as a web-based application using Hugging Face Spaces, enabling real-time interaction with the trained machine learning model.

🔗 Live Application: https://huggingface.co/spaces/tejaswini-24/SentinelSecure



##  Application Overview

The deployed web application serves as an interface between the user and the trained intrusion detection model. It allows users to input network-related parameters and receive immediate predictions regarding the nature of the network traffic.
The application is designed to simulate a real-world intrusion detection environment where incoming data can be analyzed dynamically.



##  System Architecture

The application follows a standard client-server architecture:

- **Frontend (Client Side):**
  - Developed using HTML, CSS, and JavaScript
  - Provides a clean and interactive user interface
  - Accepts input features related to network traffic

- **Backend (Server Side):**
  - Built using Flask framework
  - Handles incoming requests and processes input data
  - Loads pre-trained machine learning model (`model.pkl`)
  - Applies necessary preprocessing and encoding

- **Machine Learning Layer:**
  - Random Forest-based classification model
  - Predicts attack type based on input features
  - Uses label encoders for categorical data transformation



##  Working Flow of the Application

1. The user enters network-related parameters through the web interface.
2. The input data is sent to the Flask backend.
3. The backend performs preprocessing:
   - Feature scaling
   - Encoding categorical values
4. The processed input is passed to the trained model.
5. The model predicts the type of network activity:
   - Normal Traffic
   - DoS Attack
   - Probe Attack
   - R2L / U2R attacks
6. The prediction result is returned and displayed on the web interface.



##  Deployment Details

The application is deployed using Hugging Face Spaces with a Docker-based environment.

### Key Deployment Components:
- `app.py` → Flask application entry point
- `model.pkl` → Trained machine learning model
- `label_encoders.pkl` → Encoders for categorical features
- `templates/` → HTML files (UI)
- `static/` → CSS and JavaScript files
- `requirements.txt` → Python dependencies
- `Dockerfile` → Defines runtime environment

The application runs on port **7860**, which is the default port used by Hugging Face Spaces.



##  Key Features of the Web Application

- Real-time prediction of network intrusions
- User-friendly interface for easy interaction
- Integration of machine learning model with web framework
- Lightweight deployment using Docker container
- Accessible from any device via browser



##  Significance

This deployment transforms the project from a theoretical machine learning model into a practical cybersecurity tool. It demonstrates the ability to integrate data science workflows with web technologies to create deployable, real-world solutions.
The system can be further extended for real-time monitoring, integration with network systems, and large-scale intrusion detection pipelines.



