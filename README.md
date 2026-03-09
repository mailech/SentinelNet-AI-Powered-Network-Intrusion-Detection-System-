Milestone 1 – Project Initialization & Dataset Study

📅 Week 1

During the first week, the main focus was to understand the project objectives and study the dataset.

Tasks Completed

Defined the project goal and expected outcomes

Selected the NSL-KDD Dataset

Explored dataset structure and attack categories

Loaded the dataset using pandas

Performed basic statistical analysis and validation

Outcome

This step helped in understanding:

Network traffic features

Types of cyber-attacks

Structure of intrusion detection data

Week 2 – Data Cleaning & Preprocessing

In this stage, the dataset was prepared for machine learning.

Data Cleaning

The following checks were performed to improve data quality:

Checked for missing values

Verified duplicate records

Reviewed feature types (numerical and categorical)

Data Preprocessing

Several preprocessing techniques were applied to prepare the dataset.

Converted categorical features into numerical format

Organized cleaned data into CSV files

Prepared training and testing datasets

Dataset Handling

The dataset was explored using pandas to understand its structure.

Tasks performed:

Loaded the dataset

Checked duplicates and unique values

Verified column distributions

Exploratory Data Analysis (EDA)

EDA was performed to understand patterns in network traffic behavior.

Visualizations Created

Traffic volume by protocol

Distribution of source bytes

Protocol vs flag heatmap

These visualizations helped identify patterns that may indicate suspicious activity.

Data Quality Checks

Additional validation checks were performed to ensure data reliability.

Example:

Checked missing values in src_bytes

Verified consistency in network traffic records

Milestone 2 – Feature Engineering & Data Optimization

This stage focused on transforming raw network traffic data into a structured dataset suitable for machine learning.

Feature Scaling

Numerical features were standardized using StandardScaler.

Purpose:

Ensure all numerical variables have similar scale

Improve model performance

Prepare data for dimensionality reduction

One-Hot Encoding

Categorical attributes such as:

protocol type

service

flag

were converted into numerical format using OneHotEncoder.

Purpose:

Machine learning algorithms cannot process text categories, so they must be converted into binary numerical values.

Feature Engineering

Additional derived features were created by combining related network attributes.

Examples include:

byte-level interactions

packet-level behavior patterns

These transformations improve the representation of network activity and help models detect anomalies more effectively.

Correlation Analysis

A correlation matrix was generated to identify highly correlated features.

Highly correlated columns were removed to:

reduce redundancy

prevent multicollinearity

simplify the dataset

Noise Reduction

Low-variance and irrelevant features were removed.

Purpose:

reduce noise in the dataset

improve model accuracy

speed up model training

Class Imbalance Handling

The dataset originally had more normal traffic than attack traffic.

To balance the dataset, SMOTE was applied.

SMOTE creates synthetic samples for minority classes so the model can learn from balanced data.

Dimensionality Reduction

To simplify the dataset, Principal Component Analysis was applied.

Purpose:

reduce the number of features

retain maximum variance

improve computational efficiency

After PCA, the dataset was reduced to:

36 optimized features/components

Machine Learning Pipeline

A machine learning pipeline was created to automate the entire preprocessing and training process.

The pipeline consists of the following stages:

1️⃣ Imputing Station

Missing values are handled using median or most frequent strategies.

2️⃣ Scaling Station

Numerical features are standardized to ensure consistent distribution.

3️⃣ Categorical Encoding

Categorical variables are converted into numerical values using One-Hot Encoding.

4️⃣ Feature Selection

Important features are selected using Random Forest.

5️⃣ Classifier

The final model uses Random Forest to classify network traffic as normal or attack.
