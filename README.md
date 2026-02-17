# AI Sentinel – Network Intrusion Detection System

#  Milestone 1 – Data Loading & Preprocessing

This project focuses on building an AI-powered Network Intrusion Detection System using the NSL-KDD dataset.

#  Work Completed
- Loaded NSL-KDD dataset
- Explored dataset using Pandas
- Checked duplicates and unique values
- Performed Exploratory Data Analysis (EDA)
- Visualized:
- Visualized traffic behaviour using:
 Count plots,
 Bar charts,
 Box plots,
 Heatmaps,
 Distribution plots.


  - Traffic volume by protocol
  - Distribution of source bytes
  - Protocol vs flag heatmap
- Checked missing values in `src_bytes`
- Applied log transformation to handle skewness in src_bytes
  Created a processed dataset for machine learning

# Project Structure
AI_SENTINEL_PROJECT
│
├── data/                     # Original NSL-KDD dataset
│   ├── KDDTrain+.txt
│   ├── KDDTest+.txt
│   ├── labeled_train.csv
│   └── labeled_test.csv
│
├── notebooks/
│   ├── 01_data_loading.ipynb
│   └── data/
│        └── new_dataset.csv  # Processed dataset
│
└── README.md

