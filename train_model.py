import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
import pickle
import os

def train_and_save_model():
    print("Looking for KDDTrain+.txt...")
    train_file = 'KDDTrain+.txt'
    
    if not os.path.exists(train_file):
        print(f"Error: {train_file} not found. Cannot train NSL-KDD model.")
        return

    # Define the 43 columns specific to NSL-KDD
    columns = [
        "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
        "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
        "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations",
        "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login",
        "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate",
        "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
        "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate",
        "dst_host_diff_srv_rate", "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
        "dst_host_serror_rate", "dst_host_srv_serror_rate", "dst_host_rerror_rate",
        "dst_host_srv_rerror_rate", "attack_class", "difficulty_level"
    ]
    
    print("Loading data...")
    df = pd.read_csv(train_file, names=columns)
    
    # We don't need 'difficulty_level' for predictions
    df.drop(['difficulty_level'], axis=1, inplace=True)
    
    # Categorical columns to encode
    categorical_cols = ['protocol_type', 'service', 'flag']
    encoders = {}
    
    print("Encoding categorical variables...")
    for col in categorical_cols:
        le = LabelEncoder()
        df[col] = le.fit_transform(df[col])
        encoders[col] = le
        
        # Handle unseen labels during inference by storing full classes
        # Adding a special 'unknown' class to each encoder in case the test set has unseen labels
        classes = le.classes_.tolist()
        classes.append('unknown')
        le.classes_ = np.array(classes)
        
    X_train = df.drop('attack_class', axis=1)
    y_train = df['attack_class']
    
    print(f"Training RandomForestClassifier on {len(X_train)} rows...")
    model = RandomForestClassifier(n_estimators=50, random_state=42, n_jobs=-1)
    model.fit(X_train, y_train)
    
    print("Saving model and encoders...")
    with open('model.pkl', 'wb') as f:
        pickle.dump(model, f)
        
    with open('label_encoders.pkl', 'wb') as f:
        pickle.dump(encoders, f)
        
    print("Training complete! model.pkl and label_encoders.pkl generated.")

if __name__ == "__main__":
    train_and_save_model()
