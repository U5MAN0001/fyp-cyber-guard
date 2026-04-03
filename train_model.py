import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
import joblib
import os

def train_cyberguard():
    print("--- CyberGuard Model Training Started ---")

    if not os.path.exists("dataset.csv"):
        print("Error: 'dataset.csv' not found. Please ensure the file is in the correct directory.")
        return

    col_names = ['duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
               'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
               'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
               'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login',
               'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
               'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate',
               'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
               'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate', 'dst_host_serror_rate',
               'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'class', 'difficulty_level']

    try:
        df = pd.read_csv("dataset.csv", header=None, names=col_names, engine='python', on_bad_lines='skip')
        if str(df.iloc[0]['duration']).lower() == 'duration':
            df = df.iloc[1:].reset_index(drop=True)
        print(f"Dataset Loaded Successfully: {len(df)} records found.")
    except Exception as e:
        print(f"Dataset Error: {e}")
        return

    selected_features = ['duration', 'protocol_type', 'src_bytes', 'dst_bytes', 'num_failed_logins', 'count']
    X = df[selected_features].copy()
    
    # FIX: Using 'in' operator to catch variations like 'normal.' or 'Normal'
    y = df['class'].apply(lambda x: 'normal' if 'normal' in str(x).strip().lower() else 'anomaly')

    print("Encoding Network Protocols...")
    le = LabelEncoder()
    le.fit(['tcp', 'udp', 'icmp']) 

    X['protocol_type'] = X['protocol_type'].astype(str).str.lower().str.strip()
    X['protocol_type'] = X['protocol_type'].apply(lambda x: x if x in le.classes_ else 'tcp')
    X['protocol_type'] = le.transform(X['protocol_type'])

    for col in X.columns:
        if col != 'protocol_type':
            X[col] = pd.to_numeric(X[col], errors='coerce').fillna(0)

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    print("Training Random Forest Classifier...")
    model = RandomForestClassifier(n_estimators=25, max_depth=12, random_state=42)
    model.fit(X_train, y_train)

    accuracy = model.score(X_test, y_test)
    print(f"Model Accuracy: {accuracy * 100:.2f}%")

    joblib.dump({
        'model': model, 
        'encoders': {'protocol_type': le}, 
        'features': selected_features
    }, 'cyberguard_model.pkl')

    print("SUCCESS: 'cyberguard_model.pkl' created successfully.")

if __name__ == "__main__":
    train_cyberguard()
