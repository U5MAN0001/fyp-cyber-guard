import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
import joblib
import os

print("Loading NSL-KDD Dataset...")

# 1. Check if file exists
if not os.path.exists("dataset.csv"):
    print("Error: 'dataset.csv' file folder mein nahi hai!")
    exit()

# 2. Assign Correct Column Names
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
    # Force pandas to read it with these columns
    df = pd.read_csv("dataset.csv", header=None, names=col_names, engine='python')
    
    # Agar Kaggle se aayi hui file mein galti se pehli line mein string/text tha, toh usay hata do
    if str(df.iloc[0]['duration']).lower() == 'duration':
        df = df.iloc[1:].reset_index(drop=True)
except Exception as e:
    print(f"Dataset parhne mein masla aagaya: {e}")
    exit()

print(f"Dataset Loaded! Total rows: {df.shape[0]}")

# 3. Select 6 Main Features for App
selected_features = ['duration', 'protocol_type', 'src_bytes', 'dst_bytes', 'num_failed_logins', 'count']

X = df[selected_features].copy()
# Target Variable ko binary banana (Normal vs Anomaly)
y = df['class'].apply(lambda x: 'normal' if str(x).strip().lower() == 'normal' else 'anomaly')

print("Processing Data & Encoding Text...")
encoders = {}
le = LabelEncoder()

# Protocol type (tcp, udp) ko numbers mein badalna
X['protocol_type'] = X['protocol_type'].astype(str)
X['protocol_type'] = le.fit_transform(X['protocol_type'])
encoders['protocol_type'] = le

# Data type check taake training mein error na aaye
for col in X.columns:
    if col != 'protocol_type':
        X[col] = pd.to_numeric(X[col], errors='coerce').fillna(0)

# Data Split (80% Train, 20% Test)
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

print("Training CyberGuard AI Model...")
model = RandomForestClassifier(n_estimators=20, max_depth=10, random_state=42)
model.fit(X_train, y_train)

accuracy = model.score(X_test, y_test)
print(f"Model Trained Successfully! Accuracy: {accuracy * 100:.2f}%")

# 4. Save Model
joblib.dump({'model': model, 'encoders': encoders, 'features': selected_features}, 'cyberguard_model.pkl')
print("Model saved as 'cyberguard_model.pkl'")
