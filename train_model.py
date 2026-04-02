import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
import joblib
import os

def train_cyberguard():
    print("--- CyberGuard Model Training Started ---")

    # 1. Dataset Check
    if not os.path.exists("dataset.csv"):
        print("Error: 'dataset.csv' nahi mili. Pehle file folder mein rakhein.")
        return

    # 2. NSL-KDD Column Names
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
        # Header cleaning
        if str(df.iloc[0]['duration']).lower() == 'duration':
            df = df.iloc[1:].reset_index(drop=True)
        print(f"Dataset Loaded: {len(df)} rows found.")
    except Exception as e:
        print(f"Dataset Error: {e}")
        return

    # 3. Feature Selection (Dashboard ke features ke mutabiq)
    selected_features = ['duration', 'protocol_type', 'src_bytes', 'dst_bytes', 'num_failed_logins', 'count']
    X = df[selected_features].copy()
    y = df['class'].apply(lambda x: 'normal' if str(x).strip().lower() == 'normal' else 'anomaly')

    # 4. FIXED Encoding Logic (Sabse Important Part)
    print("⚙️ Encoding Protocols (tcp, udp, icmp)...")
    le = LabelEncoder()
    
    # AI ko pehle se hi teeno protocols sikha do
    le.fit(['tcp', 'udp', 'icmp']) 

    # Data ko saaf karo (lowercase aur extra spaces khatam)
    X['protocol_type'] = X['protocol_type'].astype(str).str.lower().str.strip()
    
    # Agar dataset mein koi ajeeb protocol ho (like 'symp'), toh usay 'tcp' bana do taake crash na ho
    X['protocol_type'] = X['protocol_type'].apply(lambda x: x if x in le.classes_ else 'tcp')
    
    # Numbers mein convert karo
    X['protocol_type'] = le.transform(X['protocol_type'])

    # Baqi numeric columns ko handle karo
    for col in X.columns:
        if col != 'protocol_type':
            X[col] = pd.to_numeric(X[col], errors='coerce').fillna(0)

    # 5. Model Training
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    print("🚀 Training Random Forest (AI Engine)...")
    model = RandomForestClassifier(n_estimators=25, max_depth=12, random_state=42)
    model.fit(X_train, y_train)

    accuracy = model.score(X_test, y_test)
    print(f"Accuracy: {accuracy * 100:.2f}%")

    # 6. Save Everything into Metadata
    # Hum 'encoders' ka poora dictionary save kar rahe hain taake app.py isay use kar sake
    joblib.dump({
        'model': model, 
        'encoders': {'protocol_type': le}, 
        'features': selected_features
    }, 'cyberguard_model.pkl')

    print("SUCCESS: 'cyberguard_model.pkl' created and ready for GitHub!")

if __name__ == "__main__":
    train_cyberguard()
