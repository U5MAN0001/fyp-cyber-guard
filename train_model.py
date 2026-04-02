import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
import joblib

print("⏳ Loading Network Dataset...")

# 1. Dataset Load Karo
df = pd.read_csv("dataset.csv")

# Agar dataset mein columns ke naam nahi hain, toh hum manually de rahe hain (NSL-KDD standard)
if len(df.columns) > 40:
    columns = (['duration','protocol_type','service','flag','src_bytes','dst_bytes',
                'land','wrong_fragment','urgent','hot','num_failed_logins','logged_in',
                'num_compromised','root_shell','su_attempted','num_root','num_file_creations',
                'num_shells','num_access_files','num_outbound_cmds','is_host_login',
                'is_guest_login','count','srv_count','serror_rate','srv_serror_rate',
                'rerror_rate','srv_rerror_rate','same_srv_rate','diff_srv_rate','srv_diff_host_rate',
                'dst_host_count','dst_host_srv_count','dst_host_same_srv_rate','dst_host_diff_srv_rate',
                'dst_host_same_src_port_rate','dst_host_srv_diff_host_rate','dst_host_serror_rate',
                'dst_host_srv_serror_rate','dst_host_rerror_rate','dst_host_srv_rerror_rate','class', 'difficulty_level'])
    df.columns = columns
    # Drop difficulty_level as it's not needed for prediction
    if 'difficulty_level' in df.columns:
        df = df.drop('difficulty_level', axis=1)

# Hum UI ke liye sirf Top 6 Important Features select kar rahe hain taake app simple rahe
selected_features = ['duration', 'protocol_type', 'src_bytes', 'dst_bytes', 'num_failed_logins', 'count']
X = df[selected_features]

# Target column ('class' contains 'normal' or attack names)
# Convert all attack names to 'anomaly' to make it a binary classification (Normal vs Attack)
y = df['class'].apply(lambda x: 'normal' if x == 'normal' else 'anomaly')

print("⚙️ Processing Data & Encoding Text...")
# Text columns (like 'tcp', 'udp') ko numbers mein convert karne ke liye LabelEncoder use hoga
encoders = {}
for col in ['protocol_type']:
    le = LabelEncoder()
    X.loc[:, col] = le.fit_transform(X[col])
    encoders[col] = le

# Data Split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

print("🚀 Training CyberGuard Random Forest Model...")
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

accuracy = model.score(X_test, y_test)
print(f"✅ Model Trained Successfully! Accuracy: {accuracy * 100:.2f}%")

# Model aur Encoders ko save karo taake App.py inhein use kar sake
joblib.dump({'model': model, 'encoders': encoders, 'features': selected_features}, 'cyberguard_model.pkl')
print("💾 Model saved as 'cyberguard_model.pkl'")