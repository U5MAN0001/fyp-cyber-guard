import streamlit as st
import pandas as pd
import joblib
from groq import Groq

# --- CONFIGURATION (Styling & Layout) ---
st.set_page_config(page_title="CyberGuard SOC", page_icon="🛡️", layout="wide")

# API KEY
GROQ_API_KEY = "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"

# --- LOAD AI ENGINE ---
@st.cache_resource
def load_engine():
    try:
        data = joblib.load('cyberguard_model.pkl')
        return data['model'], data['encoders'], data['features']
    except Exception as e:
        st.error(f"Backend Engine Missing! Please run train_model.py. Error: {e}")
        return None, None, None

model, encoders, feature_names = load_engine()

# --- LLM INCIDENT RESPONSE (Updated Model Name) ---
def generate_mitigation(traffic_details):
    try:
        client = Groq(api_key=GROQ_API_KEY)
        prompt = f"You are a Cybersecurity Expert. Analyze this network anomaly: {traffic_details}. Provide 3 short technical mitigation steps to secure the server."
        
        # FIX: Changed from llama3-8b-8192 to llama-3.1-8b-instant
        response = client.chat.completions.create(
            messages=[{"role": "user", "content": prompt}],
            model="llama-3.1-8b-instant",
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"AI Offline. Error: {str(e)}"

# --- MAIN INTERFACE ---
st.title("🛡️ CyberGuard: AI Network Threat Analyzer")
st.markdown("Monitor real-time network traffic and identify potential security threats.")

if model:
    st.sidebar.header("Traffic Input Settings")
    
    # Input fields
    duration = st.sidebar.number_input("Duration (sec)", min_value=0, value=0)
    protocol = st.sidebar.selectbox("Protocol Type", ['tcp', 'udp', 'icmp'])
    src_bytes = st.sidebar.number_input("Source Bytes", min_value=0, value=250)
    dst_bytes = st.sidebar.number_input("Destination Bytes", min_value=0, value=5000)
    failed_logins = st.sidebar.number_input("Failed Logins", min_value=0, value=0)
    count = st.sidebar.number_input("Connection Count", min_value=0, value=2)

    if st.sidebar.button("Analyze Packet", use_container_width=True):
        # Data preparation
        input_df = pd.DataFrame([[duration, protocol, src_bytes, dst_bytes, failed_logins, count]], 
                                columns=feature_names)
        
        # Standardize input
        input_df['protocol_type'] = input_df['protocol_type'].astype(str).str.lower().str.strip()
        
        try:
            # Transform using encoder from .pkl
            input_df['protocol_type'] = encoders['protocol_type'].transform(input_df['protocol_type'])
            
            with st.spinner("Scanning traffic signatures..."):
                prediction = model.predict(input_df)[0]
                
            st.markdown("---")
            if prediction == 'normal':
                st.success("✅ **STATUS: SECURE** - No malicious activity detected.")
            else:
                st.error("🚨 **CRITICAL ALERT: ANOMALY DETECTED!**")
                
                # Incident Response Trigger
                traffic_info = f"Protocol: {protocol}, Failed Logins: {failed_logins}, Duration: {duration}s"
                st.warning("Generating AI Response Plan...")
                plan = generate_mitigation(traffic_info)
                st.info(f"### Mitigation Strategy\n{plan}")
                
        except Exception as e:
            st.error(f"Encoding Error: {e}. Please retrain your model with the latest train_model.py.")

st.markdown("---")
st.caption("Developed for BS Data Science FYP | Powered by Scikit-Learn & Llama-3.1")
