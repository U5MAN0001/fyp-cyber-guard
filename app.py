import streamlit as st
import pandas as pd
import joblib
from groq import Groq

# --- Configuration ---
st.set_page_config(page_title="CyberGuard SOC", layout="wide")

GROQ_API_KEY = "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"

# --- Load Machine Learning Engine ---
@st.cache_resource
def load_engine():
    try:
        data = joblib.load('cyberguard_model.pkl')
        return data['model'], data['encoders'], data['features']
    except Exception as e:
        st.error(f"Backend Engine Missing. System Error: {e}")
        return None, None, None

model, encoders, feature_names = load_engine()

# --- LLM Incident Response Module ---
def generate_mitigation(traffic_details):
    try:
        client = Groq(api_key=GROQ_API_KEY)
        prompt = f"You are a Cybersecurity Expert. Analyze this network anomaly: {traffic_details}. Provide 3 short technical mitigation steps to secure the server."
        response = client.chat.completions.create(
            messages=[{"role": "user", "content": prompt}],
            model="llama-3.1-8b-instant", 
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"AI System Offline. Details: {str(e)}"

# --- Main Dashboard Interface ---
st.title("CyberGuard: AI Network Threat Analyzer")
st.markdown("Monitor real-time network traffic and identify potential security threats through **Hybrid (Rule-based + AI)** anomaly detection.")

if model:
    st.sidebar.header("Traffic Input Settings")
    
    duration = st.sidebar.number_input("Duration (sec)", min_value=0, value=0)
    protocol = st.sidebar.selectbox("Protocol Type", ['tcp', 'udp', 'icmp'])
    src_bytes = st.sidebar.number_input("Source Bytes", min_value=0, value=250)
    dst_bytes = st.sidebar.number_input("Destination Bytes", min_value=0, value=5000)
    failed_logins = st.sidebar.number_input("Failed Logins", min_value=0, value=0)
    count = st.sidebar.number_input("Connection Count", min_value=0, value=2)

    if st.sidebar.button("Analyze Packet", use_container_width=True):
        
        # 1. Structure the input data
        input_df = pd.DataFrame([[duration, protocol, src_bytes, dst_bytes, failed_logins, count]], 
                                columns=feature_names)
        input_df['protocol_type'] = input_df['protocol_type'].astype(str).str.lower().str.strip()
        
        try:
            input_df['protocol_type'] = encoders['protocol_type'].transform(input_df['protocol_type'])
            
            with st.spinner("Scanning traffic signatures..."):
                
                # =========================================================
                # 🚀 HYBRID IDS LOGIC: SOC Whitelisting (Rule-Based Engine)
                # =========================================================
                # Agar connection bilkul normal hai (0 failed logins, standard bytes) toh rule-based engine isay safe declare karega.
                is_whitelisted = False
                if failed_logins == 0 and protocol == 'tcp' and duration < 10 and src_bytes < 1000 and count <= 5:
                    is_whitelisted = True
                
                # Agar rule ne pakar liya toh ML ko bypass kar do, warna ML se pucho
                if is_whitelisted:
                    clean_prediction = 'normal'
                else:
                    raw_prediction = model.predict(input_df)[0]
                    clean_prediction = str(raw_prediction).strip().lower()
                # =========================================================

            st.markdown("---")
            if clean_prediction == 'normal':
                st.success("✅ STATUS: SECURE - No malicious activity detected in this packet.")
                st.info("🛡️ **SOC Note:** Traffic cleared by Hybrid IDS Engine (Standard Baseline Match).")
            else:
                st.error("🚨 CRITICAL ALERT: NETWORK ANOMALY DETECTED!")
                
                traffic_info = f"Protocol: {protocol}, Failed Logins: {failed_logins}, Duration: {duration}s"
                st.warning("Compiling AI-generated response plan...")
                plan = generate_mitigation(traffic_info)
                
                st.markdown("### Mitigation Strategy")
                st.info(plan)
                
        except Exception as e:
            st.error(f"Data Processing Error: {e}")

st.markdown("---")
st.caption("Developed by Muhammad Usman Murtaza | Hybrid IDS Architecture | Powered by Scikit-Learn & Llama-3.1")
