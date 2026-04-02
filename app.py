import streamlit as st
import pandas as pd
import joblib
from groq import Groq

# --- CONFIGURATION ---
st.set_page_config(page_title="CyberGuard SOC", page_icon="🛡️", layout="wide")

# TUMHARI API KEY YAHAN AAYEGI
GROQ_API_KEY = "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"

# --- LOAD AI ENGINE ---
@st.cache_resource
def load_engine():
    try:
        data = joblib.load('cyberguard_model.pkl')
        return data['model'], data['encoders'], data['features']
    except Exception as e:
        st.error("Backend Engine Missing! Run 'train_model.py' first.")
        return None, None, None

model, encoders, feature_names = load_engine()

# --- LLM INCIDENT RESPONSE FUNCTION ---
def generate_mitigation(traffic_details):
    if GROQ_API_KEY == "YAHAN_APNI_GROQ_KEY_PASTE_KARO":
        return "Please add your Groq API key in app.py to enable AI automated responses."
    
    try:
        client = Groq(api_key=GROQ_API_KEY)
        prompt = f"""
        You are an expert Cybersecurity Incident Response AI. 
        Our network monitoring system just detected an ANOMALY/ATTACK based on these traffic metrics:
        {traffic_details}
        
        Provide a very brief (3 bullet points) immediate mitigation plan to secure the server. 
        Keep it highly technical but short.
        """
        response = client.chat.completions.create(
            messages=[{"role": "user", "content": prompt}],
            model="llama3-8b-8192",
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"AI Offline. Error: {str(e)}"

# --- USER INTERFACE ---
st.title("🛡️ CyberGuard: AI Network Threat Analyzer")
st.markdown("Monitor real-time network packets and detect anomalies using Machine Learning.")

if model:
    st.sidebar.header("Live Traffic Input")
    st.sidebar.markdown("Simulate incoming network packets:")
    
    # User Inputs for the 6 features
    duration = st.sidebar.number_input("Connection Duration (sec)", min_value=0, value=0)
    protocol = st.sidebar.selectbox("Protocol Type", ['tcp', 'udp', 'icmp'])
    src_bytes = st.sidebar.number_input("Source Bytes (Data sent)", min_value=0, value=250)
    dst_bytes = st.sidebar.number_input("Destination Bytes (Data received)", min_value=0, value=5000)
    failed_logins = st.sidebar.number_input("Failed Logins", min_value=0, value=0)
    count = st.sidebar.number_input("Connection Count (Same Host)", min_value=0, value=2)

    if st.sidebar.button("Analyze Packet", use_container_width=True):
        
        # Prepare data for prediction
        input_data = pd.DataFrame([[duration, protocol, src_bytes, dst_bytes, failed_logins, count]], 
                                  columns=feature_names)
        
        # Encode string values back to numbers just like we did in training
        input_data['protocol_type'] = encoders['protocol_type'].transform([protocol])
        
        with st.spinner("Analyzing traffic signatures..."):
            prediction = model.predict(input_data)[0]
            
        st.markdown("---")
        if prediction == 'normal':
            st.success("**STATUS: SECURE** - No malicious activity detected in this packet.")
        else:
            st.error("🚨 **CRITICAL ALERT: NETWORK ANOMALY DETECTED!**")
            
            traffic_summary = f"Protocol: {protocol}, Failed Logins: {failed_logins}, Data: {src_bytes}B"
            
            st.warning("Generating AI Incident Response...")
            mitigation_plan = generate_mitigation(traffic_summary)
            
            st.info(f"### Mitigation Strategy\n{mitigation_plan}")

st.markdown("---")
st.markdown("*Developed for BS Data Science FYP | Powered by Scikit-Learn & Llama-3*")
