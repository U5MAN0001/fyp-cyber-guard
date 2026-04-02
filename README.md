🛡️ CyberGuard: AI Network Threat Analyzer
An Enterprise-Grade Machine Learning & Generative AI Security Operations Dashboard.

CyberGuard is a proactive network security monitoring tool designed to detect cyber anomalies in real-time. By leveraging a Random Forest Machine Learning model trained on network traffic data, it accurately classifies traffic as "Normal" or a "Cyber Attack" (such as DDoS, Brute Force, or Probe). Furthermore, it integrates with a Generative AI (LLM) engine to instantly provide IT administrators with automated, step-by-step mitigation strategies to secure the breached network.

✨ Key Features
Machine Learning Engine: Accurately classifies network traffic signatures using Scikit-Learn.

Automated Threat Intelligence: Uses the Groq API (Llama-3) to generate instant incident response and mitigation plans.

Interactive SOC Dashboard: Built with Streamlit for a seamless, enterprise-grade User Interface.

Data-Driven Processing: Handles large datasets, categorical encoding, and feature extraction securely.

🛠️ Tech Stack
Language: Python 3.9+

Data Science: Pandas, NumPy, Scikit-Learn, Joblib

Generative AI: Groq API (Llama-3 8B)

Frontend UI: Streamlit

🚀 How to Run the Project Locally
Follow these step-by-step instructions to set up and run CyberGuard on your local machine.

Step 1: Clone or Setup the Repository
Download or extract the project folder to your local machine and open it in VS Code.

Step 2: Download the Dataset
Due to GitHub size limits, the raw dataset is not included in this repository.

Download the NSL-KDD Network Intrusion Dataset from Kaggle.

Extract the archive and rename the main CSV file to dataset.csv.

Place dataset.csv directly into the root folder of this project.

Step 3: Install Dependencies
Open your terminal inside the project directory and install the required Python libraries:

Bash
pip install -r requirements.txt
Step 4: Add Your AI API Key
Get a free API key from Groq Console.

Open app.py in your text editor.

Locate the GROQ_API_KEY variable and replace "YAHAN_APNI_GROQ_KEY_PASTE_KARO" with your actual API key.

Step 5: Train the AI Engine (Backend)
Before running the dashboard, the Machine Learning model needs to be trained on the dataset. Run the following command:

Bash
python train_model.py
Note: This script will process the dataset.csv, train the Random Forest model, and generate a cyberguard_model.pkl file.

Step 6: Launch the Dashboard (Frontend)
Once the .pkl file is generated, launch the interactive web application:

Bash
streamlit run app.py
The dashboard will automatically open in your default web browser (usually at http://localhost:8501).

📁 Project Directory Structure
Plaintext
CyberGuard_FYP/
│
├── app.py                   # The Streamlit web dashboard and GenAI integration
├── train_model.py           # The ML training pipeline and data processing script
├── requirements.txt         # List of required Python packages
├── dataset.csv              # (Not in repo) The raw network traffic data
└── cyberguard_model.pkl     # (Generated) The trained ML model and encoders
⚠️ Important Notes for Evaluators
Data Streaming Simulation: For demonstration purposes within the FYP scope, the Streamlit app accepts manual input or simulated test logs to mimic a real-time Zeek/Suricata packet sniffer environment.

API Limits: The Generative AI mitigation feature relies on the free tier of the Groq API. Please allow a few seconds between consecutive analyses to prevent rate-limiting errors.

Developed by: Usman Murtaza

Program: BS Data Science

Institution: Dawood University of Engineering & Technology, Karachi
