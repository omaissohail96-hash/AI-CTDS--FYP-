# 🛡️ CyberGuard AI: Multi-Vector Threat Detection SaaS

CyberGuard AI is an enterprise-grade security platform that leverages machine learning to detect and correlate threats across multiple attack vectors, including URLs, Emails, Network Traffic, and Web Applications.

![CyberGuard Banner](https://img.shields.io/badge/Security-AI--Powered-blueviolet?style=for-the-badge&logo=shield)
![FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688?style=for-the-badge&logo=fastapi)
![React](https://img.shields.io/badge/Frontend-React-61DAFB?style=for-the-badge&logo=react)

---

## 🚀 Quick Start

### 1. Requirements
- Python 3.11+
- Node.js 18+
- SQLite (Local development) or PostgreSQL (Production)

### 2. Installation
```powershell
# Clone the repository
git clone <your-repo-url>
cd Final_Year_Project

# Setup Backend
pip install -r requirements.txt

# Setup Frontend
cd dashboard
npm install
```

### 3. Running the App
**Start Backend:**
```powershell
# From project root
$env:PYTHONPATH="."
uvicorn src.main:app --reload
```
**Start Frontend:**
```powershell
# From /dashboard
npm run dev
```

---

## 📊 Datasets & Model Training

The system core relies on several specialized ML models. If the `models/` folder is empty, you must download the datasets and run the training scripts.

### 1. URL Phishing Detection
- **Dataset**: [UCI Phishing Websites Dataset](https://drive.google.com/file/d/1hCyU6SVXC_GLD0lN__WIU6C0Cyt0Alwz/view?usp=sharing and https://drive.google.com/file/d/1IgKkoepmVODtIuG8BODJ7v-UVRfX0SSS/view?usp=sharing)
- **File**: Place `Training Dataset.arff and .old.arff` in `datasets/urls/`
- **Train**:
  ```powershell
  python train_url_model.py
  ```

### 2. Network Intrusion (IDS)
- **Dataset**: [NSL-KDD](https://drive.google.com/file/d/1msm2Vy4ydLIzdpMwgtbGvV6F6GCkUM1P/view?usp=sharing and https://drive.google.com/file/d/1E8PKo5v6QNiMw7TNdVUInEnHagIoWQNT/view?usp=sharing)
- **Files**: Place `Data.csv` and `label.csv` in `datasets/intrusion/`
- **Train**:
  ```powershell
  python train_network_ids.py
  ```

### 3. Email Phishing/Spam
- **Dataset**: (https://drive.google.com/file/d/1kguN5G272BK6qQUworWdhUzOXINvdHnK/view?usp=sharing
                https://drive.google.com/file/d/1Qfp1tP2Itu5gjZFYS4CHeODBYiPcfgDc/view?usp=sharing
                https://drive.google.com/file/d/1MR1CeJzAlOTdpsFvW0YWKp1579-Ia1ph/view?usp=sharing
                https://drive.google.com/file/d/1JbmhNRWPTViTv_G9wICld_I_ppOKwSrV/view?usp=sharing
                https://drive.google.com/file/d/1UWal0wSEOnRSYrpEaeEigo9D0-hdG18B/view?usp=sharing
                https://drive.google.com/file/d/1K63mUXjcJx1lNvHi4jK3WUiaCm--SPBk/view?usp=sharing)
- **Files**: Place `.csv` files in `datasets/emails/`
- **Train**:
  ```powershell
  python merge_and_train_email_model.py
  ```

### 4. Web Attack Detection (SQLi/XSS)
- **Dataset**: Custom web request logs with malicious payloads(https://drive.google.com/file/d/1va1eyehNRRIi2OcFlKG6UY24GxR70gB2/view?usp=sharing and 
                https://drive.google.com/file/d/1njBX2qokk7e7-LCOlTYhL6SUCZo2IItj/view?usp=sharing).
- **Files**: Place in `datasets/websites/`
- **Train**:
  ```powershell
  python train_web_attack_model.py
  ```

---

## 🧠 System Intelligence

### Cross-Vector Correlation
The **Correlation Engine** tracks entities (IPs, Domains) across different scans. If a malicious domain appears in both an email and a URL scan within 24 hours, the risk score is automatically boosted.

### Threat Intelligence
The platform includes a local **ThreatIntel** service that checks every scan against a high-speed cached blacklist of known malicious entities.

### Audit Logging
Enterprise compliance is maintained via a global **Audit Middleware** that records every security-sensitive mutation in the system.

---

## 🛠️ Project Structure
- `/src/api/v1/`: API endpoints (Auth, Agent, Workspace).
- `/src/agent/`: AI Orchestrator logic.
- `/src/services/`: Intelligence and Detection services.
- `/detectors/`: Feature extractors and model wrappers.
- `/models/`: Serialized ML models (`.pkl`).
- `/dashboard/`: React frontend application.

---

## 🔐 Credentials (Demo)
- **User**: `test@cyberguard.ai`
- **Password**: `TestPassword123!`

---
🛡️ *Developed as Final Year Project - Enterprise Intelligence Edition*
