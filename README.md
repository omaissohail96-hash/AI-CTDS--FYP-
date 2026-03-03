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
- **Dataset**: [UCI Phishing Websites Dataset](https://archive.ics.uci.edu/ml/datasets/phishing+websites)
- **File**: Place `Training Dataset.arff` in `datasets/urls/`
- **Train**:
  ```powershell
  python train_url_model.py
  ```

### 2. Network Intrusion (IDS)
- **Dataset**: [NSL-KDD](https://www.unb.ca/cic/datasets/nsl-kdd.html)
- **Files**: Place `Data.csv` and `label.csv` in `datasets/intrusion/`
- **Train**:
  ```powershell
  python train_network_ids.py
  ```

### 3. Email Phishing/Spam
- **Dataset**: Combined Enron & Ling-spam datasets.
- **Files**: Place `.csv` files in `datasets/emails/`
- **Train**:
  ```powershell
  python merge_and_train_email_model.py
  ```

### 4. Web Attack Detection (SQLi/XSS)
- **Dataset**: Custom web request logs with malicious payloads.
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

## 🔌 API Integration Guide

CyberGuard AI is built for seamless, headless integration. You can generate API keys in the **Settings** tab of the Dashboard to protect your own business workflows.

### 1. Authentication
All API requests must include your API key in the `X-API-KEY` header.
- **Header**: `X-API-KEY: your_generated_key_here`

### 2. Integration Scenarios

#### 📧 Email Protection (Python Example)
Scan incoming email content for phishing before it results in a user breach.
```python
import requests

API_URL = "http://localhost:8000/api/v1/agent/analyze"
HEADERS = {"X-API-KEY": "cg_live_xxxxxx"}

payload = {
    "type": "email",
    "data": {
        "subject": "Urgent Action Required",
        "body": "Your bank account has been locked. Verify here: http://evil-phishing.com"
    }
}

response = requests.post(API_URL, json=payload, headers=HEADERS)
verdict = response.json()["agent_verdict"]

if verdict["label"] == "CRITICAL":
    print(f"🚨 BLOCKED: {verdict['summary']}")
```

#### 🌐 Website Security (JavaScript/Fetch)
Validate user-submitted URLs or comments in real-time to prevent malicious links.
```javascript
const sanitizeInput = async (userInput) => {
  const response = await fetch('http://localhost:8000/api/v1/agent/analyze', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-API-KEY': 'cg_live_xxxxxx'
    },
    body: JSON.stringify({ type: 'url', data: userInput })
  });
  
  const result = await response.json();
  if (result.agent_verdict.score > 80) {
    console.error("⚠️ Malicious entity detected. Blocking request.");
    return false;
  }
  return true;
};
```

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