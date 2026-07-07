# 🛡️ CyberGuard AI: Multi-Vector Threat Detection & Intrusion Prevention SaaS

CyberGuard AI is a production-grade, enterprise-ready cybersecurity SaaS platform. It leverages machine learning to classify threats across multiple attack vectors (URLs, Emails, Network Intrusion, Web Requests) and couples active threat intelligence with automated real-time Intrusion Prevention (IPS) and User Behavior Analytics (UBA).

![Security Banner](https://img.shields.io/badge/Security-AI--Powered-blueviolet?style=for-the-badge&logo=shield)
![FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688?style=for-the-badge&logo=fastapi)
![React](https://img.shields.io/badge/Frontend-React-61DAFB?style=for-the-badge&logo=react)
![SQLAlchemy](https://img.shields.io/badge/Database-SQLAlchemy-red?style=for-the-badge&logo=sqlite)

---

## 🚀 Key Platform Capabilities

*   **🧠 Asynchronous Security Orchestration**: Evaluates multi-vector payloads in parallel using python's `asyncio` for extremely low latency.
*   **🤖 Hybrid Detection Engine**: Combines true Machine Learning (Random Forest, TF-IDF) with Rule-Based Regex Heuristics and active Threat Intelligence for zero-day and known threat detection.
*   **🔌 Active Intrusion Prevention (IPS)**: Middleware intercepts client traffic and returns `403 Forbidden` for blocked entities. Expired blocks are cleared automatically by a background cron scheduler.
*   **🔐 Enterprise Security Identity**: Implements granular Role-Based Access Control (RBAC) and Multi-Factor Authentication (TOTP/QR) for secure portal administration.
*   **📊 User Behavior Analytics (UBA)**: Tracks IP logins, triggers travel alerts if geography jumps imply speeds `> 900 km/h` (Impossible Travel), monitors api usage spikes, and tracks credential brute-force attempts.
*   **🔔 Real-Time Alert Escalation & Notification**: Translates detections into enterprise alerts. Alerts auto-escalate when intelligence checks trigger or when identical anomalies hit within 24 hours. Connects to SIEM tools via outbound webhooks and sends HTML emails to analysts.
*   **📑 Audit Trail Compliance**: Auto-logs every state mutation (API Key generation, unblocking actions) in a secure audit table to satisfy SOC-2 criteria.
*   **📈 Glassmorphism Portal**: Premium dashboard with live alert feeds, threat map visualization, mitigation playbooks, and one-click unblocking controls.
*   **📄 Executive PDF Reporting**: Dependency-free PDF builder compiling security metrics and trend analysis for stakeholder reviews.

---

## 🔬 Detection Architecture Transparency

CyberGuard AI employs a defense-in-depth strategy that blends AI models with deterministic rules.

### Machine Learning (AI) Components
*   **URL Phishing Detection**: Random Forest trained on lexical features.
*   **Email Threat Detection**: Random Forest trained on email body payloads.
*   **Web Attack Detection (ML)**: TF-IDF and N-Gram extraction with Random Forest classifying SQLi, XSS, and LFI.
*   **User Behavior Analytics (UBA)**: Baseline profiling and anomaly deviation scoring.
*   **Risk Scoring**: Weighted ensemble correlating multiple signals.

### Rule-Based (Heuristic) Components
*   **Threat Intelligence**: Static lookups against malicious IP/Domain databases.
*   **Web Attack Detection (Regex)**: Deterministic regex heuristics that act as a fail-safe against ML evasion.
*   **IPS Policies**: Hardcoded rate-limits and temporary IP blocks.

**Why Hybrid?**
Relying solely on AI for web attacks can lead to bypasses via payload obfuscation. CyberGuard AI correlates the high-confidence of regex heuristics with the fuzzy-matching power of ML. If an attacker bypasses the regex, the ML vectorizer still detects the malicious intent.

---

## 🛠️ Project Directory Structure

```text
Final_Year_Project/
├── src/
│   ├── agent/               # Orchestrator & Scoring engine
│   ├── api/                 # API Routes & Custom middleware
│   │   ├── middleware.py    # IPS blocking & Compliance Audit Logging
│   │   └── v1/              # Endpoint modules (Alerts, IPS, UBA, MITRE)
│   ├── core/                # DB setup & Configuration settings
│   ├── detectors/           # ML Feature Extractors and pickle wrappers
│   ├── models/              # SQLAlchemy Database Models (11 Tables)
│   ├── services/            # Deep business logic (UBA, PDF, IPS, Alerts, MITRE)
│   └── utils/               # Scheduler & Scoring utilities
├── dashboard/               # Vite React UI Portal
│   ├── src/
│   │   ├── components/      # UI widgets (Alert panel, Scanners, Timeline)
│   │   └── pages/           # Full views (Threat Prevention, UBA, Hunt Center)
├── models/                  # Serialized Scikit-Learn Classifiers (.pkl)
├── datasets/                # Training raw dataset directory
├── SYSTEM_MANUAL.md         # Detailed system design & DB schema reference
└── README.md                # You are here
```

---

## 🚀 Quick Start

### 1. Prerequisites
*   Python 3.11+
*   Node.js 18+

### 2. Environment Setup
```powershell
# Clone the repository
git clone <your-repo-url>
cd Final_Year_Project

# Create python virtual environment
python -m venv venv
.\venv\Scripts\activate

# Install Backend Dependencies
pip install -r requirements.txt

# Install Frontend Dependencies
cd dashboard
npm install
cd ..
```

### 3. Training & Preparing ML Models
If the `/models/` directory is empty, download the datasets and run the training scripts:

#### A. URL Phishing Detection
*   **Datasets**: [Part 1](https://drive.google.com/file/d/1hCyU6SVXC_GLD0lN__WIU6C0Cyt0Alwz/view?usp=sharing) | [Part 2](https://drive.google.com/file/d/1IgKkoepmVODtIuG8BODJ7v-UVRfX0SSS/view?usp=sharing)
*   **Path**: Place `Training Dataset.arff` and `Training Dataset.old.arff` in `datasets/urls/`
*   **Train**: `python train_url_model.py`

#### B. Network Intrusion (IDS)
*   **Datasets**: [Data.csv](https://drive.google.com/file/d/1msm2Vy4ydLIzdpMwgtbGvV6F6GCkUM1P/view?usp=sharing) | [Label.csv](https://drive.google.com/file/d/1E8PKo5v6QNiMw7TNdVUInEnHagIoWQNT/view?usp=sharing)
*   **Path**: Place in `datasets/intrusion/`
*   **Train**: `python train_network_ids.py`

#### C. Email Phishing/Spam
*   **Datasets**: [CSV Part 1](https://drive.google.com/file/d/1kguN5G272BK6qQUworWdhUzOXINvdHnK/view?usp=sharing) | [Part 2](https://drive.google.com/file/d/1Qfp1tP2Itu5gjZFYS4CHeODBYiPcfgDc/view?usp=sharing) | [Part 3](https://drive.google.com/file/d/1MR1CeJzAlOTdpsFvW0YWKp1579-Ia1ph/view?usp=sharing) | [Part 4](https://drive.google.com/file/d/1JbmhNRWPTViTv_G9wICld_I_ppOKwSrV/view?usp=sharing) | [Part 5](https://drive.google.com/file/d/1UWal0wSEOnRSYrpEaeEigo9D0-hdG18B/view?usp=sharing) | [Part 6](https://drive.google.com/file/d/1K63mUXjcJx1lNvHi4jK3WUiaCm--SPBk/view?usp=sharing)
*   **Path**: Place all `.csv` files in `datasets/emails/`
*   **Train**: `python merge_and_train_email_model.py`

#### D. Web Attack Detection (SQLi/XSS)
*   **Datasets**: [SQL Payload](https://drive.google.com/file/d/1va1eyehNRRIi2OcFlKG6UY24GxR70gB2/view?usp=sharing) | [XSS Payload](https://drive.google.com/file/d/1njBX2qokk7e7-LCOlTYhL6SUCZo2IItj/view?usp=sharing)
*   **Path**: Place in `datasets/websites/`
*   **Train**: `python train_web_attack_model.py`

---

## 🏃 Running the Application

### 1. Database Initialization & Seeding
Prepare and seed threat intelligence lists and mockup records:
```powershell
python seed_test_data.py
```

### 2. Start the Backend API
```powershell
$env:PYTHONPATH="."
uvicorn src.main:app --reload --host 0.0.0.0 --port 8000
```
*   *Note*: Interactive Swagger UI documentation is available at `http://localhost:8000/docs`.

### 3. Start the React Frontend Dashboard
```powershell
cd dashboard
npm run dev
```
Open `http://localhost:5173` to access the CyberGuard dashboard.

---

## 🔐 Credentials (Demo)

Use these credentials to log in to the administrative portal during demos:
*   **User**: `test@cyberguard.ai`
*   **Password**: `TestPassword123!`

---

## 🔌 API Integration Quick Example

Incorporate CyberGuard's automated scanning in third-party services:

### Phishing URL Check (JavaScript)
```javascript
const scanURL = async (target) => {
  const res = await fetch('http://localhost:8000/api/v1/agent/analyze', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-API-KEY': 'cg_live_xxxxxx' // Retrieve from Settings Tab
    },
    body: JSON.stringify({ type: 'url', data: target })
  });
  
  const result = await res.json();
  if (result.agent_verdict.score > 80) {
    console.warn("⚠️ Malicious domain block triggered:", result.agent_verdict.summary);
  }
};
```

---

## 📚 Reference Documentation

For more granular specifications on specific subsystems, view the following resources:
*   [System Manual](file:///c:/Users/Farooq/Desktop/Final_Year_Project/SYSTEM_MANUAL.md): Full database schema configurations, orchestrator maps, and class workflows.
*   [Alert Documentation](file:///c:/Users/Farooq/Desktop/Final_Year_Project/ALERT_SYSTEM_DOCUMENTATION.md): Real-time alert lifecycle details, parameters, and SIEM webhooks.
*   [IPS Documentation](file:///c:/Users/Farooq/Desktop/Final_Year_Project/IPS_SYSTEM_DOCUMENTATION.md): Block thresholds, middleware logic, and unblock commands.
*   [IPS Deployment Guide](file:///c:/Users/Farooq/Desktop/Final_Year_Project/IPS_DEPLOYMENT_GUIDE.md): Production checklist for high-speed traffic filtering.

---
🛡️ *Developed as Final Year Project - Enterprise Intelligence Edition*
