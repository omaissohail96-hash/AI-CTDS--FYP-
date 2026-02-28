import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from engine.cyber_health_engine import run_cyber_health_check


# Dummy Network Flow (structure matters)
network_flow = {
    "Flow Duration": 123456,
    "Total Fwd Packet": 10,
    "Total Bwd packets": 5,
    "Total Length of Fwd Packet": 500,
    "Total Length of Bwd Packet": 300,
    "Fwd Packet Length Max": 100,
    "Fwd Packet Length Min": 20,
    "Fwd Packet Length Mean": 50,
    "Fwd Packet Length Std": 10,
    "Bwd Packet Length Max": 80,
    "Bwd Packet Length Min": 30,
    "Bwd Packet Length Mean": 60,
    "Bwd Packet Length Std": 15,
    "Flow Bytes/s": 2000,
    "Flow Packets/s": 20,
    "Flow IAT Mean": 50,
    "Flow IAT Std": 10,
    "Flow IAT Max": 100,
    "Flow IAT Min": 5,
    "Fwd IAT Total": 300,
    "Fwd IAT Mean": 50,
    "Fwd IAT Std": 10,
    "Fwd IAT Max": 100,
    "Fwd IAT Min": 5,
    "Bwd IAT Total": 200,
    "Bwd IAT Mean": 40,
    "Bwd IAT Std": 8,
    "Bwd IAT Max": 80,
    "Bwd IAT Min": 5,
    "Fwd PSH Flags": 0,
    "Bwd PSH Flags": 0,
    "Fwd URG Flags": 0,
    "Bwd URG Flags": 0,
    "Fwd Header Length": 40,
    "Bwd Header Length": 32,
    "Fwd Packets/s": 12,
    "Bwd Packets/s": 8,
    "Packet Length Min": 20,
    "Packet Length Max": 100,
    "Packet Length Mean": 60,
    "Packet Length Std": 15,
    "Packet Length Variance": 225,
    "FIN Flag Count": 0,
    "SYN Flag Count": 1,
    "RST Flag Count": 0,
    "PSH Flag Count": 0,
    "ACK Flag Count": 1,
    "URG Flag Count": 0,
    "CWR Flag Count": 0,
    "ECE Flag Count": 0,
    "Down/Up Ratio": 1,
    "Average Packet Size": 60,
    "Fwd Segment Size Avg": 50,
    "Bwd Segment Size Avg": 60,
    "Fwd Bytes/Bulk Avg": 0,
    "Fwd Packet/Bulk Avg": 0,
    "Fwd Bulk Rate Avg": 0,
    "Bwd Bytes/Bulk Avg": 0,
    "Bwd Packet/Bulk Avg": 0,
    "Bwd Bulk Rate Avg": 0,
    "Subflow Fwd Packets": 10,
    "Subflow Fwd Bytes": 500,
    "Subflow Bwd Packets": 5,
    "Subflow Bwd Bytes": 300,
    "FWD Init Win Bytes": 256,
    "Bwd Init Win Bytes": 128,
    "Fwd Act Data Pkts": 8,
    "Fwd Seg Size Min": 20,
    "Active Mean": 1000,
    "Active Std": 100,
    "Active Max": 1200,
    "Active Min": 800,
    "Idle Mean": 2000,
    "Idle Std": 300,
    "Idle Max": 2500,
    "Idle Min": 1500
}

url = "http://secure-login-paypal.verify-user.com"
email_text = body = """
Dear user,
Your account has been suspended. Click the link below to verify:
facebok.com
"""
result = run_cyber_health_check(url, network_flow , email_text)

print("\n===== CYBER HEALTH REPORT =====")
for k, v in result.items():
    print(f"{k}: {v}")
