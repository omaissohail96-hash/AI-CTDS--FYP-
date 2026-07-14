import uuid
import sys
import os
import random
from datetime import datetime, timedelta

sys.path.append(os.getcwd())

from src.core.database import SessionLocal
from src.models import models

def generate_mock_data():
    db = SessionLocal()
    try:
        workspace = db.query(models.Workspace).filter(models.Workspace.name == "Test Laboratory").first()
        if not workspace:
            print("Test workspace not found. Run seed_test_data.py first.")
            return

        user = db.query(models.User).filter(models.User.email == "test@cyberguard.ai").first()

        print("Generating mock ScanHistory...")
        for i in range(15):
            scan = models.ScanHistory(
                workspace_id=workspace.id,
                user_id=user.id if user else None,
                input_type=random.choice(["url", "email", "network", "web"]),
                entity=f"example-{i}.com",
                attack_type=random.choice(["PHISHING WEBSITE", "SQL INJECTION", "MALWARE DROP", "SAFE"]),
                severity=random.choice(["LOW", "MEDIUM", "HIGH", "CRITICAL"]),
                ml_confidence=random.randint(60, 99),
                risk_score=random.randint(10, 100),
                verdict=random.choice(["SAFE", "SUSPICIOUS", "MALICIOUS"]),
                created_at=datetime.utcnow() - timedelta(hours=random.randint(1, 72))
            )
            db.add(scan)

        print("Generating mock Alerts...")
        for i in range(10):
            alert = models.Alert(
                workspace_id=workspace.id,
                alert_type=random.choice(["Phishing Attempt", "Multiple Failed Logins", "SQL Injection Detected", "Impossible Travel"]),
                severity=random.choice(["MEDIUM", "HIGH", "CRITICAL"]),
                title=f"Suspicious Activity Detected #{i}",
                description="Our engines have detected abnormal behavior matching known attack vectors.",
                entity=f"192.168.1.{random.randint(1, 255)}",
                entity_type="ip",
                source_vector=random.choice(["web", "network", "auth"]),
                risk_score=random.randint(70, 100),
                ml_confidence=random.randint(80, 99),
                resolved_status=random.choice([True, False]),
                created_at=datetime.utcnow() - timedelta(hours=random.randint(1, 48))
            )
            db.add(alert)
        
        print("Generating mock UBA Profile...")
        uba = db.query(models.UserBehaviorProfile).filter(models.UserBehaviorProfile.workspace_id == workspace.id).first()
        if not uba:
            uba = models.UserBehaviorProfile(
                workspace_id=workspace.id,
                user_id=user.id if user else None,
                average_daily_logins=5,
                average_api_calls=1200,
                common_ip_addresses=["10.0.0.5", "192.168.1.150"],
                common_locations=["New York, USA", "London, UK"],
                common_login_hours=["09:00", "14:00", "18:00"],
                baseline_risk_score=15
            )
            db.add(uba)

        db.commit()
        print("Mock data generated successfully!")

    except Exception as e:
        db.rollback()
        print(f"Error generating mock data: {e}")
    finally:
        db.close()

if __name__ == "__main__":
    generate_mock_data()
