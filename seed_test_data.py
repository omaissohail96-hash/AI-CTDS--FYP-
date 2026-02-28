import uuid
import sys
import os
from datetime import datetime

# Add current directory to path so we can import src
sys.path.append(os.getcwd())

from src.core.database import SessionLocal, engine
from src.models import models
from src.core.security import get_password_hash

def seed_test_data():
    print("Initializing database tables...")
    # Explicitly ensure models are registered
    from src.models.models import Base, Workspace, User, ThreatIntel
    Base.metadata.create_all(bind=engine)
    
    db = SessionLocal()
    try:
        # 1. Create Workspace
        print("Checking for Test workspace...")
        workspace = db.query(models.Workspace).filter(models.Workspace.name == "Test Laboratory").first()
        if not workspace:
            workspace = models.Workspace(
                id=uuid.uuid4(),
                name="Test Laboratory",
                tier="pro",
                monthly_quota=1000,
                rate_limit_rpm=60
            )
            db.add(workspace)
            db.commit()
            db.refresh(workspace)
            print(f"Created Workspace: {workspace.name}")
        else:
            print(f"Workspace {workspace.name} already exists")

        # 2. Create User
        print("Checking for Test user...")
        user = db.query(models.User).filter(models.User.email == "test@cyberguard.ai").first()
        if not user:
            user = models.User(
                id=uuid.uuid4(),
                workspace_id=workspace.id,
                email="test@cyberguard.ai",
                hashed_password=get_password_hash("TestPassword123!"),
                full_name="Test Engineer",
                role="admin"
            )
            db.add(user)
            db.commit()
            print(f"Created User: {user.email}")
        else:
            print(f"User {user.email} already exists")

        # 3. Create Sample Threat Intel Data
        print("Seeding Threat Intelligence...")
        threats = [
            {"value": "evil-phishing.com", "type": "domain", "threat": "phishing", "level": "critical"},
            {"value": "192.168.1.100", "type": "ip", "threat": "botnet", "level": "high"},
            {"value": "malware-drop.ru", "type": "domain", "threat": "malware", "level": "critical"}
        ]
        
        for t in threats:
            exists = db.query(ThreatIntel).filter(ThreatIntel.entity_value == t["value"]).first()
            if not exists:
                intel = ThreatIntel(
                    entity_value=t["value"],
                    entity_type=t["type"],
                    threat_type=t["threat"],
                    risk_level=t["level"],
                    source="local",
                    last_synced=datetime.utcnow()
                )
                db.add(intel)
                print(f"Seeded Intel: {t['value']}")
        
        db.commit()

    except Exception as e:
        print(f"Error seeding data: {e}")
    finally:
        db.close()

if __name__ == "__main__":
    seed_test_data()
