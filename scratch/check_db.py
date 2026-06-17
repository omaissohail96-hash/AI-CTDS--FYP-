import sys
import os
sys.path.append(os.getcwd())

from src.core.database import SessionLocal
from src.models.models import ScanHistory

db = SessionLocal()
try:
    scans = db.query(ScanHistory).all()
    print(f"Total scans in DB: {len(scans)}")
    for s in scans:
        print(f"ID: {s.id} | Input Type: {s.input_type} | Verdict: {s.verdict} | Created At: {s.created_at} (type: {type(s.created_at)})")
finally:
    db.close()
