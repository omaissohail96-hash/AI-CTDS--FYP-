import sys
import os
from sqlalchemy.orm import Session
from src.core.database import SessionLocal
from src.models.models import User
from src.core.security import verify_password, get_password_hash

def check_user():
    db = SessionLocal()
    user = db.query(User).filter(User.email == "test@cyberguard.ai").first()
    if not user:
        print("User not found!")
        return

    print(f"User ID: {user.id}")
    print(f"Email: {user.email}")
    print(f"Is Active: {user.is_active}")
    print(f"Role: {user.role}")
    
    password = "TestPassword123!"
    is_valid = verify_password(password, user.hashed_password)
    print(f"Password 'TestPassword123!' valid? {is_valid}")
    
    # Let's forcefully update the password just in case
    if not is_valid:
        print("Updating password...")
        user.hashed_password = get_password_hash("TestPassword123!")
        db.commit()
        print("Password updated.")
    
    db.close()

if __name__ == "__main__":
    check_user()
