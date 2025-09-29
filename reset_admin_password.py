"""
Emergency Admin Password Reset Script
This script resets the himolee admin password and provides the new password
"""

import os
import sys
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from passlib.context import CryptContext
from datetime import datetime
import secrets
import string

# Database setup (same as main.py)
DATABASE_URL = "sqlite:///./marvin.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime)
    is_active = Column(Integer, default=1)  # 1 = active, 0 = disabled
    is_admin = Column(Integer, default=0)   # 0 = user, 1 = admin, 2 = super admin
    failed_login_attempts = Column(Integer, default=0)

def generate_secure_password(length=12):
    """Generate a secure random password"""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    password = ''.join(secrets.choice(alphabet) for _ in range(length))
    return password

def hash_password(password: str) -> str:
    """Hash a password"""
    return pwd_context.hash(password)

def reset_himolee_password():
    """Reset himolee admin password"""
    db = SessionLocal()
    
    try:
        # Find himolee user
        user = db.query(User).filter(User.username == "himolee").first()
        
        if not user:
            print("❌ ERROR: himolee user not found in database!")
            return None
        
        # Generate new secure password
        new_password = generate_secure_password(12)
        
        # Hash the new password
        hashed_password = hash_password(new_password)
        
        # Update user record
        user.hashed_password = hashed_password
        user.failed_login_attempts = 0  # Reset failed attempts
        user.is_active = 1  # Ensure account is active
        user.is_admin = 2   # Ensure super admin status
        
        # Commit changes
        db.commit()
        
        print("✅ SUCCESS: himolee password has been reset!")
        print(f"🔑 New Password: {new_password}")
        print(f"👤 Username: himolee")
        print(f"🔒 Admin Level: Super Admin (Level 2)")
        print(f"📅 Reset Time: {datetime.utcnow().isoformat()}")
        
        return new_password
        
    except Exception as e:
        print(f"❌ ERROR: Failed to reset password: {str(e)}")
        db.rollback()
        return None
    
    finally:
        db.close()

if __name__ == "__main__":
    print("🔄 Resetting himolee admin password...")
    print("=" * 50)
    
    new_password = reset_himolee_password()
    
    if new_password:
        print("=" * 50)
        print("✅ Password reset completed successfully!")
        print("🌐 You can now log in at: https://marvin-ai-assistant.onrender.com")
        print("⚠️  Please change this password after logging in!")
    else:
        print("=" * 50)
        print("❌ Password reset failed!")
        print("💡 Please check the database connection and try again.")
