#!/usr/bin/env python3
"""
Database migration script to make himolee a super admin
Run this once to upgrade the existing user to super admin status
"""

import os
import sys
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime

# Configuration
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./marvin.db")

# Database setup
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# User model (matching main.py)
class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_admin = Column(Integer, default=0)  # 0=user, 1=admin, 2=super_admin
    is_active = Column(Integer, default=1)  # 0=disabled, 1=active
    last_login = Column(DateTime, nullable=True)
    failed_login_attempts = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)

def migrate_database():
    """Add new columns to existing users table and make himolee super admin"""
    
    # Create database session
    db = SessionLocal()
    
    try:
        # First, try to add the new columns (this will fail if they already exist, which is fine)
        try:
            engine.execute("ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0")
            print("✅ Added is_admin column")
        except:
            print("ℹ️  is_admin column already exists")
            
        try:
            engine.execute("ALTER TABLE users ADD COLUMN is_active INTEGER DEFAULT 1")
            print("✅ Added is_active column")
        except:
            print("ℹ️  is_active column already exists")
            
        try:
            engine.execute("ALTER TABLE users ADD COLUMN last_login DATETIME")
            print("✅ Added last_login column")
        except:
            print("ℹ️  last_login column already exists")
            
        try:
            engine.execute("ALTER TABLE users ADD COLUMN failed_login_attempts INTEGER DEFAULT 0")
            print("✅ Added failed_login_attempts column")
        except:
            print("ℹ️  failed_login_attempts column already exists")
        
        # Find himolee user and make super admin
        himolee = db.query(User).filter(User.username == "himolee").first()
        
        if himolee:
            himolee.is_admin = 2  # Super admin
            himolee.is_active = 1  # Active
            himolee.failed_login_attempts = 0  # Reset any failed attempts
            db.commit()
            print("🎉 Successfully made himolee a super admin!")
            print(f"   User ID: {himolee.id}")
            print(f"   Username: {himolee.username}")
            print(f"   Admin Level: {himolee.is_admin} (2=super_admin)")
            print(f"   Status: {'Active' if himolee.is_active else 'Disabled'}")
        else:
            print("❌ User 'himolee' not found in database!")
            print("   Make sure the user exists before running this migration.")
            return False
            
        return True
        
    except Exception as e:
        print(f"❌ Migration failed: {str(e)}")
        db.rollback()
        return False
        
    finally:
        db.close()

if __name__ == "__main__":
    print("🔧 Starting database migration...")
    print(f"📁 Database: {DATABASE_URL}")
    
    success = migrate_database()
    
    if success:
        print("\n✅ Migration completed successfully!")
        print("🔒 Security features activated:")
        print("   - himolee is now super admin")
        print("   - Admin role system enabled")
        print("   - Account locking system active")
        print("   - Enhanced login security enabled")
    else:
        print("\n❌ Migration failed!")
        sys.exit(1)
