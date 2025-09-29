"""
Add a temporary password reset endpoint to the application
"""

from fastapi import FastAPI, Request, Form, Depends, HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import os
from passlib.context import CryptContext
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
import secrets
import string

app = FastAPI()

# Mount static files
app.mount("/static", StaticFiles(directory="frontend/static"), name="static")
templates = Jinja2Templates(directory="frontend/templates")

# Database setup
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

def generate_secure_password(length=10):
    """Generate a secure random password"""
    alphabet = string.ascii_letters + string.digits
    password = ''.join(secrets.choice(alphabet) for _ in range(length))
    return password

def hash_password(password: str) -> str:
    """Hash a password"""
    # Ensure password is not longer than 72 bytes (bcrypt limit)
    password = password[:72] if len(password.encode('utf-8')) > 72 else password
    return pwd_context.hash(password)

@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    return RedirectResponse(url="/login")

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.get("/chat", response_class=HTMLResponse)
async def chat_page(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

@app.get("/reset-himolee-password")
async def reset_himolee_password():
    """Temporary endpoint to reset himolee password"""
    # Create tables if they don't exist
    Base.metadata.create_all(bind=engine)
    
    db = SessionLocal()
    
    try:
        # Check if himolee user exists
        user = db.query(User).filter(User.username == "himolee").first()
        
        if user:
            # Generate new secure password
            new_password = "MarvinAdmin2025"
            
            # Hash the new password
            hashed_password = hash_password(new_password)
            
            # Update user record
            user.hashed_password = hashed_password
            user.failed_login_attempts = 0  # Reset failed attempts
            user.is_active = 1  # Ensure account is active
            user.is_admin = 2   # Ensure super admin status
            
            # Commit changes
            db.commit()
            
            return JSONResponse(content={
                "status": "success",
                "message": "himolee password has been reset",
                "username": "himolee",
                "password": new_password,
                "admin_level": 2
            })
        else:
            # Create himolee user
            new_password = "MarvinAdmin2025"
            
            # Hash the new password
            hashed_password = hash_password(new_password)
            
            # Create new user
            new_user = User(
                username="himolee",
                hashed_password=hashed_password,
                is_active=1,
                is_admin=2  # Super admin
            )
            
            db.add(new_user)
            db.commit()
            
            return JSONResponse(content={
                "status": "success",
                "message": "himolee user has been created",
                "username": "himolee",
                "password": new_password,
                "admin_level": 2
            })
        
    except Exception as e:
        db.rollback()
        return JSONResponse(
            status_code=500,
            content={
                "status": "error",
                "message": f"Failed to reset password: {str(e)}"
            }
        )
    
    finally:
        db.close()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
