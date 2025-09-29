from fastapi import FastAPI, Request, Depends, HTTPException, status, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from passlib.context import CryptContext
from datetime import datetime, timedelta
import jwt
import os
import httpx
import asyncio
from typing import Optional
from security_hardening import (
    SecurityMiddleware, CSRFProtection, SecurityHeaders,
    log_security_event, validate_username, security_health_check
)

# Configuration
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-change-this")
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./marvin.db")
DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY", "")
DEEPSEEK_API_URL = "https://api.deepseek.com/v1/chat/completions"
ALLOWED_IPS = os.getenv("ALLOWED_IPS", "").split(",") if os.getenv("ALLOWED_IPS") else []

# Database setup
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Models
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

class ChatMessage(Base):
    __tablename__ = "chat_messages"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer)
    message = Column(Text)
    response = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)

# Create tables
Base.metadata.create_all(bind=engine)

# Security
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

app = FastAPI(title="Marvin - Personal AI Assistant")

# Security middleware
@app.middleware("http")
async def security_middleware(request: Request, call_next):
    # Rate limiting
    client_ip = request.client.host
    if not SecurityMiddleware.check_rate_limit(client_ip):
        log_security_event("rate_limit_exceeded", {"ip": client_ip}, client_ip)
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    
    # Process request
    response = await call_next(request)
    
    # Add security headers
    security_headers = SecurityHeaders.get_security_headers()
    for header, value in security_headers.items():
        response.headers[header] = value
    
    return response

# Static files and templates
app.mount("/static", StaticFiles(directory="frontend/static"), name="static")
templates = Jinja2Templates(directory="frontend/templates")

# Dependency to get database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# IP whitelist middleware
@app.middleware("http")
async def ip_whitelist_middleware(request: Request, call_next):
    if ALLOWED_IPS and request.client.host not in ALLOWED_IPS:
        raise HTTPException(status_code=403, detail="Access forbidden")
    response = await call_next(request)
    return response

# Authentication functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(hours=24)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm="HS256")
    return encoded_jwt

def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        username: str = payload.get("sub")
        if username is None:
            return None
        return username
    except jwt.PyJWTError:
        return None

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security), db: Session = Depends(get_db)):
    username = verify_token(credentials.credentials)
    if username is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return user

# Routes
@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login")
async def login(request: Request, username: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    client_ip = request.client.host
    
    # Input validation and sanitization
    username = SecurityMiddleware.validate_input(username, 50)
    if not validate_username(username):
        log_security_event("invalid_username_attempt", {"username": username}, client_ip)
        return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid credentials"})
    
    user = db.query(User).filter(User.username == username).first()
    
    # Check if user exists and is active
    if not user:
        log_security_event("login_attempt_nonexistent_user", {"username": username}, client_ip)
        return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid credentials"})
    
    if user.is_active == 0:
        log_security_event("login_attempt_disabled_user", {"username": username}, client_ip)
        return templates.TemplateResponse("login.html", {"request": request, "error": "Account is disabled. Contact administrator."})
    
    # Check failed login attempts (basic rate limiting)
    if user.failed_login_attempts >= 5:
        log_security_event("login_attempt_locked_account", {"username": username}, client_ip)
        return templates.TemplateResponse("login.html", {"request": request, "error": "Account locked due to too many failed attempts. Contact administrator."})
    
    # Verify password
    if not verify_password(password, user.hashed_password):
        # Increment failed login attempts
        user.failed_login_attempts += 1
        db.commit()
        log_security_event("failed_login_attempt", {
            "username": username, 
            "attempts": user.failed_login_attempts
        }, client_ip)
        return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid credentials"})
    
    # Successful login - reset failed attempts and update last login
    user.failed_login_attempts = 0
    user.last_login = datetime.utcnow()
    db.commit()
    
    # Log successful login
    log_security_event("successful_login", {
        "username": username,
        "admin_level": user.is_admin,
        "redirect": "/admin" if user.is_admin == 2 else "/chat"
    }, client_ip)
    
    # Create token with admin info
    access_token = create_access_token(data={"sub": user.username, "admin": user.is_admin})
    
    # Redirect to admin panel if super admin, otherwise to chat
    redirect_url = "/admin" if user.is_admin == 2 else "/chat"
    response = RedirectResponse(url=redirect_url, status_code=302)
    response.set_cookie(key="access_token", value=f"Bearer {access_token}", httponly=True, secure=True, samesite="strict")
    return response

# Registration disabled for security - admin only user creation
@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request, "error": "Registration is disabled. Contact administrator."})

@app.post("/register")
async def register(request: Request, username: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    return templates.TemplateResponse("login.html", {"request": request, "error": "Registration is disabled. Contact administrator."})

@app.get("/chat", response_class=HTMLResponse)
async def chat_page(request: Request):
    token = request.cookies.get("access_token")
    if not token:
        return RedirectResponse(url="/login")
    
    try:
        username = verify_token(token.replace("Bearer ", ""))
        if not username:
            return RedirectResponse(url="/login")
    except:
        return RedirectResponse(url="/login")
    
    return templates.TemplateResponse("chat.html", {"request": request, "username": username})

@app.post("/api/chat")
async def chat_api(request: Request, message: str = Form(...), db: Session = Depends(get_db)):
    client_ip = request.client.host
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    username = verify_token(token.replace("Bearer ", ""))
    
    # Input validation and sanitization
    message = SecurityMiddleware.validate_input(message, 2000)
    if not message.strip():
        raise HTTPException(status_code=400, detail="Message cannot be empty")
    
    # Log chat interaction
    log_security_event("chat_message", {
        "username": username,
        "message_length": len(message)
    }, client_ip)
    if not username:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Call DeepSeek API
    try:
        if not DEEPSEEK_API_KEY:
            ai_response = "DeepSeek API key not configured. Please set DEEPSEEK_API_KEY environment variable."
        else:
            async with httpx.AsyncClient() as client:
                headers = {
                    "Authorization": f"Bearer {DEEPSEEK_API_KEY}",
                    "Content-Type": "application/json"
                }
                payload = {
                    "model": "deepseek-chat",
                    "messages": [
                        {"role": "system", "content": "You are Marvin, a helpful AI assistant. Be concise and helpful."},
                        {"role": "user", "content": message}
                    ],
                    "max_tokens": 1000,
                    "temperature": 0.7
                }
                response = await client.post(
                    DEEPSEEK_API_URL,
                    json=payload,
                    headers=headers,
                    timeout=30.0
                )
                if response.status_code == 200:
                    result = response.json()
                    ai_response = result["choices"][0]["message"]["content"]
                else:
                    ai_response = f"I'm sorry, I'm having trouble processing your request. (Status: {response.status_code})"
    except Exception as e:
        ai_response = f"I'm sorry, the AI service is currently unavailable. Error: {str(e)}"
    
    # Save to database
    chat_message = ChatMessage(
        user_id=user.id,
        message=message,
        response=ai_response
    )
    db.add(chat_message)
    db.commit()
    
    return {"response": ai_response}

@app.post("/logout")
async def logout():
    response = RedirectResponse(url="/login", status_code=302)
    response.delete_cookie(key="access_token")
    return response

# Admin upgrade endpoint (remove after use)
@app.get("/upgrade-admin-himolee-secret-endpoint-2024")
async def upgrade_himolee_admin(db: Session = Depends(get_db)):
    """Special one-time endpoint to upgrade himolee to super admin"""
    try:
        # Find himolee user
        himolee = db.query(User).filter(User.username == "himolee").first()
        
        if not himolee:
            return {"error": "User 'himolee' not found"}
        
        # Check if already admin
        if himolee.is_admin == 2:
            return {"message": "himolee is already a super admin", "status": "already_admin"}
        
        # Upgrade to super admin
        himolee.is_admin = 2  # Super admin
        himolee.is_active = 1  # Ensure active
        himolee.failed_login_attempts = 0  # Reset failed attempts
        db.commit()
        
        return {
            "message": "Successfully upgraded himolee to super admin!",
            "user_id": himolee.id,
            "username": himolee.username,
            "admin_level": himolee.is_admin,
            "status": "upgraded"
        }
        
    except Exception as e:
        return {"error": f"Upgrade failed: {str(e)}"}

# Temporary endpoint to create himolee admin account
@app.get("/create-himolee-admin-emergency")
async def create_himolee_admin_emergency(db: Session = Depends(get_db)):
    """Emergency endpoint to create himolee admin account"""
    import secrets
    import string
    
    try:
        # Check if himolee already exists
        existing_user = db.query(User).filter(User.username == "himolee").first()
        if existing_user:
            return {"error": "himolee user already exists", "message": "Use password reset endpoint instead"}
        
        # Generate secure password
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        password = ''.join(secrets.choice(alphabet) for _ in range(12))
        
        # Create himolee admin user
        new_user = User(
            username="himolee",
            hashed_password=hash_password(password),
            is_admin=2,  # Super admin
            is_active=1,  # Active
            failed_login_attempts=0,
            created_at=datetime.utcnow()
        )
        
        db.add(new_user)
        db.commit()
        
        return {
            "status": "success",
            "message": "himolee admin account created successfully!",
            "username": "himolee",
            "password": password,
            "admin_level": "Super Admin (Level 2)",
            "login_url": "https://marvin-ai-assistant.onrender.com/login",
            "warning": "Please change this password after logging in!"
        }
        
    except Exception as e:
        return {"status": "error", "message": f"Failed to create account: {str(e)}"}

# Helper functions for admin access
def get_current_user_admin_level(token: str, db: Session):
    """Get current user's admin level from token"""
    try:
        payload = jwt.decode(token.replace("Bearer ", ""), SECRET_KEY, algorithms=["HS256"])
        username = payload.get("sub")
        admin_level = payload.get("admin", 0)
        
        if username:
            user = db.query(User).filter(User.username == username).first()
            if user:
                return user, admin_level
    except:
        pass
    return None, 0

def require_super_admin(request: Request, db: Session = Depends(get_db)):
    """Require super admin access"""
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    user, admin_level = get_current_user_admin_level(token, db)
    if not user or admin_level < 2:
        raise HTTPException(status_code=403, detail="Super admin access required")
    
    return user

# Admin Panel Routes
@app.get("/admin", response_class=HTMLResponse)
async def admin_panel(request: Request, current_user: User = Depends(require_super_admin)):
    return templates.TemplateResponse("admin.html", {"request": request, "username": current_user.username})

@app.post("/admin/create-user")
async def admin_create_user(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    admin_level: int = Form(...),
    current_user: User = Depends(require_super_admin),
    db: Session = Depends(get_db)
):
    """Create new user (admin only)"""
    try:
        # Check if user already exists
        existing_user = db.query(User).filter(User.username == username).first()
        if existing_user:
            return {"success": False, "error": "Username already exists"}
        
        # Create new user
        hashed_password = get_password_hash(password)
        new_user = User(
            username=username,
            hashed_password=hashed_password,
            is_admin=admin_level,
            is_active=1
        )
        db.add(new_user)
        db.commit()
        
        return {"success": True, "message": f"User '{username}' created successfully"}
        
    except Exception as e:
        return {"success": False, "error": str(e)}

@app.get("/admin/users")
async def admin_get_users(current_user: User = Depends(require_super_admin), db: Session = Depends(get_db)):
    """Get all users (admin only)"""
    users = db.query(User).all()
    return [
        {
            "id": user.id,
            "username": user.username,
            "is_admin": user.is_admin,
            "is_active": user.is_active,
            "last_login": user.last_login.isoformat() if user.last_login else None,
            "failed_login_attempts": user.failed_login_attempts,
            "created_at": user.created_at.isoformat()
        }
        for user in users
    ]

@app.post("/admin/toggle-user")
async def admin_toggle_user(
    request: Request,
    current_user: User = Depends(require_super_admin),
    db: Session = Depends(get_db)
):
    """Toggle user active status (admin only)"""
    try:
        data = await request.json()
        user_id = data.get("user_id")
        active = data.get("active")
        
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            return {"success": False, "error": "User not found"}
        
        user.is_active = 1 if active else 0
        db.commit()
        
        return {"success": True, "message": f"User {'enabled' if active else 'disabled'} successfully"}
        
    except Exception as e:
        return {"success": False, "error": str(e)}

@app.post("/admin/reset-attempts")
async def admin_reset_attempts(
    request: Request,
    current_user: User = Depends(require_super_admin),
    db: Session = Depends(get_db)
):
    """Reset failed login attempts (admin only)"""
    try:
        data = await request.json()
        user_id = data.get("user_id")
        
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            return {"success": False, "error": "User not found"}
        
        user.failed_login_attempts = 0
        db.commit()
        
        return {"success": True, "message": "Failed login attempts reset successfully"}
        
    except Exception as e:
        return {"success": False, "error": str(e)}

@app.get("/admin/deepseek-status")
async def admin_deepseek_status(current_user: User = Depends(require_super_admin)):
    """Check DeepSeek API status (admin only)"""
    try:
        if not DEEPSEEK_API_KEY:
            return {"status": "error", "message": "API key not configured"}
        
        # Simple test - just check if key is set
        return {"status": "connected", "message": "API key configured"}
        
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

@app.get("/emergency-reset-himolee")
async def emergency_reset_himolee_password(db: Session = Depends(get_db)):
    """Emergency password reset for himolee admin (one-time use)"""
    import secrets
    import string
    
    try:
        # Find himolee user
        user = db.query(User).filter(User.username == "himolee").first()
        
        if not user:
            return {"status": "error", "message": "himolee user not found"}
        
        # Generate new secure password
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        new_password = ''.join(secrets.choice(alphabet) for _ in range(12))
        
        # Hash the new password
        hashed_password = hash_password(new_password)
        
        # Update user record
        user.hashed_password = hashed_password
        user.failed_login_attempts = 0  # Reset failed attempts
        user.is_active = 1  # Ensure account is active
        user.is_admin = 2   # Ensure super admin status
        
        # Commit changes
        db.commit()
        
        # Log the password reset
        log_security_event("emergency_password_reset", {
            "username": "himolee",
            "reset_time": datetime.utcnow().isoformat()
        })
        
        return {
            "status": "success",
            "message": "Password reset successfully",
            "username": "himolee",
            "new_password": new_password,
            "admin_level": "Super Admin",
            "login_url": "https://marvin-ai-assistant.onrender.com/login",
            "warning": "Please change this password after logging in!"
        }
        
    except Exception as e:
        return {"status": "error", "message": f"Failed to reset password: {str(e)}"}

@app.get("/security-health")
async def security_health_check_endpoint(current_user: User = Depends(require_super_admin)):
    """Security health check (admin only)"""
    return security_health_check()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", 8000)))
