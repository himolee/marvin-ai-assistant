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

# Configuration
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-change-this")
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./marvin.db")
LLM_SERVICE_URL = os.getenv("LLM_SERVICE_URL", "http://localhost:8001")
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
    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(password, user.hashed_password):
        return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid credentials"})
    
    access_token = create_access_token(data={"sub": user.username})
    response = RedirectResponse(url="/chat", status_code=302)
    response.set_cookie(key="access_token", value=f"Bearer {access_token}", httponly=True)
    return response

@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

@app.post("/register")
async def register(request: Request, username: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    # Check if user already exists
    existing_user = db.query(User).filter(User.username == username).first()
    if existing_user:
        return templates.TemplateResponse("register.html", {"request": request, "error": "Username already exists"})
    
    # Create new user
    hashed_password = get_password_hash(password)
    new_user = User(username=username, hashed_password=hashed_password)
    db.add(new_user)
    db.commit()
    
    return templates.TemplateResponse("login.html", {"request": request, "success": "Account created successfully"})

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
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    username = verify_token(token.replace("Bearer ", ""))
    if not username:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Call LLM service
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{LLM_SERVICE_URL}/generate",
                json={"message": message},
                timeout=30.0
            )
            if response.status_code == 200:
                ai_response = response.json()["response"]
            else:
                ai_response = "I'm sorry, I'm having trouble processing your request right now."
    except:
        ai_response = "I'm sorry, the AI service is currently unavailable."
    
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

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", 8000)))
