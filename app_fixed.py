"""
Marvin AI Assistant - Main Application
"""

from fastapi import FastAPI, Request, Form, HTTPException, status, Depends
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import os
import secrets
import jwt
from datetime import datetime, timedelta

app = FastAPI()

# Configuration
SECRET_KEY = os.environ.get("SECRET_KEY", "marvin_default_secret_key_for_development")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# Security token
security = HTTPBearer()

# Mount static files
app.mount("/static", StaticFiles(directory="frontend/static"), name="static")
templates = Jinja2Templates(directory="frontend/templates")

# Helper functions
def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def decode_token(token):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except:
        return None

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    payload = decode_token(token)
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return payload

@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    return RedirectResponse(url="/login")

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login")
async def login(request: Request, username: str = Form(...), password: str = Form(...)):
    # Hardcoded login for himolee
    if username == "himolee" and password == "MarvinAdmin2025":
        # Create access token
        access_token = create_access_token(
            data={"sub": username, "admin": 2}  # 2 = super admin
        )
        
        response = RedirectResponse(url="/chat", status_code=status.HTTP_302_FOUND)
        response.set_cookie(
            key="access_token",
            value=f"Bearer {access_token}",
            httponly=True,
            max_age=1800,
            expires=1800,
        )
        return response
    
    return templates.TemplateResponse(
        "login.html", 
        {"request": request, "error": "Invalid username or password"}
    )

@app.get("/chat", response_class=HTMLResponse)
async def chat_page(request: Request):
    # Get token from cookie
    token = request.cookies.get("access_token")
    if not token or not token.startswith("Bearer "):
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    
    # Verify token
    payload = decode_token(token.replace("Bearer ", ""))
    if not payload:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    
    # Render chat page
    return templates.TemplateResponse(
        "chat.html", 
        {"request": request, "username": payload.get("sub", "User")}
    )

@app.post("/api/chat")
async def process_chat(request: Request, message: str = Form(...)):
    # Simple echo response for now
    response = f"You said: {message}"
    return {"response": response}

@app.post("/logout")
async def logout(request: Request):
    response = RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    response.delete_cookie("access_token")
    return response

@app.get("/admin", response_class=HTMLResponse)
async def admin_page(request: Request):
    # Get token from cookie
    token = request.cookies.get("access_token")
    if not token or not token.startswith("Bearer "):
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    
    # Verify token
    payload = decode_token(token.replace("Bearer ", ""))
    if not payload or payload.get("admin", 0) < 1:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    
    # Render admin page
    return templates.TemplateResponse(
        "admin.html", 
        {"request": request, "username": payload.get("sub", "Admin")}
    )

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
