"""
Admin upgrade functionality to be integrated into main.py
This will be added as a special endpoint that can be called once to upgrade himolee
"""

# Add this to main.py after the existing routes

@app.get("/upgrade-admin-himolee-secret-endpoint-2024")
async def upgrade_himolee_admin(db: Session = Depends(get_db)):
    """
    Special one-time endpoint to upgrade himolee to super admin
    This endpoint should be removed after use for security
    """
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

# Add this helper function for admin checks
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

def require_admin(min_level: int = 1):
    """Decorator to require admin access"""
    def decorator(func):
        async def wrapper(request: Request, *args, **kwargs):
            token = request.cookies.get("access_token")
            if not token:
                raise HTTPException(status_code=401, detail="Not authenticated")
            
            db = next(get_db())
            user, admin_level = get_current_user_admin_level(token, db)
            
            if not user or admin_level < min_level:
                raise HTTPException(status_code=403, detail="Insufficient privileges")
            
            return await func(request, *args, **kwargs)
        return wrapper
    return decorator
