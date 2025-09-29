"""
Admin Endpoints for Marvin AI Assistant
This module contains all admin-related endpoints and functionality
"""

from fastapi import APIRouter, Depends, HTTPException, Request, Form
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from typing import Dict, List, Optional
from datetime import datetime, timedelta
import json

# Import from other modules
from security_hardening import log_security_event, SecurityMiddleware, validate_username
from admin_roles import has_permission, get_role_name, get_all_roles, change_user_role
from audit_log import (
    log_audit_event, get_audit_logs, get_security_dashboard_data,
    EVENT_USER_CREATED, EVENT_USER_MODIFIED, EVENT_USER_DELETED,
    EVENT_ROLE_CHANGED, EVENT_ADMIN_ACTION, SEVERITY_INFO
)

# Create router
router = APIRouter(prefix="/admin", tags=["admin"])

# Templates reference (will be set in main.py)
templates = None

# Database dependency (will be set in main.py)
get_db = None

# User model (will be set in main.py)
User = None

# Authentication functions (will be set in main.py)
require_super_admin = None
get_password_hash = None

def init_admin_module(
    templates_instance,
    db_dependency,
    user_model,
    super_admin_dependency,
    password_hash_function
):
    """Initialize the admin module with dependencies from main.py"""
    global templates, get_db, User, require_super_admin, get_password_hash
    templates = templates_instance
    get_db = db_dependency
    User = user_model
    require_super_admin = super_admin_dependency
    get_password_hash = password_hash_function

# Admin panel main page
@router.get("/", response_class=HTMLResponse)
async def admin_panel(request: Request, current_user = Depends(require_super_admin)):
    return templates.TemplateResponse("admin.html", {"request": request, "username": current_user.username})

# User management endpoints
@router.post("/create-user")
async def admin_create_user(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    admin_level: int = Form(...),
    current_user = Depends(require_super_admin),
    db: Session = Depends(get_db)
):
    """Create new user (admin only)"""
    client_ip = request.client.host
    
    try:
        # Input validation
        username = SecurityMiddleware.validate_input(username, 50)
        if not validate_username(username):
            return {"success": False, "error": "Invalid username format. Use 3-20 alphanumeric characters and underscores only."}
        
        # Password validation
        is_valid, password_error = SecurityMiddleware.validate_password(password)
        if not is_valid:
            return {"success": False, "error": password_error}
        
        # Check if user already exists
        existing_user = db.query(User).filter(User.username == username).first()
        if existing_user:
            return {"success": False, "error": "Username already exists"}
        
        # Validate admin level
        if admin_level not in [0, 1, 2]:
            return {"success": False, "error": "Invalid admin level"}
        
        # Create new user
        hashed_password = get_password_hash(password)
        new_user = User(
            username=username,
            hashed_password=hashed_password,
            is_admin=admin_level,
            is_active=1,
            failed_login_attempts=0,
            created_at=datetime.utcnow()
        )
        
        db.add(new_user)
        db.commit()
        
        # Log user creation
        log_security_event("admin_user_created", {
            "created_by": current_user.username,
            "new_username": username,
            "admin_level": admin_level
        }, client_ip)
        
        # Log to audit system
        log_audit_event(
            event_type=EVENT_USER_CREATED,
            details={
                "username": username,
                "admin_level": admin_level,
                "role_name": get_role_name(admin_level)
            },
            user_id=current_user.id,
            username=current_user.username,
            ip_hash=client_ip
        )
        
        return {
            "success": True, 
            "message": f"User '{username}' created successfully",
            "user_id": new_user.id
        }
        
    except Exception as e:
        return {"success": False, "error": f"Failed to create user: {str(e)}"}

@router.get("/users")
async def admin_get_users(current_user = Depends(require_super_admin), db: Session = Depends(get_db)):
    """Get all users (admin only)"""
    users = db.query(User).all()
    return [
        {
            "id": user.id,
            "username": user.username,
            "is_admin": user.is_admin,
            "role_name": get_role_name(user.is_admin),
            "is_active": user.is_active,
            "last_login": user.last_login.isoformat() if user.last_login else None,
            "failed_login_attempts": user.failed_login_attempts,
            "created_at": user.created_at.isoformat()
        }
        for user in users
    ]

@router.post("/toggle-user")
async def admin_toggle_user(
    request: Request,
    current_user = Depends(require_super_admin),
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
        
        # Prevent disabling super admin accounts
        if user.is_admin == 2 and not active:
            return {"success": False, "error": "Cannot disable super admin accounts"}
        
        user.is_active = 1 if active else 0
        db.commit()
        
        # Log to audit system
        log_audit_event(
            event_type=EVENT_USER_MODIFIED,
            details={
                "user_id": user_id,
                "username": user.username,
                "action": "enabled" if active else "disabled",
                "new_status": "active" if active else "disabled"
            },
            user_id=current_user.id,
            username=current_user.username,
            ip_hash=request.client.host
        )
        
        return {"success": True, "message": f"User {'enabled' if active else 'disabled'} successfully"}
        
    except Exception as e:
        return {"success": False, "error": str(e)}

@router.post("/reset-attempts")
async def admin_reset_attempts(
    request: Request,
    current_user = Depends(require_super_admin),
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
        
        # Log to audit system
        log_audit_event(
            event_type=EVENT_ADMIN_ACTION,
            details={
                "action": "reset_login_attempts",
                "target_user_id": user_id,
                "target_username": user.username
            },
            user_id=current_user.id,
            username=current_user.username,
            ip_hash=request.client.host
        )
        
        return {"success": True, "message": "Failed login attempts reset successfully"}
        
    except Exception as e:
        return {"success": False, "error": str(e)}

@router.post("/change-role")
async def admin_change_role(
    request: Request,
    current_user = Depends(require_super_admin),
    db: Session = Depends(get_db)
):
    """Change user role (admin only)"""
    try:
        data = await request.json()
        user_id = data.get("user_id")
        new_role = data.get("role")
        
        result = change_user_role(
            db=db,
            user_id=user_id,
            new_role=new_role,
            changed_by_username=current_user.username,
            client_ip=request.client.host
        )
        
        return result
        
    except Exception as e:
        return {"success": False, "error": str(e)}

@router.get("/roles")
async def admin_get_roles(current_user = Depends(require_super_admin)):
    """Get all available roles (admin only)"""
    return get_all_roles()

@router.post("/reset-password")
async def admin_reset_password(
    request: Request,
    current_user = Depends(require_super_admin),
    db: Session = Depends(get_db)
):
    """Reset user password (admin only)"""
    try:
        data = await request.json()
        user_id = data.get("user_id")
        new_password = data.get("password")
        
        # Validate password
        is_valid, password_error = SecurityMiddleware.validate_password(new_password)
        if not is_valid:
            return {"success": False, "error": password_error}
        
        # Find user
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            return {"success": False, "error": "User not found"}
        
        # Update password
        user.hashed_password = get_password_hash(new_password)
        user.failed_login_attempts = 0  # Reset failed attempts
        db.commit()
        
        # Log to audit system
        log_audit_event(
            event_type=EVENT_USER_MODIFIED,
            details={
                "action": "password_reset",
                "target_user_id": user_id,
                "target_username": user.username
            },
            user_id=current_user.id,
            username=current_user.username,
            ip_hash=request.client.host
        )
        
        return {"success": True, "message": f"Password reset successfully for user '{user.username}'"}
        
    except Exception as e:
        return {"success": False, "error": str(e)}

@router.delete("/delete-user")
async def admin_delete_user(
    request: Request,
    current_user = Depends(require_super_admin),
    db: Session = Depends(get_db)
):
    """Delete user (admin only)"""
    try:
        data = await request.json()
        user_id = data.get("user_id")
        
        # Find user
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            return {"success": False, "error": "User not found"}
        
        # Prevent deleting super admin accounts
        if user.is_admin == 2:
            return {"success": False, "error": "Cannot delete super admin accounts"}
        
        # Store username for logging
        username = user.username
        
        # Delete user
        db.delete(user)
        db.commit()
        
        # Log to audit system
        log_audit_event(
            event_type=EVENT_USER_DELETED,
            details={
                "deleted_user_id": user_id,
                "deleted_username": username
            },
            user_id=current_user.id,
            username=current_user.username,
            ip_hash=request.client.host,
            severity=SEVERITY_INFO
        )
        
        return {"success": True, "message": f"User '{username}' deleted successfully"}
        
    except Exception as e:
        return {"success": False, "error": str(e)}

# Security endpoints
@router.get("/audit-logs")
async def admin_get_audit_logs(
    request: Request,
    limit: int = 100,
    offset: int = 0,
    event_type: Optional[str] = None,
    username: Optional[str] = None,
    severity: Optional[str] = None,
    current_user = Depends(require_super_admin),
    db: Session = Depends(get_db)
):
    """Get audit logs (admin only)"""
    try:
        logs = get_audit_logs(
            db=db,
            limit=limit,
            offset=offset,
            event_type=event_type,
            username=username,
            severity=severity
        )
        
        return {"success": True, "logs": logs, "count": len(logs)}
        
    except Exception as e:
        return {"success": False, "error": str(e)}

@router.get("/security-dashboard")
async def admin_security_dashboard(
    request: Request,
    current_user = Depends(require_super_admin),
    db: Session = Depends(get_db)
):
    """Get security dashboard data (admin only)"""
    try:
        dashboard_data = get_security_dashboard_data(db)
        return {"success": True, "data": dashboard_data}
        
    except Exception as e:
        return {"success": False, "error": str(e)}

# System endpoints
@router.get("/deepseek-status")
async def admin_deepseek_status(current_user = Depends(require_super_admin)):
    """Check DeepSeek API status (admin only)"""
    import os
    
    try:
        api_key = os.getenv("DEEPSEEK_API_KEY", "")
        if not api_key:
            return {"status": "error", "message": "API key not configured"}
        
        # Simple test - just check if key is set
        return {"status": "connected", "message": "API key configured"}
        
    except Exception as e:
        return {"status": "error", "message": str(e)}

@router.get("/system-info")
async def admin_system_info(current_user = Depends(require_super_admin)):
    """Get system information (admin only)"""
    import platform
    import os
    
    try:
        return {
            "success": True,
            "system": {
                "platform": platform.platform(),
                "python_version": platform.python_version(),
                "hostname": platform.node(),
                "deployment": "Render",
                "environment": os.getenv("ENVIRONMENT", "production")
            }
        }
        
    except Exception as e:
        return {"success": False, "error": str(e)}
