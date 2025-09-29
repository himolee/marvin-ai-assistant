"""
Admin Role Management for Marvin AI Assistant
This module contains role management functionality for the admin panel
"""

from datetime import datetime
from typing import Dict, List, Optional
from sqlalchemy.orm import Session
from security_hardening import log_security_event

# Role definitions
ROLES = {
    0: {
        "name": "User",
        "description": "Regular user with chat access only",
        "permissions": ["chat"]
    },
    1: {
        "name": "Admin",
        "description": "Administrator with user management capabilities",
        "permissions": ["chat", "user_view", "user_toggle", "user_reset"]
    },
    2: {
        "name": "Super Admin",
        "description": "Super administrator with full system access",
        "permissions": ["chat", "user_view", "user_toggle", "user_reset", "user_create", "user_delete", "system_settings", "security_audit"]
    }
}

# Permission checks
def has_permission(user_admin_level: int, permission: str) -> bool:
    """Check if a user has a specific permission based on their admin level"""
    if user_admin_level not in ROLES:
        return False
    
    return permission in ROLES[user_admin_level]["permissions"]

def get_role_name(admin_level: int) -> str:
    """Get the role name for an admin level"""
    if admin_level not in ROLES:
        return "Unknown"
    
    return ROLES[admin_level]["name"]

def get_role_description(admin_level: int) -> str:
    """Get the role description for an admin level"""
    if admin_level not in ROLES:
        return "Unknown role"
    
    return ROLES[admin_level]["description"]

def get_all_roles() -> List[Dict]:
    """Get all available roles"""
    return [
        {
            "level": level,
            "name": role["name"],
            "description": role["description"],
            "permissions": role["permissions"]
        }
        for level, role in ROLES.items()
    ]

def change_user_role(db: Session, user_id: int, new_role: int, changed_by_username: str, client_ip: str) -> Dict:
    """Change a user's role"""
    from main import User  # Import here to avoid circular imports
    
    # Validate role
    if new_role not in ROLES:
        return {"success": False, "error": "Invalid role level"}
    
    # Find user
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        return {"success": False, "error": "User not found"}
    
    # Get old role for logging
    old_role = user.is_admin
    old_role_name = get_role_name(old_role)
    new_role_name = get_role_name(new_role)
    
    # Update role
    user.is_admin = new_role
    db.commit()
    
    # Log role change
    log_security_event("user_role_changed", {
        "user_id": user_id,
        "username": user.username,
        "old_role": old_role,
        "old_role_name": old_role_name,
        "new_role": new_role,
        "new_role_name": new_role_name,
        "changed_by": changed_by_username
    }, client_ip)
    
    return {
        "success": True,
        "message": f"User role changed from {old_role_name} to {new_role_name}",
        "user_id": user_id,
        "username": user.username,
        "new_role": new_role,
        "new_role_name": new_role_name
    }

def get_user_permissions(user_admin_level: int) -> List[str]:
    """Get all permissions for a user based on their admin level"""
    if user_admin_level not in ROLES:
        return []
    
    return ROLES[user_admin_level]["permissions"]
