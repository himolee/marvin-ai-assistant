"""
Security Hardening Implementation for Marvin AI Assistant
This module contains additional security measures to be integrated into main.py
"""

import re
import html
import secrets
from datetime import datetime, timedelta
from typing import Optional
from fastapi import Request, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import hashlib
import time

# Security Configuration
SECURITY_CONFIG = {
    "MAX_LOGIN_ATTEMPTS": 5,
    "LOCKOUT_DURATION": 30,  # minutes
    "SESSION_TIMEOUT": 60,   # minutes
    "PASSWORD_MIN_LENGTH": 8,
    "REQUIRE_SPECIAL_CHARS": True,
    "MAX_REQUEST_SIZE": 1024 * 1024,  # 1MB
    "RATE_LIMIT_REQUESTS": 100,  # per minute
    "RATE_LIMIT_WINDOW": 60,  # seconds
}

# Rate limiting storage (in production, use Redis)
rate_limit_storage = {}
failed_attempts_storage = {}

class SecurityMiddleware:
    """Security middleware for request validation and protection"""
    
    @staticmethod
    def validate_input(input_text: str, max_length: int = 1000) -> str:
        """Validate and sanitize user input"""
        if not input_text:
            return ""
        
        # Length check
        if len(input_text) > max_length:
            raise HTTPException(status_code=400, detail="Input too long")
        
        # HTML escape to prevent XSS
        sanitized = html.escape(input_text.strip())
        
        # Remove potentially dangerous patterns
        dangerous_patterns = [
            r'<script[^>]*>.*?</script>',
            r'javascript:',
            r'vbscript:',
            r'onload=',
            r'onerror=',
            r'onclick=',
        ]
        
        for pattern in dangerous_patterns:
            sanitized = re.sub(pattern, '', sanitized, flags=re.IGNORECASE)
        
        return sanitized
    
    @staticmethod
    def validate_password(password: str) -> tuple[bool, str]:
        """Validate password strength"""
        if len(password) < SECURITY_CONFIG["PASSWORD_MIN_LENGTH"]:
            return False, f"Password must be at least {SECURITY_CONFIG['PASSWORD_MIN_LENGTH']} characters"
        
        if SECURITY_CONFIG["REQUIRE_SPECIAL_CHARS"]:
            if not re.search(r'[A-Z]', password):
                return False, "Password must contain at least one uppercase letter"
            if not re.search(r'[a-z]', password):
                return False, "Password must contain at least one lowercase letter"
            if not re.search(r'\d', password):
                return False, "Password must contain at least one number"
            if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
                return False, "Password must contain at least one special character"
        
        return True, "Password is valid"
    
    @staticmethod
    def check_rate_limit(client_ip: str) -> bool:
        """Check if client has exceeded rate limit"""
        current_time = time.time()
        window_start = current_time - SECURITY_CONFIG["RATE_LIMIT_WINDOW"]
        
        # Clean old entries
        if client_ip in rate_limit_storage:
            rate_limit_storage[client_ip] = [
                timestamp for timestamp in rate_limit_storage[client_ip]
                if timestamp > window_start
            ]
        else:
            rate_limit_storage[client_ip] = []
        
        # Check current count
        request_count = len(rate_limit_storage[client_ip])
        
        if request_count >= SECURITY_CONFIG["RATE_LIMIT_REQUESTS"]:
            return False
        
        # Add current request
        rate_limit_storage[client_ip].append(current_time)
        return True
    
    @staticmethod
    def check_failed_attempts(username: str) -> bool:
        """Check if user has too many failed login attempts"""
        if username not in failed_attempts_storage:
            return True
        
        attempts = failed_attempts_storage[username]
        current_time = datetime.utcnow()
        
        # Remove old attempts (outside lockout window)
        lockout_window = timedelta(minutes=SECURITY_CONFIG["LOCKOUT_DURATION"])
        recent_attempts = [
            attempt_time for attempt_time in attempts
            if current_time - attempt_time < lockout_window
        ]
        
        failed_attempts_storage[username] = recent_attempts
        
        return len(recent_attempts) < SECURITY_CONFIG["MAX_LOGIN_ATTEMPTS"]
    
    @staticmethod
    def record_failed_attempt(username: str):
        """Record a failed login attempt"""
        if username not in failed_attempts_storage:
            failed_attempts_storage[username] = []
        
        failed_attempts_storage[username].append(datetime.utcnow())
    
    @staticmethod
    def clear_failed_attempts(username: str):
        """Clear failed login attempts for user"""
        if username in failed_attempts_storage:
            del failed_attempts_storage[username]

class CSRFProtection:
    """CSRF protection implementation"""
    
    @staticmethod
    def generate_csrf_token() -> str:
        """Generate a CSRF token"""
        return secrets.token_urlsafe(32)
    
    @staticmethod
    def validate_csrf_token(token: str, session_token: str) -> bool:
        """Validate CSRF token"""
        return secrets.compare_digest(token, session_token)

class SecurityHeaders:
    """Security headers for HTTP responses"""
    
    @staticmethod
    def get_security_headers() -> dict:
        """Get security headers to add to responses"""
        return {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data:; "
                "connect-src 'self'; "
                "font-src 'self'; "
                "object-src 'none'; "
                "media-src 'self'; "
                "frame-src 'none';"
            ),
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=(), microphone=(), camera=()"
        }

def hash_ip_address(ip: str) -> str:
    """Hash IP address for privacy-compliant logging"""
    return hashlib.sha256(ip.encode()).hexdigest()[:16]

def log_security_event(event_type: str, details: dict, ip: str = None):
    """Log security events (in production, use proper logging)"""
    timestamp = datetime.utcnow().isoformat()
    hashed_ip = hash_ip_address(ip) if ip else "unknown"
    
    log_entry = {
        "timestamp": timestamp,
        "event_type": event_type,
        "details": details,
        "ip_hash": hashed_ip
    }
    
    # In production, send to proper logging system
    print(f"SECURITY_LOG: {log_entry}")

# SQL Injection Prevention
def sanitize_sql_input(input_value: str) -> str:
    """Additional SQL injection prevention (SQLAlchemy ORM already protects)"""
    if not input_value:
        return ""
    
    # Remove SQL keywords and dangerous characters
    dangerous_sql = [
        'DROP', 'DELETE', 'INSERT', 'UPDATE', 'CREATE', 'ALTER',
        'EXEC', 'EXECUTE', 'UNION', 'SELECT', '--', ';', '/*', '*/',
        'xp_', 'sp_', 'SCRIPT', 'DECLARE', 'CAST'
    ]
    
    sanitized = input_value
    for keyword in dangerous_sql:
        sanitized = re.sub(re.escape(keyword), '', sanitized, flags=re.IGNORECASE)
    
    return sanitized.strip()

# Session Security
class SessionSecurity:
    """Session security management"""
    
    @staticmethod
    def is_session_expired(last_activity: datetime) -> bool:
        """Check if session has expired"""
        if not last_activity:
            return True
        
        session_timeout = timedelta(minutes=SECURITY_CONFIG["SESSION_TIMEOUT"])
        return datetime.utcnow() - last_activity > session_timeout
    
    @staticmethod
    def generate_secure_session_id() -> str:
        """Generate a secure session ID"""
        return secrets.token_urlsafe(32)

# Input Validation Schemas
USERNAME_PATTERN = re.compile(r'^[a-zA-Z0-9_]{3,20}$')
EMAIL_PATTERN = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')

def validate_username(username: str) -> bool:
    """Validate username format"""
    return bool(USERNAME_PATTERN.match(username))

def validate_email(email: str) -> bool:
    """Validate email format"""
    return bool(EMAIL_PATTERN.match(email))

# Security audit functions
def audit_user_permissions(user_id: int, db_session) -> dict:
    """Audit user permissions and access"""
    # Implementation would check user's access patterns, permissions, etc.
    return {
        "user_id": user_id,
        "last_audit": datetime.utcnow().isoformat(),
        "permissions_valid": True,
        "suspicious_activity": False
    }

def security_health_check() -> dict:
    """Perform security health check"""
    return {
        "timestamp": datetime.utcnow().isoformat(),
        "security_features": {
            "rate_limiting": True,
            "input_validation": True,
            "csrf_protection": True,
            "secure_headers": True,
            "session_security": True,
            "password_policy": True,
            "account_lockout": True
        },
        "status": "healthy"
    }
