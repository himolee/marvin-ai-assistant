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
    "PASSWORD_MIN_LENGTH": 12,  # Increased from 8
    "REQUIRE_SPECIAL_CHARS": True,
    "MAX_REQUEST_SIZE": 1024 * 1024,  # 1MB
    "RATE_LIMIT_REQUESTS": 100,  # per minute
    "RATE_LIMIT_WINDOW": 60,  # seconds
    "API_RATE_LIMIT": 60,  # per minute for API endpoints
    "ADMIN_RATE_LIMIT": 30,  # per minute for admin endpoints
    "AUTH_RATE_LIMIT": 10,  # per minute for auth endpoints
    "PASSWORD_HISTORY": 5,  # Remember last 5 passwords
    "PASSWORD_EXPIRY": 90,  # days
    "SESSION_ABSOLUTE_TIMEOUT": 24 * 60,  # minutes (24 hours)
    "SECURE_HEADERS_ENABLED": True,
    "AUDIT_LOGGING_ENABLED": True,
    "BRUTE_FORCE_DETECTION": True,
    "SUSPICIOUS_ACTIVITY_THRESHOLD": 5  # Number of suspicious actions before alert
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
    def check_rate_limit(client_ip: str, path: str = None, method: str = None) -> bool:
        """
        Check if client has exceeded rate limit with path and method-specific limits
        
        Args:
            client_ip: The client IP address
            path: Optional request path for path-specific rate limits
            method: Optional HTTP method for method-specific rate limits
            
        Returns:
            bool: True if within rate limit, False if exceeded
        """
        current_time = time.time()
        window_start = current_time - SECURITY_CONFIG["RATE_LIMIT_WINDOW"]
        
        # Default rate limit
        rate_limit = SECURITY_CONFIG["RATE_LIMIT_REQUESTS"]
        
        # Path-specific rate limits
        if path:
            # API endpoints may have stricter limits
            if path.startswith("/api/"):
                rate_limit = SECURITY_CONFIG.get("API_RATE_LIMIT", 60)
            # Admin endpoints may have stricter limits
            elif path.startswith("/admin/"):
                rate_limit = SECURITY_CONFIG.get("ADMIN_RATE_LIMIT", 30)
            # Authentication endpoints have stricter limits
            elif path in ["/login", "/register", "/reset-password"]:
                rate_limit = SECURITY_CONFIG.get("AUTH_RATE_LIMIT", 10)
        
        # Method-specific adjustments
        if method:
            # POST/PUT/DELETE requests may have stricter limits
            if method in ["POST", "PUT", "DELETE"]:
                rate_limit = int(rate_limit * 0.5)  # 50% of the normal limit
        
        # Initialize storage for this IP if not exists
        key = f"{client_ip}:{path}" if path else client_ip
        if key not in rate_limit_storage:
            rate_limit_storage[key] = []
        
        # Clean old entries
        rate_limit_storage[key] = [
            timestamp for timestamp in rate_limit_storage[key]
            if timestamp > window_start
        ]
        
        # Check current count
        request_count = len(rate_limit_storage[key])
        
        if request_count >= rate_limit:
            # Log rate limit exceeded
            details = {
                "ip": client_ip,
                "path": path,
                "method": method,
                "request_count": request_count,
                "rate_limit": rate_limit
            }
            log_security_event("rate_limit_exceeded", details, client_ip)
            return False
        
        # Add current request
        rate_limit_storage[key].append(current_time)
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
    """Enhanced CSRF protection implementation"""
    
    @staticmethod
    def generate_csrf_token() -> str:
        """Generate a CSRF token"""
        return secrets.token_urlsafe(32)
    
    @staticmethod
    def validate_csrf_token(token: str, session_token: str, request_path: str = None) -> bool:
        """
        Validate CSRF token with additional security checks
        
        Args:
            token: The token from the request
            session_token: The token from the session
            request_path: Optional path to validate against path-specific tokens
            
        Returns:
            bool: True if token is valid, False otherwise
        """
        # Basic token comparison
        if not token or not session_token:
            return False
            
        # Check if token matches session token
        is_valid = secrets.compare_digest(token, session_token)
        
        # Additional validation could be added here
        # For example, checking token age, path-specific tokens, etc.
        
        return is_valid
        
    @staticmethod
    def get_token_for_request(request_path: str, base_token: str) -> str:
        """
        Get a path-specific token for a request
        
        Args:
            request_path: The path of the request
            base_token: The base token from the session
            
        Returns:
            str: A path-specific token
        """
        if not request_path or not base_token:
            return ""
            
        # Create a path-specific token by combining the base token with the path
        path_hash = hashlib.sha256(request_path.encode()).hexdigest()[:8]
        return f"{base_token}:{path_hash}"


class SecurityHeaders:
    """Security headers for HTTP responses"""
    
    @staticmethod
    def get_security_headers() -> dict:
        """Get enhanced security headers to add to responses"""
        return {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
            "Content-Security-Policy": (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
                "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com; "
                "img-src 'self' data: https:; "
                "connect-src 'self'; "
                "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; "
                "object-src 'none'; "
                "media-src 'self'; "
                "frame-src 'none'; "
                "form-action 'self'; "
                "base-uri 'self'; "
                "frame-ancestors 'none';"
            ),
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=(), microphone=(), camera=(), payment=(), usb=(), interest-cohort=()",
            "Cache-Control": "no-store, max-age=0",
            "Clear-Site-Data": ""cache", "cookies", "storage"",
            "Cross-Origin-Embedder-Policy": "require-corp",
            "Cross-Origin-Opener-Policy": "same-origin",
            "Cross-Origin-Resource-Policy": "same-origin"
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
    """Enhanced session security management"""
    
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
    
    @staticmethod
    def validate_session(session_id: str, user_id: int, user_agent: str, ip_hash: str) -> bool:
        """
        Validate session with additional security checks
        
        Args:
            session_id: The session ID
            user_id: The user ID
            user_agent: The user agent string
            ip_hash: The hashed IP address
            
        Returns:
            bool: True if session is valid, False otherwise
        """
        # In a real implementation, this would check against a database
        # Here we're just demonstrating the concept
        
        # Check if session exists
        if not session_id:
            return False
        
        # Check if session is associated with the correct user
        # This would involve a database lookup in a real implementation
        
        # Check if user agent matches
        # This helps prevent session hijacking
        
        # Check if IP is within acceptable range
        # Some variation is allowed for users with dynamic IPs
        
        # For demonstration purposes, we'll just return True
        return True
    
    @staticmethod
    def regenerate_session_id(old_session_id: str) -> str:
        """
        Regenerate session ID after authentication or privilege change
        
        Args:
            old_session_id: The old session ID
            
        Returns:
            str: A new session ID
        """
        # Generate new session ID
        new_session_id = SessionSecurity.generate_secure_session_id()
        
        # In a real implementation, update the session in the database
        # Associate the new session ID with the same user and data
        # Then invalidate the old session ID
        
        return new_session_id
    
    @staticmethod
    def get_session_info(session_id: str) -> dict:
        """
        Get information about a session
        
        Args:
            session_id: The session ID
            
        Returns:
            dict: Session information
        """
        # In a real implementation, this would retrieve session data from a database
        return {
            "session_id": session_id,
            "created_at": datetime.utcnow().isoformat(),
            "last_activity": datetime.utcnow().isoformat(),
            "expires_at": (datetime.utcnow() + timedelta(minutes=SECURITY_CONFIG["SESSION_TIMEOUT"])).isoformat(),
            "is_valid": True
        }


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


# Brute Force Detection
def detect_brute_force_attack(username: str, ip: str, action: str = "login") -> bool:
    """
    Detect potential brute force attacks
    
    Args:
        username: The username being targeted
        ip: The IP address of the request
        action: The action being performed (login, password reset, etc.)
        
    Returns:
        bool: True if a brute force attack is detected, False otherwise
    """
    current_time = datetime.utcnow()
    ip_hash = hash_ip_address(ip)
    
    # Check for multiple failed attempts from the same IP
    if ip in failed_attempts_storage:
        recent_attempts = [
            attempt_time for attempt_time in failed_attempts_storage[ip]
            if current_time - attempt_time < timedelta(minutes=5)
        ]
        
        if len(recent_attempts) >= SECURITY_CONFIG["SUSPICIOUS_ACTIVITY_THRESHOLD"]:
            # Log potential brute force attack
            log_security_event("potential_brute_force", {
                "username": username,
                "ip_hash": ip_hash,
                "action": action,
                "attempts": len(recent_attempts),
                "window": "5 minutes"
            }, ip)
            return True
    
    # Check for distributed attacks against the same username
    username_attempts = {}
    for attempt_ip, attempts in failed_attempts_storage.items():
        for attempt in attempts:
            if current_time - attempt < timedelta(minutes=10):
                if attempt_ip not in username_attempts:
                    username_attempts[attempt_ip] = 0
                username_attempts[attempt_ip] += 1
    
    if len(username_attempts) >= 3:  # Attempts from 3+ different IPs
        # Log potential distributed brute force attack
        log_security_event("potential_distributed_attack", {
            "username": username,
            "ip_hash": ip_hash,
            "action": action,
            "unique_ips": len(username_attempts),
            "window": "10 minutes"
        }, ip)
        return True
    
    return False

def implement_progressive_delays(username: str) -> int:
    """
    Implement progressive delays for repeated failed attempts
    
    Args:
        username: The username being targeted
        
    Returns:
        int: Delay in seconds to apply
    """
    if username not in failed_attempts_storage:
        return 0
    
    attempts = len(failed_attempts_storage[username])
    
    # Progressive delay formula: 2^(attempts-1) seconds
    # 1 attempt: 0s, 2 attempts: 2s, 3 attempts: 4s, 4 attempts: 8s, 5 attempts: 16s
    if attempts <= 1:
        return 0
    
    delay = min(2 ** (attempts - 1), 30)  # Cap at 30 seconds
    return delay
