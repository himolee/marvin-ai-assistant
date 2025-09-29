#!/usr/bin/env python3
"""
Enhanced Security Headers for Marvin AI Assistant
This script updates the security_hardening.py file with improved security headers
"""

import os
import sys
import re

# Path to security_hardening.py
SECURITY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "security_hardening.py")

# Enhanced security headers
ENHANCED_HEADERS = """
    @staticmethod
    def get_security_headers() -> dict:
        \"\"\"Get enhanced security headers to add to responses\"\"\"
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
            "Clear-Site-Data": "\"cache\", \"cookies\", \"storage\"",
            "Cross-Origin-Embedder-Policy": "require-corp",
            "Cross-Origin-Opener-Policy": "same-origin",
            "Cross-Origin-Resource-Policy": "same-origin"
        }
"""

def update_security_headers():
    """Update security headers in security_hardening.py"""
    if not os.path.exists(SECURITY_FILE):
        print(f"Error: {SECURITY_FILE} not found.")
        return False
    
    try:
        with open(SECURITY_FILE, 'r') as f:
            content = f.read()
        
        # Find the get_security_headers method
        pattern = r'@staticmethod\s+def get_security_headers\(\).*?return \{.*?\}'
        
        # Replace with enhanced headers
        updated_content = re.sub(pattern, ENHANCED_HEADERS.strip(), content, flags=re.DOTALL)
        
        if content == updated_content:
            print("Warning: Could not find or replace security headers method.")
            return False
        
        # Write updated content
        with open(SECURITY_FILE, 'w') as f:
            f.write(updated_content)
        
        print("Security headers updated successfully.")
        return True
    
    except Exception as e:
        print(f"Error updating security headers: {e}")
        return False

def add_csrf_protection():
    """Add CSRF protection to security_hardening.py"""
    if not os.path.exists(SECURITY_FILE):
        print(f"Error: {SECURITY_FILE} not found.")
        return False
    
    try:
        with open(SECURITY_FILE, 'r') as f:
            content = f.read()
        
        # Check if CSRF protection is already enhanced
        if "def validate_csrf_token(token: str, session_token: str, request_path: str = None)" in content:
            print("CSRF protection already enhanced.")
            return True
        
        # Find the CSRFProtection class
        csrf_class_pattern = r'class CSRFProtection:.*?@staticmethod\s+def validate_csrf_token\(token: str, session_token: str\) -> bool:.*?return secrets\.compare_digest\(token, session_token\)'
        
        # Enhanced CSRF protection
        enhanced_csrf = """class CSRFProtection:
    \"\"\"Enhanced CSRF protection implementation\"\"\"
    
    @staticmethod
    def generate_csrf_token() -> str:
        \"\"\"Generate a CSRF token\"\"\"
        return secrets.token_urlsafe(32)
    
    @staticmethod
    def validate_csrf_token(token: str, session_token: str, request_path: str = None) -> bool:
        \"\"\"
        Validate CSRF token with additional security checks
        
        Args:
            token: The token from the request
            session_token: The token from the session
            request_path: Optional path to validate against path-specific tokens
            
        Returns:
            bool: True if token is valid, False otherwise
        \"\"\"
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
        \"\"\"
        Get a path-specific token for a request
        
        Args:
            request_path: The path of the request
            base_token: The base token from the session
            
        Returns:
            str: A path-specific token
        \"\"\"
        if not request_path or not base_token:
            return ""
            
        # Create a path-specific token by combining the base token with the path
        path_hash = hashlib.sha256(request_path.encode()).hexdigest()[:8]
        return f"{base_token}:{path_hash}"
"""
        
        # Replace with enhanced CSRF protection
        updated_content = re.sub(csrf_class_pattern, enhanced_csrf, content, flags=re.DOTALL)
        
        if content == updated_content:
            print("Warning: Could not find or replace CSRF protection class.")
            return False
        
        # Add hashlib import if not present
        if "import hashlib" not in updated_content:
            updated_content = updated_content.replace("import secrets", "import secrets\nimport hashlib")
        
        # Write updated content
        with open(SECURITY_FILE, 'w') as f:
            f.write(updated_content)
        
        print("CSRF protection enhanced successfully.")
        return True
    
    except Exception as e:
        print(f"Error enhancing CSRF protection: {e}")
        return False

def enhance_rate_limiting():
    """Enhance rate limiting in security_hardening.py"""
    if not os.path.exists(SECURITY_FILE):
        print(f"Error: {SECURITY_FILE} not found.")
        return False
    
    try:
        with open(SECURITY_FILE, 'r') as f:
            content = f.read()
        
        # Check if rate limiting is already enhanced
        if "def check_rate_limit(client_ip: str, path: str = None, method: str = None)" in content:
            print("Rate limiting already enhanced.")
            return True
        
        # Find the check_rate_limit method
        rate_limit_pattern = r'@staticmethod\s+def check_rate_limit\(client_ip: str\) -> bool:.*?return True'
        
        # Enhanced rate limiting
        enhanced_rate_limit = """    @staticmethod
    def check_rate_limit(client_ip: str, path: str = None, method: str = None) -> bool:
        \"\"\"
        Check if client has exceeded rate limit with path and method-specific limits
        
        Args:
            client_ip: The client IP address
            path: Optional request path for path-specific rate limits
            method: Optional HTTP method for method-specific rate limits
            
        Returns:
            bool: True if within rate limit, False if exceeded
        \"\"\"
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
        return True"""
        
        # Replace with enhanced rate limiting
        updated_content = re.sub(rate_limit_pattern, enhanced_rate_limit, content, flags=re.DOTALL)
        
        if content == updated_content:
            print("Warning: Could not find or replace rate limiting method.")
            return False
        
        # Update SECURITY_CONFIG to include new rate limit settings
        config_pattern = r'SECURITY_CONFIG = \{.*?\}'
        
        # Find the current config
        config_match = re.search(config_pattern, content, re.DOTALL)
        if config_match:
            current_config = config_match.group(0)
            
            # Check if new settings already exist
            if "API_RATE_LIMIT" in current_config:
                print("Rate limit settings already updated.")
            else:
                # Add new settings
                enhanced_config = current_config.rstrip('}') + ',\n    "API_RATE_LIMIT": 60,\n    "ADMIN_RATE_LIMIT": 30,\n    "AUTH_RATE_LIMIT": 10\n}'
                updated_content = updated_content.replace(current_config, enhanced_config)
        
        # Write updated content
        with open(SECURITY_FILE, 'w') as f:
            f.write(updated_content)
        
        print("Rate limiting enhanced successfully.")
        return True
    
    except Exception as e:
        print(f"Error enhancing rate limiting: {e}")
        return False

def main():
    """Main function"""
    print("Enhancing security measures for Marvin AI Assistant...")
    
    # Update security headers
    update_security_headers()
    
    # Enhance CSRF protection
    add_csrf_protection()
    
    # Enhance rate limiting
    enhance_rate_limiting()
    
    print("Security enhancements completed.")

if __name__ == "__main__":
    main()
