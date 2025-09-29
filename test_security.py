#!/usr/bin/env python3
"""
Test script for Marvin AI Assistant security features
"""

import requests
import json
import time
import sys

BASE_URL = "http://localhost:8000"

def test_rate_limiting():
    """Test rate limiting functionality"""
    print("Testing rate limiting...")
    
    # Make multiple requests in quick succession
    for i in range(10):
        response = requests.get(f"{BASE_URL}/health")
        print(f"Request {i+1}: Status {response.status_code}")
        if response.status_code == 429:
            print("✅ Rate limiting working correctly")
            return True
    
    print("❌ Rate limiting not triggered")
    return False

def test_security_headers():
    """Test security headers"""
    print("Testing security headers...")
    
    response = requests.get(f"{BASE_URL}/health")
    headers = response.headers
    
    required_headers = [
        "X-Content-Type-Options",
        "X-Frame-Options",
        "X-XSS-Protection",
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "Referrer-Policy"
    ]
    
    missing_headers = []
    for header in required_headers:
        if header not in headers:
            missing_headers.append(header)
    
    if missing_headers:
        print(f"❌ Missing security headers: {', '.join(missing_headers)}")
        return False
    else:
        print("✅ All security headers present")
        return True

def test_invalid_login():
    """Test invalid login handling"""
    print("Testing invalid login handling...")
    
    # Test with invalid credentials
    login_data = {
        "username": "nonexistent_user",
        "password": "invalid_password"
    }
    
    response = requests.post(f"{BASE_URL}/login", data=login_data)
    
    if "Invalid credentials" in response.text:
        print("✅ Invalid login handled correctly")
        return True
    else:
        print("❌ Invalid login not handled correctly")
        return False

def test_csrf_protection():
    """Test CSRF protection"""
    print("Testing CSRF protection...")
    
    # This is a simplified test - in a real scenario, we would need to extract the CSRF token
    # For now, we'll just check if the login form has a CSRF token field
    
    response = requests.get(f"{BASE_URL}/login")
    
    if "csrf_token" in response.text:
        print("✅ CSRF protection appears to be in place")
        return True
    else:
        print("⚠️ Could not verify CSRF protection")
        return False

def test_admin_access():
    """Test admin access restrictions"""
    print("Testing admin access restrictions...")
    
    # Try to access admin panel without authentication
    response = requests.get(f"{BASE_URL}/admin")
    
    if response.status_code in [401, 403] or "/login" in response.url:
        print("✅ Admin access properly restricted")
        return True
    else:
        print("❌ Admin access not properly restricted")
        return False

def run_all_tests():
    """Run all security tests"""
    print("Running security tests for Marvin AI Assistant...\n")
    
    tests = [
        test_rate_limiting,
        test_security_headers,
        test_invalid_login,
        test_csrf_protection,
        test_admin_access
    ]
    
    results = []
    for test in tests:
        result = test()
        results.append(result)
        print()
    
    # Summary
    passed = results.count(True)
    failed = results.count(False)
    
    print(f"Test Summary: {passed} passed, {failed} failed")
    
    if failed > 0:
        return False
    return True

if __name__ == "__main__":
    success = run_all_tests()
    if not success:
        sys.exit(1)
