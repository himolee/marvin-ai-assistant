#!/usr/bin/env python3
"""
Deployment Verification Script for Marvin AI Assistant
This script verifies that the application is deployed and functioning correctly
"""

import requests
import argparse
import sys
import time
import json
from datetime import datetime

class DeploymentVerifier:
    """Verify deployment of Marvin AI Assistant"""
    
    def __init__(self, base_url):
        """Initialize with base URL"""
        self.base_url = base_url
        self.session = requests.Session()
        self.verification_results = {
            "timestamp": datetime.now().isoformat(),
            "base_url": base_url,
            "checks": [],
            "overall_status": "pending"
        }
    
    def run_all_checks(self):
        """Run all verification checks"""
        print("=" * 80)
        print("MARVIN AI ASSISTANT - DEPLOYMENT VERIFICATION")
        print("=" * 80)
        print(f"Verifying deployment at: {self.base_url}")
        print("-" * 80)
        
        # Basic connectivity checks
        self.check_health_endpoint()
        self.check_login_page()
        self.check_security_headers()
        
        # Determine overall status
        failed_checks = [check for check in self.verification_results["checks"] if check["status"] == "failed"]
        if failed_checks:
            self.verification_results["overall_status"] = "failed"
        else:
            self.verification_results["overall_status"] = "passed"
        
        # Print summary
        print("\n" + "=" * 80)
        print("VERIFICATION SUMMARY")
        print("-" * 80)
        print(f"Total checks: {len(self.verification_results['checks'])}")
        print(f"Passed: {len([c for c in self.verification_results['checks'] if c['status'] == 'passed'])}")
        print(f"Failed: {len([c for c in self.verification_results['checks'] if c['status'] == 'failed'])}")
        print(f"Overall status: {self.verification_results['overall_status'].upper()}")
        print("=" * 80)
        
        # Save results to file
        self.save_results()
        
        return self.verification_results["overall_status"] == "passed"
    
    def record_check(self, name, status, message=None):
        """Record check result"""
        check = {
            "name": name,
            "status": status,
            "timestamp": datetime.now().isoformat()
        }
        
        if message:
            check["message"] = message
        
        self.verification_results["checks"].append(check)
        
        status_str = status.upper()
        print(f"[{status_str}] {name}")
        if message:
            print(f"         {message}")
    
    def check_health_endpoint(self):
        """Check health endpoint"""
        try:
            response = self.session.get(f"{self.base_url}/health", timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "healthy":
                    self.record_check("Health Endpoint", "passed")
                else:
                    self.record_check("Health Endpoint", "failed", f"Unexpected response: {data}")
            else:
                self.record_check("Health Endpoint", "failed", f"Status code: {response.status_code}")
        except Exception as e:
            self.record_check("Health Endpoint", "failed", f"Exception: {str(e)}")
    
    def check_login_page(self):
        """Check login page"""
        try:
            response = self.session.get(f"{self.base_url}/login", timeout=10)
            
            if response.status_code == 200 and "login" in response.text.lower():
                self.record_check("Login Page", "passed")
            else:
                self.record_check("Login Page", "failed", f"Status code: {response.status_code}")
        except Exception as e:
            self.record_check("Login Page", "failed", f"Exception: {str(e)}")
    
    def check_security_headers(self):
        """Check security headers"""
        try:
            response = self.session.get(f"{self.base_url}/login", timeout=10)
            headers = response.headers
            
            required_headers = [
                "X-Content-Type-Options",
                "X-Frame-Options",
                "X-XSS-Protection",
                "Content-Security-Policy",
                "Strict-Transport-Security",
                "Referrer-Policy"
            ]
            
            missing_headers = []
            for header in required_headers:
                if header not in headers:
                    missing_headers.append(header)
            
            if not missing_headers:
                self.record_check("Security Headers", "passed")
            else:
                self.record_check("Security Headers", "failed", f"Missing headers: {', '.join(missing_headers)}")
        except Exception as e:
            self.record_check("Security Headers", "failed", f"Exception: {str(e)}")
    
    def save_results(self):
        """Save verification results to file"""
        filename = f"verification_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(filename, "w") as f:
            json.dump(self.verification_results, f, indent=2)
        
        print(f"\nVerification results saved to: {filename}")

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="Marvin AI Assistant Deployment Verification")
    parser.add_argument("--url", required=True, help="Base URL of the deployed application")
    parser.add_argument("--wait", type=int, default=0, help="Wait time in seconds before verification (for deployment to stabilize)")
    args = parser.parse_args()
    
    if args.wait > 0:
        print(f"Waiting {args.wait} seconds for deployment to stabilize...")
        time.sleep(args.wait)
    
    verifier = DeploymentVerifier(args.url)
    success = verifier.run_all_checks()
    
    if not success:
        sys.exit(1)

if __name__ == "__main__":
    main()
