#!/usr/bin/env python3
"""
Deployment Script for Marvin AI Assistant
This script prepares and deploys the application to Render
"""

import os
import sys
import argparse
import subprocess
import json
import time
from datetime import datetime

def run_command(command, cwd=None):
    """Run a shell command and return the output"""
    try:
        result = subprocess.run(
            command,
            shell=True,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=cwd
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {command}")
        print(f"Error message: {e.stderr}")
        return None

def check_dependencies():
    """Check if all required dependencies are installed"""
    print("Checking dependencies...")
    
    # Check Python version
    python_version = run_command("python3 --version")
    if not python_version:
        print("Error: Python 3 is not installed")
        return False
    
    print(f"Python version: {python_version}")
    
    # Check pip
    pip_version = run_command("pip3 --version")
    if not pip_version:
        print("Error: pip3 is not installed")
        return False
    
    print(f"pip version: {pip_version}")
    
    # Check git
    git_version = run_command("git --version")
    if not git_version:
        print("Error: git is not installed")
        return False
    
    print(f"git version: {git_version}")
    
    return True

def check_environment_variables():
    """Check if all required environment variables are set"""
    print("Checking environment variables...")
    
    required_vars = ["SECRET_KEY", "DEEPSEEK_API_KEY"]
    missing_vars = []
    
    for var in required_vars:
        if not os.environ.get(var):
            missing_vars.append(var)
    
    if missing_vars:
        print(f"Error: The following environment variables are not set: {', '.join(missing_vars)}")
        return False
    
    print("All required environment variables are set")
    return True

def run_tests(url):
    """Run tests to ensure everything is working"""
    print("Running tests...")
    
    # Run the test script
    result = run_command(f"python3 test_all_features.py --url {url}")
    
    if result is None:
        print("Error: Tests failed")
        return False
    
    print("Tests completed")
    return True

def prepare_deployment():
    """Prepare the application for deployment"""
    print("Preparing deployment...")
    
    # Check if requirements.txt exists
    if not os.path.exists("requirements.txt"):
        print("Error: requirements.txt not found")
        return False
    
    # Check if runtime.txt exists
    if not os.path.exists("runtime.txt"):
        print("Creating runtime.txt...")
        with open("runtime.txt", "w") as f:
            f.write("python-3.11.0")
    
    # Create a .gitignore file if it doesn't exist
    if not os.path.exists(".gitignore"):
        print("Creating .gitignore...")
        with open(".gitignore", "w") as f:
            f.write("__pycache__/\n*.py[cod]\n*$py.class\n*.so\n.env\n.venv\nenv/\nvenv/\nENV/\nenv.bak/\nvenv.bak/\n.idea/\n.vscode/\n*.sqlite\n*.db\n")
    
    # Create a README.md file if it doesn't exist
    if not os.path.exists("README.md"):
        print("Creating README.md...")
        with open("README.md", "w") as f:
            f.write("# Marvin AI Assistant\n\nA secure AI assistant web application built with FastAPI and DeepSeek AI.\n\n")
            f.write("## Features\n\n")
            f.write("- Secure authentication system\n")
            f.write("- Role-based access control\n")
            f.write("- Comprehensive security measures\n")
            f.write("- Modern UI/UX design\n")
            f.write("- DeepSeek AI integration\n")
            f.write("- Audit logging\n\n")
            f.write("## Deployment\n\n")
            f.write("This application is deployed on Render.\n\n")
            f.write(f"Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    print("Deployment preparation completed")
    return True

def deploy_to_render(render_token=None):
    """Deploy the application to Render"""
    print("Deploying to Render...")
    
    if not render_token:
        print("No Render token provided. Manual deployment required.")
        print("Please follow these steps:")
        print("1. Push your code to GitHub")
        print("2. Log in to your Render account")
        print("3. Connect your GitHub repository")
        print("4. Deploy the application")
        return True
    
    # This is a placeholder for Render API deployment
    # In a real scenario, you would use the Render API to deploy the application
    print("Automatic deployment to Render is not implemented yet")
    print("Please follow the manual deployment steps")
    
    return True

def push_to_github(repo_url=None):
    """Push the code to GitHub"""
    print("Pushing to GitHub...")
    
    if not repo_url:
        print("No GitHub repository URL provided")
        
        # Check if git is already initialized
        if not os.path.exists(".git"):
            print("Initializing git repository...")
            run_command("git init")
        
        # Add all files
        run_command("git add .")
        
        # Commit changes
        commit_message = f"Update Marvin AI Assistant - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        run_command(f'git commit -m "{commit_message}"')
        
        print("Changes committed locally")
        print("Please push to your GitHub repository manually")
    else:
        # Check if git is already initialized
        if not os.path.exists(".git"):
            print("Initializing git repository...")
            run_command("git init")
            
            # Add remote
            run_command(f"git remote add origin {repo_url}")
        else:
            # Check if remote exists
            remotes = run_command("git remote -v")
            if "origin" not in remotes:
                run_command(f"git remote add origin {repo_url}")
        
        # Add all files
        run_command("git add .")
        
        # Commit changes
        commit_message = f"Update Marvin AI Assistant - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        run_command(f'git commit -m "{commit_message}"')
        
        # Push to GitHub
        run_command("git push -u origin main")
        
        print(f"Changes pushed to {repo_url}")
    
    return True

def create_deployment_report():
    """Create a deployment report"""
    print("Creating deployment report...")
    
    report = {
        "timestamp": datetime.now().isoformat(),
        "application": "Marvin AI Assistant",
        "version": "1.0.0",
        "environment": "production",
        "files": []
    }
    
    # Get list of files
    for root, dirs, files in os.walk("."):
        if ".git" in root or "__pycache__" in root:
            continue
        
        for file in files:
            if file.endswith(".pyc") or file.endswith(".sqlite") or file.endswith(".db"):
                continue
            
            file_path = os.path.join(root, file)
            report["files"].append({
                "path": file_path,
                "size": os.path.getsize(file_path),
                "last_modified": datetime.fromtimestamp(os.path.getmtime(file_path)).isoformat()
            })
    
    # Write report to file
    with open("deployment_report.json", "w") as f:
        json.dump(report, f, indent=2)
    
    print("Deployment report created: deployment_report.json")
    return True

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="Marvin AI Assistant Deployment Script")
    parser.add_argument("--test-url", default="http://localhost:8000", help="URL for testing")
    parser.add_argument("--skip-tests", action="store_true", help="Skip running tests")
    parser.add_argument("--github-repo", help="GitHub repository URL")
    parser.add_argument("--render-token", help="Render API token")
    args = parser.parse_args()
    
    print("=" * 80)
    print("MARVIN AI ASSISTANT - DEPLOYMENT SCRIPT")
    print("=" * 80)
    
    # Check dependencies
    if not check_dependencies():
        sys.exit(1)
    
    # Check environment variables
    if not check_environment_variables():
        print("Warning: Some environment variables are missing")
        print("You can continue, but the application may not work correctly")
        
        # Ask for confirmation
        response = input("Do you want to continue? (y/n): ")
        if response.lower() != "y":
            sys.exit(1)
    
    # Run tests
    if not args.skip_tests:
        if not run_tests(args.test_url):
            print("Warning: Tests failed")
            print("You can continue, but the application may have issues")
            
            # Ask for confirmation
            response = input("Do you want to continue? (y/n): ")
            if response.lower() != "y":
                sys.exit(1)
    else:
        print("Skipping tests")
    
    # Prepare deployment
    if not prepare_deployment():
        sys.exit(1)
    
    # Create deployment report
    if not create_deployment_report():
        sys.exit(1)
    
    # Push to GitHub
    if not push_to_github(args.github_repo):
        sys.exit(1)
    
    # Deploy to Render
    if not deploy_to_render(args.render_token):
        sys.exit(1)
    
    print("\n" + "=" * 80)
    print("DEPLOYMENT COMPLETED SUCCESSFULLY")
    print("=" * 80)

if __name__ == "__main__":
    main()
