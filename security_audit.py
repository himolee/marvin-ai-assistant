#!/usr/bin/env python3
"""
Security Audit System for Marvin AI Assistant
This script provides comprehensive security auditing functionality
"""

import os
import sys
import json
import sqlite3
import argparse
from datetime import datetime, timedelta
import hashlib
import csv
import time

# Database connection
DB_PATH = os.getenv("DB_PATH", "./marvin.db")

def connect_db():
    """Connect to the SQLite database"""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        return conn
    except sqlite3.Error as e:
        print(f"Error connecting to database: {e}")
        sys.exit(1)

def check_audit_table():
    """Check if audit_logs table exists, create if not"""
    conn = connect_db()
    cursor = conn.cursor()
    
    try:
        # Check if table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='audit_logs'")
        if not cursor.fetchone():
            print("Audit logs table not found. Creating...")
            
            # Create audit_logs table
            cursor.execute('''
            CREATE TABLE audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                event_type TEXT,
                user_id INTEGER,
                username TEXT,
                ip_hash TEXT,
                details TEXT,
                severity TEXT DEFAULT 'info'
            )
            ''')
            
            conn.commit()
            print("Audit logs table created successfully.")
        else:
            print("Audit logs table exists.")
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    finally:
        conn.close()

def get_audit_logs(start_date=None, end_date=None, event_type=None, username=None, severity=None, limit=100):
    """Get audit logs with optional filtering"""
    conn = connect_db()
    cursor = conn.cursor()
    
    query = "SELECT * FROM audit_logs WHERE 1=1"
    params = []
    
    if start_date:
        query += " AND timestamp >= ?"
        params.append(start_date)
    
    if end_date:
        query += " AND timestamp <= ?"
        params.append(end_date)
    
    if event_type:
        query += " AND event_type = ?"
        params.append(event_type)
    
    if username:
        query += " AND username = ?"
        params.append(username)
    
    if severity:
        query += " AND severity = ?"
        params.append(severity)
    
    query += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)
    
    try:
        cursor.execute(query, params)
        rows = cursor.fetchall()
        
        logs = []
        for row in rows:
            try:
                details = json.loads(row['details'])
            except:
                details = {"error": "Invalid JSON"}
            
            logs.append({
                "id": row['id'],
                "timestamp": row['timestamp'],
                "event_type": row['event_type'],
                "user_id": row['user_id'],
                "username": row['username'],
                "ip_hash": row['ip_hash'],
                "details": details,
                "severity": row['severity']
            })
        
        return logs
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return []
    finally:
        conn.close()

def get_security_metrics(days=7):
    """Get security metrics for the specified number of days"""
    conn = connect_db()
    cursor = conn.cursor()
    
    # Calculate date range
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=days)
    
    metrics = {
        "period": f"Last {days} days",
        "start_date": start_date.isoformat(),
        "end_date": end_date.isoformat(),
        "total_events": 0,
        "events_by_type": {},
        "events_by_severity": {},
        "failed_logins": 0,
        "security_violations": 0,
        "user_creation_events": 0,
        "user_modification_events": 0,
        "daily_events": {}
    }
    
    try:
        # Total events
        cursor.execute(
            "SELECT COUNT(*) FROM audit_logs WHERE timestamp BETWEEN ? AND ?",
            (start_date.isoformat(), end_date.isoformat())
        )
        metrics["total_events"] = cursor.fetchone()[0]
        
        # Events by type
        cursor.execute(
            "SELECT event_type, COUNT(*) as count FROM audit_logs WHERE timestamp BETWEEN ? AND ? GROUP BY event_type",
            (start_date.isoformat(), end_date.isoformat())
        )
        for row in cursor.fetchall():
            metrics["events_by_type"][row['event_type']] = row['count']
        
        # Events by severity
        cursor.execute(
            "SELECT severity, COUNT(*) as count FROM audit_logs WHERE timestamp BETWEEN ? AND ? GROUP BY severity",
            (start_date.isoformat(), end_date.isoformat())
        )
        for row in cursor.fetchall():
            metrics["events_by_severity"][row['severity']] = row['count']
        
        # Failed logins
        cursor.execute(
            "SELECT COUNT(*) FROM audit_logs WHERE event_type = 'login_failed' AND timestamp BETWEEN ? AND ?",
            (start_date.isoformat(), end_date.isoformat())
        )
        metrics["failed_logins"] = cursor.fetchone()[0]
        
        # Security violations
        cursor.execute(
            "SELECT COUNT(*) FROM audit_logs WHERE event_type = 'security_violation' AND timestamp BETWEEN ? AND ?",
            (start_date.isoformat(), end_date.isoformat())
        )
        metrics["security_violations"] = cursor.fetchone()[0]
        
        # User creation events
        cursor.execute(
            "SELECT COUNT(*) FROM audit_logs WHERE event_type = 'user_created' AND timestamp BETWEEN ? AND ?",
            (start_date.isoformat(), end_date.isoformat())
        )
        metrics["user_creation_events"] = cursor.fetchone()[0]
        
        # User modification events
        cursor.execute(
            "SELECT COUNT(*) FROM audit_logs WHERE event_type = 'user_modified' AND timestamp BETWEEN ? AND ?",
            (start_date.isoformat(), end_date.isoformat())
        )
        metrics["user_modification_events"] = cursor.fetchone()[0]
        
        # Daily events
        for i in range(days):
            day_date = end_date - timedelta(days=i)
            day_start = day_date.replace(hour=0, minute=0, second=0, microsecond=0)
            day_end = day_start + timedelta(days=1)
            
            cursor.execute(
                "SELECT COUNT(*) FROM audit_logs WHERE timestamp BETWEEN ? AND ?",
                (day_start.isoformat(), day_end.isoformat())
            )
            metrics["daily_events"][day_start.strftime("%Y-%m-%d")] = cursor.fetchone()[0]
        
        return metrics
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return metrics
    finally:
        conn.close()

def export_audit_logs(output_file, format="csv", start_date=None, end_date=None, event_type=None, username=None, severity=None):
    """Export audit logs to a file"""
    logs = get_audit_logs(start_date, end_date, event_type, username, severity, limit=10000)
    
    if not logs:
        print("No logs found matching the criteria.")
        return False
    
    try:
        if format.lower() == "csv":
            with open(output_file, 'w', newline='') as csvfile:
                fieldnames = ["id", "timestamp", "event_type", "user_id", "username", "ip_hash", "severity", "details"]
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                
                writer.writeheader()
                for log in logs:
                    log_row = {
                        "id": log["id"],
                        "timestamp": log["timestamp"],
                        "event_type": log["event_type"],
                        "user_id": log["user_id"],
                        "username": log["username"],
                        "ip_hash": log["ip_hash"],
                        "severity": log["severity"],
                        "details": json.dumps(log["details"])
                    }
                    writer.writerow(log_row)
        
        elif format.lower() == "json":
            with open(output_file, 'w') as jsonfile:
                json.dump(logs, jsonfile, indent=2)
        
        else:
            print(f"Unsupported format: {format}")
            return False
        
        print(f"Exported {len(logs)} logs to {output_file}")
        return True
    
    except Exception as e:
        print(f"Error exporting logs: {e}")
        return False

def generate_security_report(output_file, days=30):
    """Generate a comprehensive security report"""
    metrics = get_security_metrics(days)
    recent_logs = get_audit_logs(
        start_date=(datetime.utcnow() - timedelta(days=days)).isoformat(),
        limit=1000
    )
    
    # Filter for important events
    critical_events = [log for log in recent_logs if log["severity"] in ["critical", "error"]]
    failed_logins = [log for log in recent_logs if log["event_type"] == "login_failed"]
    security_violations = [log for log in recent_logs if log["event_type"] == "security_violation"]
    
    try:
        with open(output_file, 'w') as f:
            f.write("# Marvin AI Assistant - Security Audit Report\n\n")
            f.write(f"**Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"**Period:** {metrics['period']}\n")
            f.write(f"**Start Date:** {metrics['start_date']}\n")
            f.write(f"**End Date:** {metrics['end_date']}\n\n")
            
            f.write("## Summary\n\n")
            f.write(f"- **Total Events:** {metrics['total_events']}\n")
            f.write(f"- **Failed Logins:** {metrics['failed_logins']}\n")
            f.write(f"- **Security Violations:** {metrics['security_violations']}\n")
            f.write(f"- **User Creation Events:** {metrics['user_creation_events']}\n")
            f.write(f"- **User Modification Events:** {metrics['user_modification_events']}\n\n")
            
            f.write("## Events by Type\n\n")
            f.write("| Event Type | Count |\n")
            f.write("|------------|-------|\n")
            for event_type, count in metrics['events_by_type'].items():
                f.write(f"| {event_type} | {count} |\n")
            f.write("\n")
            
            f.write("## Events by Severity\n\n")
            f.write("| Severity | Count |\n")
            f.write("|----------|-------|\n")
            for severity, count in metrics['events_by_severity'].items():
                f.write(f"| {severity} | {count} |\n")
            f.write("\n")
            
            f.write("## Daily Events\n\n")
            f.write("| Date | Count |\n")
            f.write("|------|-------|\n")
            for date, count in sorted(metrics['daily_events'].items()):
                f.write(f"| {date} | {count} |\n")
            f.write("\n")
            
            if critical_events:
                f.write("## Critical Events\n\n")
                f.write("| Timestamp | Event Type | Username | Details |\n")
                f.write("|-----------|------------|----------|--------|\n")
                for event in critical_events[:10]:  # Limit to 10 events
                    details_str = json.dumps(event["details"])[:100] + "..." if len(json.dumps(event["details"])) > 100 else json.dumps(event["details"])
                    f.write(f"| {event['timestamp']} | {event['event_type']} | {event['username'] or 'N/A'} | {details_str} |\n")
                f.write("\n")
            
            if failed_logins:
                f.write("## Recent Failed Logins\n\n")
                f.write("| Timestamp | Username | IP Hash | Reason |\n")
                f.write("|-----------|----------|---------|--------|\n")
                for event in failed_logins[:10]:  # Limit to 10 events
                    reason = event["details"].get("reason", "Unknown")
                    f.write(f"| {event['timestamp']} | {event['username'] or 'N/A'} | {event['ip_hash']} | {reason} |\n")
                f.write("\n")
            
            if security_violations:
                f.write("## Security Violations\n\n")
                f.write("| Timestamp | Type | IP Hash | Details |\n")
                f.write("|-----------|------|---------|--------|\n")
                for event in security_violations[:10]:  # Limit to 10 events
                    details_str = json.dumps(event["details"])[:100] + "..." if len(json.dumps(event["details"])) > 100 else json.dumps(event["details"])
                    f.write(f"| {event['timestamp']} | {event['event_type']} | {event['ip_hash']} | {details_str} |\n")
                f.write("\n")
            
            f.write("## Recommendations\n\n")
            
            # Generate recommendations based on metrics
            if metrics['failed_logins'] > 10:
                f.write("- **High number of failed logins detected.** Consider reviewing account security policies and implementing additional protection measures.\n")
            
            if metrics['security_violations'] > 0:
                f.write("- **Security violations detected.** Investigate these incidents and take appropriate action.\n")
            
            if metrics['user_modification_events'] > metrics['user_creation_events'] * 2:
                f.write("- **High number of user modifications.** Review user management practices and ensure proper authorization controls.\n")
            
            f.write("\n*End of Report*\n")
        
        print(f"Security report generated: {output_file}")
        return True
    
    except Exception as e:
        print(f"Error generating security report: {e}")
        return False

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="Marvin AI Assistant Security Audit Tool")
    subparsers = parser.add_subparsers(dest="command", help="Command to run")
    
    # Check command
    check_parser = subparsers.add_parser("check", help="Check audit table")
    
    # List command
    list_parser = subparsers.add_parser("list", help="List audit logs")
    list_parser.add_argument("--start", help="Start date (YYYY-MM-DD)")
    list_parser.add_argument("--end", help="End date (YYYY-MM-DD)")
    list_parser.add_argument("--type", help="Filter by event type")
    list_parser.add_argument("--user", help="Filter by username")
    list_parser.add_argument("--severity", help="Filter by severity")
    list_parser.add_argument("--limit", type=int, default=100, help="Limit number of results")
    
    # Export command
    export_parser = subparsers.add_parser("export", help="Export audit logs")
    export_parser.add_argument("output", help="Output file")
    export_parser.add_argument("--format", choices=["csv", "json"], default="csv", help="Output format")
    export_parser.add_argument("--start", help="Start date (YYYY-MM-DD)")
    export_parser.add_argument("--end", help="End date (YYYY-MM-DD)")
    export_parser.add_argument("--type", help="Filter by event type")
    export_parser.add_argument("--user", help="Filter by username")
    export_parser.add_argument("--severity", help="Filter by severity")
    
    # Metrics command
    metrics_parser = subparsers.add_parser("metrics", help="Get security metrics")
    metrics_parser.add_argument("--days", type=int, default=7, help="Number of days to analyze")
    
    # Report command
    report_parser = subparsers.add_parser("report", help="Generate security report")
    report_parser.add_argument("output", help="Output file")
    report_parser.add_argument("--days", type=int, default=30, help="Number of days to analyze")
    
    args = parser.parse_args()
    
    if args.command == "check":
        check_audit_table()
    
    elif args.command == "list":
        logs = get_audit_logs(
            start_date=args.start,
            end_date=args.end,
            event_type=args.type,
            username=args.user,
            severity=args.severity,
            limit=args.limit
        )
        
        if logs:
            print(f"Found {len(logs)} audit logs:")
            for log in logs:
                print(f"[{log['timestamp']}] {log['event_type']} - {log['username'] or 'N/A'} - {log['severity']}")
                print(f"  Details: {json.dumps(log['details'])}")
                print()
        else:
            print("No audit logs found matching the criteria.")
    
    elif args.command == "export":
        export_audit_logs(
            args.output,
            format=args.format,
            start_date=args.start,
            end_date=args.end,
            event_type=args.type,
            username=args.user,
            severity=args.severity
        )
    
    elif args.command == "metrics":
        metrics = get_security_metrics(days=args.days)
        print(json.dumps(metrics, indent=2))
    
    elif args.command == "report":
        generate_security_report(args.output, days=args.days)
    
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
