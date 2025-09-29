"""
Audit Logging System for Marvin AI Assistant
This module provides comprehensive audit logging functionality
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Optional, Any
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session

# Database setup - use the same database as the main application
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./marvin.db")
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Audit Log Model
class AuditLog(Base):
    __tablename__ = "audit_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    event_type = Column(String, index=True)
    user_id = Column(Integer, nullable=True)
    username = Column(String, nullable=True)
    ip_hash = Column(String, nullable=True)
    details = Column(Text)  # JSON serialized details
    severity = Column(String, default="info")  # info, warning, error, critical

# Create tables
Base.metadata.create_all(bind=engine)

# Severity levels
SEVERITY_INFO = "info"
SEVERITY_WARNING = "warning"
SEVERITY_ERROR = "error"
SEVERITY_CRITICAL = "critical"

# Event types
EVENT_LOGIN = "login"
EVENT_LOGOUT = "logout"
EVENT_LOGIN_FAILED = "login_failed"
EVENT_USER_CREATED = "user_created"
EVENT_USER_MODIFIED = "user_modified"
EVENT_USER_DELETED = "user_deleted"
EVENT_ROLE_CHANGED = "role_changed"
EVENT_SECURITY_VIOLATION = "security_violation"
EVENT_SYSTEM_ERROR = "system_error"
EVENT_CHAT_MESSAGE = "chat_message"
EVENT_ADMIN_ACTION = "admin_action"

def log_audit_event(
    event_type: str,
    details: Dict[str, Any],
    user_id: Optional[int] = None,
    username: Optional[str] = None,
    ip_hash: Optional[str] = None,
    severity: str = SEVERITY_INFO
) -> None:
    """
    Log an audit event to the database
    
    Args:
        event_type: Type of event (use constants defined in this module)
        details: Dictionary of event details
        user_id: ID of the user who performed the action (if applicable)
        username: Username of the user who performed the action (if applicable)
        ip_hash: Hashed IP address of the client
        severity: Event severity level
    """
    try:
        db = SessionLocal()
        
        # Create audit log entry
        audit_log = AuditLog(
            event_type=event_type,
            user_id=user_id,
            username=username,
            ip_hash=ip_hash,
            details=json.dumps(details),
            severity=severity
        )
        
        db.add(audit_log)
        db.commit()
        
    except Exception as e:
        print(f"Error logging audit event: {str(e)}")
    finally:
        db.close()

def get_audit_logs(
    db: Session,
    limit: int = 100,
    offset: int = 0,
    event_type: Optional[str] = None,
    username: Optional[str] = None,
    severity: Optional[str] = None,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None
) -> List[Dict]:
    """
    Get audit logs with optional filtering
    
    Args:
        db: Database session
        limit: Maximum number of logs to return
        offset: Offset for pagination
        event_type: Filter by event type
        username: Filter by username
        severity: Filter by severity level
        start_date: Filter by start date
        end_date: Filter by end date
        
    Returns:
        List of audit log entries as dictionaries
    """
    query = db.query(AuditLog)
    
    # Apply filters
    if event_type:
        query = query.filter(AuditLog.event_type == event_type)
    
    if username:
        query = query.filter(AuditLog.username == username)
    
    if severity:
        query = query.filter(AuditLog.severity == severity)
    
    if start_date:
        query = query.filter(AuditLog.timestamp >= start_date)
    
    if end_date:
        query = query.filter(AuditLog.timestamp <= end_date)
    
    # Order by timestamp descending (newest first)
    query = query.order_by(AuditLog.timestamp.desc())
    
    # Apply pagination
    query = query.limit(limit).offset(offset)
    
    # Convert to dictionaries
    logs = []
    for log in query.all():
        try:
            details = json.loads(log.details)
        except:
            details = {"error": "Invalid JSON"}
        
        logs.append({
            "id": log.id,
            "timestamp": log.timestamp.isoformat(),
            "event_type": log.event_type,
            "user_id": log.user_id,
            "username": log.username,
            "ip_hash": log.ip_hash,
            "details": details,
            "severity": log.severity
        })
    
    return logs

def get_security_dashboard_data(db: Session) -> Dict:
    """
    Get security dashboard data summarizing recent activity
    
    Args:
        db: Database session
        
    Returns:
        Dictionary with security dashboard data
    """
    # Get counts for different event types in the last 24 hours
    now = datetime.utcnow()
    yesterday = now.replace(hour=0, minute=0, second=0, microsecond=0)
    
    # Failed logins in last 24 hours
    failed_logins = db.query(AuditLog).filter(
        AuditLog.event_type == EVENT_LOGIN_FAILED,
        AuditLog.timestamp >= yesterday
    ).count()
    
    # Successful logins in last 24 hours
    successful_logins = db.query(AuditLog).filter(
        AuditLog.event_type == EVENT_LOGIN,
        AuditLog.timestamp >= yesterday
    ).count()
    
    # Security violations in last 24 hours
    security_violations = db.query(AuditLog).filter(
        AuditLog.event_type == EVENT_SECURITY_VIOLATION,
        AuditLog.timestamp >= yesterday
    ).count()
    
    # Admin actions in last 24 hours
    admin_actions = db.query(AuditLog).filter(
        AuditLog.event_type == EVENT_ADMIN_ACTION,
        AuditLog.timestamp >= yesterday
    ).count()
    
    # Recent critical events
    critical_events = get_audit_logs(
        db=db,
        limit=5,
        severity=SEVERITY_CRITICAL
    )
    
    return {
        "failed_logins_24h": failed_logins,
        "successful_logins_24h": successful_logins,
        "security_violations_24h": security_violations,
        "admin_actions_24h": admin_actions,
        "critical_events": critical_events,
        "timestamp": now.isoformat()
    }

def log_security_event_to_audit(
    event_type: str,
    details: Dict[str, Any],
    ip_hash: Optional[str] = None,
    user_id: Optional[int] = None,
    username: Optional[str] = None,
    severity: str = SEVERITY_INFO
) -> None:
    """
    Bridge function to log security events to the audit log
    This function can be called from security_hardening.py
    
    Args:
        event_type: Type of event
        details: Dictionary of event details
        ip_hash: Hashed IP address
        user_id: User ID (if applicable)
        username: Username (if applicable)
        severity: Event severity
    """
    log_audit_event(
        event_type=event_type,
        details=details,
        user_id=user_id,
        username=username,
        ip_hash=ip_hash,
        severity=severity
    )
