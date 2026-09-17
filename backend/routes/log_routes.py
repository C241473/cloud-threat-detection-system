import datetime
import random
from typing import Optional, List
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.models import SecurityLog
from backend.schemas import SecurityLogCreate, SecurityLogResponse
from backend.security_engine.detector import SecurityEngine
from backend.security_engine.geo import get_ip_geolocation

router = APIRouter(prefix="/api/logs", tags=["Security Logs"])

@router.post("", response_model=SecurityLogResponse, status_code=status.HTTP_201_CREATED)
def submit_log(log_in: SecurityLogCreate, db: Session = Depends(get_db)):
    """
    Receive and record a security event log.
    Automatically triggers the Threat Detection Engine on the ingested log.
    """
    log = SecurityLog(
        ip_address=log_in.ip_address,
        username=log_in.username,
        event_type=log_in.event_type.upper(),
        status=log_in.status.upper(),
        details=log_in.details,
        timestamp=datetime.datetime.utcnow()
    )
    db.add(log)
    db.commit()
    db.refresh(log)

    # Trigger Threat Engine Analysis
    SecurityEngine.process_log(db, log)

    return log

@router.get("", response_model=List[SecurityLogResponse])
def get_logs(
    ip_address: Optional[str] = Query(None),
    event_type: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db)
):
    """Retrieve security logs with optional query filters."""
    query = db.query(SecurityLog)
    
    if ip_address:
        query = query.filter(SecurityLog.ip_address == ip_address)
    if event_type and event_type != "ALL":
        query = query.filter(SecurityLog.event_type == event_type.upper())
    if status and status != "ALL":
        query = query.filter(SecurityLog.status == status.upper())

    logs = query.order_by(SecurityLog.timestamp.desc()).limit(limit).all()
    return logs

@router.get("/geo/{ip}")
def get_ip_info(ip: str):
    """Get location / ISP information for an IP address."""
    return get_ip_geolocation(ip)

@router.post("/simulate/brute-force")
def simulate_brute_force_attack(ip_address: str = "192.168.1.105", target_user: str = "admin", db: Session = Depends(get_db)):
    """
    Simulation utility: Triggers 5 failed login attempts in rapid succession to test brute-force detection.
    """
    created_logs = []
    for i in range(5):
        log = SecurityLog(
            ip_address=ip_address,
            username=target_user,
            event_type="LOGIN_FAILED",
            status="FAILED",
            details=f"Invalid password attempt #{i+1}",
            timestamp=datetime.datetime.utcnow()
        )
        db.add(log)
        db.commit()
        db.refresh(log)
        created_logs.append(log.id)
        
        # Run detection engine
        SecurityEngine.process_log(db, log)

    return {
        "message": f"Successfully simulated Brute-Force attack with 5 failed login attempts from IP {ip_address}",
        "log_ids": created_logs,
        "triggered_rule": "5 failed logins within 5 minutes threshold exceeded!"
    }

@router.post("/simulate/sqli")
def simulate_sql_injection(ip_address: str = "198.51.100.99", db: Session = Depends(get_db)):
    """
    Simulation utility: Triggers a SQL Injection / Malicious Payload attack payload to test CRITICAL threat detection.
    """
    log = SecurityLog(
        ip_address=ip_address,
        username="hacker_x",
        event_type="SUSPICIOUS_REQUEST",
        status="FAILED",
        details="Attempted SQLi payload: ' OR '1'='1' -- UNION SELECT username, password_hash FROM users",
        timestamp=datetime.datetime.utcnow()
    )
    db.add(log)
    db.commit()
    db.refresh(log)

    triggered = SecurityEngine.process_log(db, log)

    return {
        "message": f"Successfully simulated SQL Injection attack from IP {ip_address}",
        "log_id": log.id,
        "triggered_threats": triggered
    }
