import psutil
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func

from backend.database import get_db
from backend.models import SecurityLog, Threat, SystemMetric

router = APIRouter(prefix="/api/dashboard", tags=["Dashboard Metrics"])

@router.get("/stats")
def get_dashboard_summary(db: Session = Depends(get_db)):
    """
    Returns aggregated metrics for the Cloud Security Dashboard:
    - Total events processed
    - Total failed logins
    - Total threat count
    - Threats grouped by severity
    - Real-time CPU, Memory, and Disk usage metrics
    """
    total_events = db.query(SecurityLog).count()
    failed_logins = db.query(SecurityLog).filter(SecurityLog.event_type == "LOGIN_FAILED").count()
    total_threats = db.query(Threat).count()
    active_threats = db.query(Threat).filter(Threat.status == "ACTIVE").count()

    # Severity counts
    severities = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    threats_by_severity = {}
    for sev in severities:
        count = db.query(Threat).filter(Threat.severity == sev).count()
        threats_by_severity[sev] = count

    # Recent 5 threats
    recent_threats = db.query(Threat).order_by(Threat.detected_at.desc()).limit(5).all()
    
    # Recent 10 logs
    recent_logs = db.query(SecurityLog).order_by(SecurityLog.timestamp.desc()).limit(10).all()

    # Real-time System Metrics
    cpu = psutil.cpu_percent(interval=None)
    mem = psutil.virtual_memory().percent
    disk = psutil.disk_usage('/').percent

    # Top Suspicious IPs
    top_ips = db.query(
        SecurityLog.ip_address, func.count(SecurityLog.id).label("count")
    ).filter(SecurityLog.status == "FAILED").group_by(SecurityLog.ip_address).order_by(func.count(SecurityLog.id).desc()).limit(5).all()

    top_suspicious_ips = [{"ip": ip, "failed_count": count} for ip, count in top_ips]

    return {
        "total_events": total_events,
        "failed_logins": failed_logins,
        "total_threats": total_threats,
        "active_threats": active_threats,
        "threats_by_severity": threats_by_severity,
        "recent_threats": [
            {
                "id": t.id,
                "ip_address": t.ip_address,
                "threat_type": t.threat_type,
                "severity": t.severity,
                "description": t.description,
                "detected_at": t.detected_at.isoformat(),
                "status": t.status
            } for t in recent_threats
        ],
        "recent_logs": [
            {
                "id": l.id,
                "ip_address": l.ip_address,
                "username": l.username,
                "event_type": l.event_type,
                "status": l.status,
                "timestamp": l.timestamp.isoformat(),
                "details": l.details
            } for l in recent_logs
        ],
        "system_metrics": {
            "cpu_percent": cpu,
            "memory_percent": mem,
            "disk_percent": disk
        },
        "top_suspicious_ips": top_suspicious_ips
    }
