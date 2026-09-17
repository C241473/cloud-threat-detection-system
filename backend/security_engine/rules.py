import datetime
import re
from sqlalchemy.orm import Session
from sqlalchemy import func
from backend.models import SecurityLog, Threat
from backend.config import settings

class ThreatDetectionRules:
    
    @staticmethod
    def check_brute_force(db: Session, ip_address: str) -> bool:
        """
        Rule 1: 5 failed login attempts within 5 minutes from the same IP.
        """
        time_window = datetime.datetime.utcnow() - datetime.timedelta(minutes=settings.BRUTE_FORCE_WINDOW_MINUTES)
        
        failed_count = db.query(SecurityLog).filter(
            SecurityLog.ip_address == ip_address,
            SecurityLog.event_type == "LOGIN_FAILED",
            SecurityLog.timestamp >= time_window
        ).count()

        if failed_count >= settings.BRUTE_FORCE_THRESHOLD:
            existing = db.query(Threat).filter(
                Threat.ip_address == ip_address,
                Threat.threat_type == "Brute-Force Login Attempt",
                Threat.status == "ACTIVE",
                Threat.detected_at >= time_window
            ).first()

            if not existing:
                threat = Threat(
                    ip_address=ip_address,
                    threat_type="Brute-Force Login Attempt",
                    severity="HIGH",
                    description=f"Detected {failed_count} failed login attempts within {settings.BRUTE_FORCE_WINDOW_MINUTES} minutes from IP {ip_address}.",
                    status="ACTIVE"
                )
                db.add(threat)
                db.commit()
                return True
        return False

    @staticmethod
    def check_automated_flooding(db: Session, ip_address: str) -> bool:
        """
        Rule 2: Many requests (>= 50) within short timeframe (1 minute).
        """
        time_window = datetime.datetime.utcnow() - datetime.timedelta(minutes=settings.HIGH_REQUEST_WINDOW_MINUTES)
        
        req_count = db.query(SecurityLog).filter(
            SecurityLog.ip_address == ip_address,
            SecurityLog.timestamp >= time_window
        ).count()

        if req_count >= settings.HIGH_REQUEST_RATE_THRESHOLD:
            existing = db.query(Threat).filter(
                Threat.ip_address == ip_address,
                Threat.threat_type == "Possible Automated Activity (Rate Limit)",
                Threat.status == "ACTIVE",
                Threat.detected_at >= time_window
            ).first()

            if not existing:
                threat = Threat(
                    ip_address=ip_address,
                    threat_type="Possible Automated Activity (Rate Limit)",
                    severity="MEDIUM",
                    description=f"High request volume ({req_count} requests in {settings.HIGH_REQUEST_WINDOW_MINUTES} min) from IP {ip_address}.",
                    status="ACTIVE"
                )
                db.add(threat)
                db.commit()
                return True
        return False

    @staticmethod
    def check_unauthorized_access(db: Session, ip_address: str, username: str = None) -> bool:
        """
        Rule 3: Repeated unauthorized access attempts (ACCESS_DENIED).
        """
        time_window = datetime.datetime.utcnow() - datetime.timedelta(minutes=10)
        
        denied_count = db.query(SecurityLog).filter(
            SecurityLog.ip_address == ip_address,
            SecurityLog.event_type == "ACCESS_DENIED",
            SecurityLog.timestamp >= time_window
        ).count()

        if denied_count >= 3:
            existing = db.query(Threat).filter(
                Threat.ip_address == ip_address,
                Threat.threat_type == "Access Violation",
                Threat.status == "ACTIVE",
                Threat.detected_at >= time_window
            ).first()

            if not existing:
                threat = Threat(
                    ip_address=ip_address,
                    threat_type="Access Violation",
                    severity="HIGH",
                    description=f"Repeated unauthorized access attempts ({denied_count} times) by IP {ip_address} (User: {username or 'unknown'}).",
                    status="ACTIVE"
                )
                db.add(threat)
                db.commit()
                return True
        return False

    @staticmethod
    def check_suspicious_admin(db: Session, log: SecurityLog) -> bool:
        """
        Rule 4: Admin login attempt or password change attempt for admin account.
        """
        if log.username and log.username.lower() in ["admin", "root", "administrator"]:
            if log.event_type in ["LOGIN_FAILED", "SUSPICIOUS_REQUEST"]:
                existing = db.query(Threat).filter(
                    Threat.ip_address == log.ip_address,
                    Threat.threat_type == "Suspicious Admin Activity",
                    Threat.status == "ACTIVE",
                    Threat.detected_at >= datetime.datetime.utcnow() - datetime.timedelta(minutes=5)
                ).first()

                if not existing:
                    threat = Threat(
                        ip_address=log.ip_address,
                        threat_type="Suspicious Admin Activity",
                        severity="CRITICAL" if log.event_type == "SUSPICIOUS_REQUEST" else "HIGH",
                        description=f"Suspicious activity targeted towards privileged user '{log.username}' from IP {log.ip_address}.",
                        status="ACTIVE"
                    )
                    db.add(threat)
                    db.commit()
                    return True
        return False

    @staticmethod
    def check_sql_injection_payload(db: Session, log: SecurityLog) -> bool:
        """
        Rule 5: Detects SQL Injection or malicious script payload patterns in request details.
        """
        if not log.details:
            return False

        sql_patterns = [
            r"(\%27|\'|\-\-|\/\*|\*\/)",
            r"(?i)\b(SELECT|INSERT|DELETE|UPDATE|DROP|UNION|OR 1=1|OR '1'='1')\b",
            r"<script[\s\S]*?>[\s\S]*?<\/script>",
        ]

        for pattern in sql_patterns:
            if re.search(pattern, log.details):
                existing = db.query(Threat).filter(
                    Threat.ip_address == log.ip_address,
                    Threat.threat_type == "SQL Injection / Malicious Payload Attack",
                    Threat.status == "ACTIVE",
                    Threat.detected_at >= datetime.datetime.utcnow() - datetime.timedelta(minutes=5)
                ).first()

                if not existing:
                    threat = Threat(
                        ip_address=log.ip_address,
                        threat_type="SQL Injection / Malicious Payload Attack",
                        severity="CRITICAL",
                        description=f"Malicious code payload detected from IP {log.ip_address}: '{log.details[:80]}...'",
                        status="ACTIVE"
                    )
                    db.add(threat)
                    db.commit()
                    return True
        return False
