from sqlalchemy.orm import Session
from backend.models import SecurityLog
from backend.security_engine.rules import ThreatDetectionRules

class SecurityEngine:
    
    @staticmethod
    def process_log(db: Session, log: SecurityLog) -> list:
        """
        Analyzes an incoming log entry against all threat detection rules.
        Returns a list of triggered threat types.
        """
        triggered_threats = []

        # Rule 1: Brute Force Check
        if log.event_type == "LOGIN_FAILED":
            if ThreatDetectionRules.check_brute_force(db, log.ip_address):
                triggered_threats.append("Brute-Force Login Attempt")

        # Rule 2: Automated Request Rate Check
        if ThreatDetectionRules.check_automated_flooding(db, log.ip_address):
            triggered_threats.append("Possible Automated Activity (Rate Limit)")

        # Rule 3: Access Violation Check
        if log.event_type == "ACCESS_DENIED":
            if ThreatDetectionRules.check_unauthorized_access(db, log.ip_address, log.username):
                triggered_threats.append("Access Violation")

        # Rule 4: Privileged Admin Activity
        if ThreatDetectionRules.check_suspicious_admin(db, log):
            triggered_threats.append("Suspicious Admin Activity")

        # Rule 5: SQL Injection & Malicious Payload Detection
        if ThreatDetectionRules.check_sql_injection_payload(db, log):
            triggered_threats.append("SQL Injection / Malicious Payload Attack")

        return triggered_threats
