import datetime
from sqlalchemy import Column, Integer, String, DateTime, Float, Text
from backend.database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False, index=True)
    email = Column(String(100), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(20), default="analyst") # "admin" or "analyst"
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

class SecurityLog(Base):
    __tablename__ = "security_logs"

    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String(45), index=True, nullable=False)
    username = Column(String(50), index=True, nullable=True)
    event_type = Column(String(50), index=True, nullable=False) # LOGIN_SUCCESS, LOGIN_FAILED, LOGOUT, PASSWORD_CHANGE, ACCESS_DENIED, SUSPICIOUS_REQUEST
    status = Column(String(20), nullable=False) # SUCCESS, FAILED, WARNING
    timestamp = Column(DateTime, default=datetime.datetime.utcnow, index=True)
    details = Column(Text, nullable=True)

class Threat(Base):
    __tablename__ = "threats"

    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String(45), index=True, nullable=False)
    threat_type = Column(String(100), nullable=False) # Brute-Force Login, Rate Limit Exceeded, Unauthorized Admin Access, Suspicious Activity
    severity = Column(String(20), nullable=False) # LOW, MEDIUM, HIGH, CRITICAL
    description = Column(Text, nullable=False)
    detected_at = Column(DateTime, default=datetime.datetime.utcnow, index=True)
    status = Column(String(20), default="ACTIVE") # ACTIVE, INVESTIGATING, RESOLVED, DISMISSED

class SystemMetric(Base):
    __tablename__ = "system_metrics"

    id = Column(Integer, primary_key=True, index=True)
    cpu_percent = Column(Float, nullable=False)
    memory_percent = Column(Float, nullable=False)
    disk_percent = Column(Float, nullable=False)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow, index=True)
