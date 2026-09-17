import pytest
import datetime
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.database import Base
from backend.models import SecurityLog, Threat
from backend.security_engine.detector import SecurityEngine

SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"
engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

@pytest.fixture(autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)

def get_test_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()

def test_single_failed_login_no_alert():
    """Test Case 1: 1 failed login should NOT trigger a brute-force alert."""
    db = TestingSessionLocal()
    log = SecurityLog(
        ip_address="192.168.1.50",
        username="test_user",
        event_type="LOGIN_FAILED",
        status="FAILED",
        details="Wrong password",
        timestamp=datetime.datetime.utcnow()
    )
    db.add(log)
    db.commit()

    threats_triggered = SecurityEngine.process_log(db, log)
    assert len(threats_triggered) == 0
    assert db.query(Threat).count() == 0

def test_brute_force_threshold_triggers_alert():
    """Test Case 2: 5 failed logins within 5 minutes MUST trigger a Brute-Force threat alert."""
    db = TestingSessionLocal()
    test_ip = "192.168.1.88"

    for i in range(5):
        log = SecurityLog(
            ip_address=test_ip,
            username="victim_user",
            event_type="LOGIN_FAILED",
            status="FAILED",
            details=f"Attempt #{i+1}",
            timestamp=datetime.datetime.utcnow()
        )
        db.add(log)
        db.commit()
        SecurityEngine.process_log(db, log)

    threats = db.query(Threat).filter(Threat.ip_address == test_ip).all()
    assert len(threats) >= 1
    assert threats[0].threat_type == "Brute-Force Login Attempt"
    assert threats[0].severity == "HIGH"
    assert threats[0].status == "ACTIVE"

def test_sql_injection_payload_triggers_critical_alert():
    """Test Case 3: SQL Injection payload MUST trigger a CRITICAL threat alert."""
    db = TestingSessionLocal()
    log = SecurityLog(
        ip_address="198.51.100.22",
        username="attacker",
        event_type="SUSPICIOUS_REQUEST",
        status="FAILED",
        details="Attempted payload: ' OR '1'='1' -- UNION SELECT",
        timestamp=datetime.datetime.utcnow()
    )
    db.add(log)
    db.commit()

    threats_triggered = SecurityEngine.process_log(db, log)
    assert "SQL Injection / Malicious Payload Attack" in threats_triggered
    
    threat = db.query(Threat).filter(Threat.ip_address == "198.51.100.22").first()
    assert threat is not None
    assert threat.severity == "CRITICAL"

def test_successful_login_no_threat():
    """Test Case 4: Normal successful login event produces no threat alerts."""
    db = TestingSessionLocal()
    log = SecurityLog(
        ip_address="192.168.1.99",
        username="alice",
        event_type="LOGIN_SUCCESS",
        status="SUCCESS",
        details="User logged in normally",
        timestamp=datetime.datetime.utcnow()
    )
    db.add(log)
    db.commit()

    threats_triggered = SecurityEngine.process_log(db, log)
    assert len(threats_triggered) == 0
    assert db.query(Threat).count() == 0
